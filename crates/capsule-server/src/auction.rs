//! Sealed-bid auction / commitment scheme (Project H, Step 5).
//!
//! An auction fixes a reveal round up front. Every bid is tlock-
//! encrypted to that same round, so:
//!   * nobody (bidders, auctioneer, this server) can read any bid
//!     before the reveal round -- not even the bid's own author after
//!     submitting, since the server stores only ciphertext;
//!   * every bid unlocks at the *same instant*, when drand publishes
//!     the round, so nobody can wait to see others' bids first;
//!   * each bid gets a public SHA-256 *commitment* of its ciphertext
//!     at submission time. The commitments list is public and
//!     append-only from the API's point of view, so after the reveal
//!     anyone can check bids were not swapped (hash the ciphertext,
//!     compare). Bids are stored as ordinary capsules and opened by
//!     the normal decryption service.
//!
//! Bidder names are stored as the capsule label and are only returned
//! after the reveal. Limitation: the server stores ciphertexts, so a
//! malicious *server* could still drop or reorder bids; the commitments
//! make that detectable only if bidders keep their own receipt.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{bad_request, clean_label, internal, not_found, ApiError, Capsule, Content, SharedState, MAX_CAPSULES};

const MIN_REVEAL_SECS: i64 = 10;
const MAX_REVEAL_SECS: i64 = 5 * 365 * 24 * 3600;
const MAX_BIDS_PER_AUCTION: usize = 500;
const MAX_AUCTIONS: usize = 2_000;

pub(crate) struct Auction {
    id: Uuid,
    label: Option<String>,
    round: u64,
    reveal_time: DateTime<Utc>,
    bids: Vec<BidRecord>,
}

#[derive(Clone)]
struct BidRecord {
    capsule_id: Uuid,
    commitment: String,
}

fn commitment(ct: &tlock_core::Ciphertext) -> String {
    let mut h = Sha256::new();
    h.update(b"TLOCK-AUCTION-COMMITMENT");
    h.update(ct.round.to_be_bytes());
    h.update(&ct.u);
    h.update(&ct.v);
    h.update(&ct.w);
    h.update(&ct.nonce);
    h.update(&ct.payload);
    hex::encode(h.finalize())
}

#[derive(Deserialize)]
pub(crate) struct CreateAuctionRequest {
    label: Option<String>,
    reveal_in_seconds: i64,
}

#[derive(Serialize)]
pub(crate) struct CreateAuctionResponse {
    id: Uuid,
    round: u64,
    reveal_time: DateTime<Utc>,
}

pub(crate) async fn create(
    State(state): State<SharedState>,
    Json(req): Json<CreateAuctionRequest>,
) -> Result<Json<CreateAuctionResponse>, ApiError> {
    if !(MIN_REVEAL_SECS..=MAX_REVEAL_SECS).contains(&req.reveal_in_seconds) {
        return Err(bad_request(format!(
            "reveal_in_seconds must be between {MIN_REVEAL_SECS} and {MAX_REVEAL_SECS}"
        )));
    }
    let label = clean_label(req.label)?;
    if state.auctions.read().await.len() >= MAX_AUCTIONS {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "auction storage is full".into()));
    }
    let target = Utc::now() + chrono::Duration::seconds(req.reveal_in_seconds);
    let round = state.drand.round_at(target.into());
    let reveal_time: DateTime<Utc> = state.drand.time_of_round(round).into();
    let id = Uuid::new_v4();
    state
        .auctions
        .write()
        .await
        .insert(id, Auction { id, label, round, reveal_time, bids: Vec::new() });
    tracing::info!(%id, round, %reveal_time, "auction created");
    Ok(Json(CreateAuctionResponse { id, round, reveal_time }))
}

#[derive(Deserialize)]
pub(crate) struct PlaceBidRequest {
    bidder: String,
    bid: String,
}

#[derive(Serialize)]
pub(crate) struct PlaceBidResponse {
    /// SHA-256 commitment to the sealed bid. Keep it as your receipt.
    commitment: String,
    index: usize,
}

pub(crate) async fn place_bid(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(req): Json<PlaceBidRequest>,
) -> Result<Json<PlaceBidResponse>, ApiError> {
    let bidder = req.bidder.trim().to_string();
    let bid = req.bid.trim().to_string();
    if bidder.is_empty() || bidder.chars().count() > 100 {
        return Err(bad_request("bidder must be 1-100 characters"));
    }
    if bid.is_empty() || bid.chars().count() > 2000 {
        return Err(bad_request("bid must be 1-2000 characters"));
    }

    let (round, reveal_time) = {
        let auctions = state.auctions.read().await;
        let a = auctions.get(&id).ok_or_else(|| not_found("no such auction"))?;
        if a.bids.len() >= MAX_BIDS_PER_AUCTION {
            return Err((StatusCode::CONFLICT, "this auction has reached its bid limit".into()));
        }
        (a.round, a.reveal_time)
    };
    // Once the reveal round exists, its signature is public, so a bid
    // sealed to it would be readable by anyone immediately.
    if Utc::now() >= reveal_time || state.drand.current_round() >= round {
        return Err((StatusCode::CONFLICT, "bidding is closed: the reveal round has arrived".into()));
    }
    if state.store.read().await.len() >= MAX_CAPSULES {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "capsule storage is full".into()));
    }

    let ciphertext = tlock_core::encrypt(bid.as_bytes(), round, &state.pubkey).map_err(internal)?;
    let commit = commitment(&ciphertext);
    let capsule_id = Uuid::new_v4();

    state.store.write().await.insert(
        capsule_id,
        Capsule {
            id: capsule_id,
            label: Some(bidder),
            ciphertext,
            created_at: Utc::now(),
            unlock_time: reveal_time,
            content: Content::Text,
            decrypted: None,
            last_error: None,
            decrypt_failed: false,
            webhook_url: None,
            recipients: Vec::new(),
        },
    );

    let index = {
        let mut auctions = state.auctions.write().await;
        let a = auctions.get_mut(&id).ok_or_else(|| not_found("no such auction"))?;
        a.bids.push(BidRecord { capsule_id, commitment: commit.clone() });
        a.bids.len() - 1
    };
    tracing::info!(auction = %id, index, "sealed bid accepted");
    Ok(Json(PlaceBidResponse { commitment: commit, index }))
}

#[derive(Serialize)]
struct BidCommitment {
    index: usize,
    commitment: String,
}

#[derive(Serialize, Clone)]
struct RevealedBid {
    bidder: String,
    bid: String,
}

#[derive(Serialize)]
pub(crate) struct AuctionStatus {
    id: Uuid,
    label: Option<String>,
    round: u64,
    reveal_time: DateTime<Utc>,
    /// "sealed" -> "revealing" (round reached, decrypting) -> "revealed"
    status: &'static str,
    seconds_remaining: Option<i64>,
    bid_count: usize,
    commitments: Vec<BidCommitment>,
    revealed_bids: Vec<RevealedBid>,
    pending_count: usize,
    /// Only if every bid parses as a number.
    highest: Option<RevealedBid>,
}

pub(crate) async fn get(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AuctionStatus>, ApiError> {
    let (label, round, reveal_time, records) = {
        let auctions = state.auctions.read().await;
        let a = auctions.get(&id).ok_or_else(|| not_found("no such auction"))?;
        (a.label.clone(), a.round, a.reveal_time, a.bids.clone())
    };
    let commitments: Vec<BidCommitment> = records
        .iter()
        .enumerate()
        .map(|(index, r)| BidCommitment { index, commitment: r.commitment.clone() })
        .collect();
    let bid_count = records.len();
    let now = Utc::now();

    // Before the reveal time we return only counts + commitments.
    if now < reveal_time {
        return Ok(Json(AuctionStatus {
            id,
            label,
            round,
            reveal_time,
            status: "sealed",
            seconds_remaining: Some((reveal_time - now).num_seconds().max(0)),
            bid_count,
            commitments,
            revealed_bids: Vec::new(),
            pending_count: bid_count,
            highest: None,
        }));
    }

    let store = state.store.read().await;
    let mut revealed: Vec<RevealedBid> = Vec::new();
    let mut pending = 0usize;
    for r in &records {
        match store.get(&r.capsule_id).and_then(|c| c.decrypted.as_ref().map(|d| (c, d))) {
            Some((c, bytes)) => revealed.push(RevealedBid {
                bidder: c.label.clone().unwrap_or_default(),
                bid: String::from_utf8_lossy(bytes).into_owned(),
            }),
            None => pending += 1,
        }
    }

    let highest = if pending == 0 && !revealed.is_empty() {
        let nums: Option<Vec<f64>> = revealed
            .iter()
            .map(|b| b.bid.trim().parse::<f64>().ok().filter(|x| x.is_finite()))
            .collect();
        nums.and_then(|nums| {
            let mut best = 0usize;
            for (i, n) in nums.iter().enumerate() {
                if *n > nums[best] {
                    best = i;
                }
            }
            revealed.get(best).cloned()
        })
    } else {
        None
    };

    Ok(Json(AuctionStatus {
        id,
        label,
        round,
        reveal_time,
        status: if pending == 0 { "revealed" } else { "revealing" },
        seconds_remaining: None,
        bid_count,
        commitments,
        revealed_bids: revealed,
        pending_count: pending,
        highest,
    }))
}
