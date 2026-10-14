//! Dead man's switch (Project H, Step 5).
//!
//! The owner seals a message with a check-in interval. While they keep
//! checking in, nothing is revealed. If they stop, the message is
//! released automatically -- and the release is enforced by the drand
//! beacon, not by trusting this server to "decide" to open it.
//!
//! Mechanism: a switch always holds one standing tlock ciphertext
//! locked to `now + interval`. A check-in re-encrypts the message to a
//! fresh, later round and discards the old ciphertext. If the deadline
//! round arrives first, the decrypt succeeds and the switch is
//! `triggered`.
//!
//! IMPORTANT trust trade-off: re-encrypting needs the plaintext, so
//! unlike a plain capsule the server *retains the plaintext in memory*
//! while the switch is armed. This is inherent to any extendable
//! timelock; it is documented in DESIGN.md section 5.3. Check-ins are
//! also refused once the deadline has passed, because the old round's
//! signature may already be public.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

use crate::{
    bad_request, clean_label, content_fields, internal, not_found, parse_content, send_webhook,
    validate_webhook_url, ApiError, Content, SharedState,
};

const MIN_INTERVAL_SECS: i64 = 10;
const MAX_INTERVAL_SECS: i64 = 10 * 365 * 24 * 3600;
const MAX_SWITCHES: usize = 5_000;

pub(crate) struct Switch {
    id: Uuid,
    label: Option<String>,
    manage_token: Uuid,
    interval_secs: i64,
    content: Content,
    plaintext: Vec<u8>,
    ciphertext: tlock_core::Ciphertext,
    deadline: DateTime<Utc>,
    checkins: u32,
    triggered: bool,
    last_error: Option<String>,
    webhook_url: Option<String>,
}

impl Switch {
    fn status_str(&self) -> &'static str {
        if self.triggered {
            "triggered"
        } else if Utc::now() >= self.deadline {
            "pending-trigger"
        } else {
            "armed"
        }
    }
}

fn ct_eq(a: &Uuid, b: &Uuid) -> bool {
    a.as_bytes().iter().zip(b.as_bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn seal(
    state: &crate::AppState,
    plaintext: &[u8],
    interval_secs: i64,
) -> Result<(tlock_core::Ciphertext, DateTime<Utc>), ApiError> {
    let target = Utc::now() + chrono::Duration::seconds(interval_secs);
    let round = state.drand.round_at(target.into());
    let ct = tlock_core::encrypt(plaintext, round, &state.pubkey).map_err(internal)?;
    let deadline: DateTime<Utc> = state.drand.time_of_round(round).into();
    Ok((ct, deadline))
}

#[derive(Deserialize)]
pub(crate) struct CreateSwitchRequest {
    label: Option<String>,
    message: Option<String>,
    file_name: Option<String>,
    file_base64: Option<String>,
    checkin_interval_seconds: i64,
    webhook_url: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct CreateSwitchResponse {
    id: Uuid,
    /// Shown ONCE. Required to check in; lose it and the switch will fire.
    manage_token: Uuid,
    deadline: DateTime<Utc>,
    round: u64,
}

pub(crate) async fn create(
    State(state): State<SharedState>,
    Json(req): Json<CreateSwitchRequest>,
) -> Result<Json<CreateSwitchResponse>, ApiError> {
    let (bytes, content) = parse_content(req.message, req.file_base64, req.file_name)?;
    let label = clean_label(req.label)?;
    if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&req.checkin_interval_seconds) {
        return Err(bad_request(format!(
            "checkin_interval_seconds must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS}"
        )));
    }
    let webhook_url = match req.webhook_url.map(|u| u.trim().to_string()) {
        Some(u) if !u.is_empty() => {
            validate_webhook_url(&u)?;
            Some(u)
        }
        _ => None,
    };
    if state.switches.read().await.len() >= MAX_SWITCHES {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "switch storage is full".into()));
    }

    let (ciphertext, deadline) = seal(&state, &bytes, req.checkin_interval_seconds)?;
    let id = Uuid::new_v4();
    let manage_token = Uuid::new_v4();
    let round = ciphertext.round;
    state.switches.write().await.insert(
        id,
        Switch {
            id,
            label,
            manage_token,
            interval_secs: req.checkin_interval_seconds,
            content,
            plaintext: bytes,
            ciphertext,
            deadline,
            checkins: 0,
            triggered: false,
            last_error: None,
            webhook_url,
        },
    );
    tracing::info!(%id, round, %deadline, "dead man's switch armed");
    Ok(Json(CreateSwitchResponse { id, manage_token, deadline, round }))
}

#[derive(Deserialize)]
pub(crate) struct CheckinRequest {
    token: Uuid,
}

#[derive(Serialize)]
pub(crate) struct CheckinResponse {
    deadline: DateTime<Utc>,
    round: u64,
    checkins: u32,
}

pub(crate) async fn checkin(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CheckinRequest>,
) -> Result<Json<CheckinResponse>, ApiError> {
    let mut map = state.switches.write().await;
    let sw = map.get_mut(&id).ok_or_else(|| not_found("no such switch"))?;
    if !ct_eq(&sw.manage_token, &req.token) {
        return Err((StatusCode::FORBIDDEN, "wrong token".into()));
    }
    if sw.triggered || Utc::now() >= sw.deadline {
        return Err((
            StatusCode::CONFLICT,
            "too late: the deadline has passed, so the switch has fired (or is firing)".into(),
        ));
    }
    let (ct, deadline) = seal(&state, &sw.plaintext, sw.interval_secs)?;
    sw.ciphertext = ct;
    sw.deadline = deadline;
    sw.checkins += 1;
    tracing::info!(%id, checkins = sw.checkins, %deadline, "switch checked in");
    Ok(Json(CheckinResponse { deadline, round: sw.ciphertext.round, checkins: sw.checkins }))
}

#[derive(Serialize)]
pub(crate) struct SwitchStatus {
    id: Uuid,
    label: Option<String>,
    status: &'static str,
    deadline: DateTime<Utc>,
    round: u64,
    seconds_remaining: Option<i64>,
    checkin_interval_seconds: i64,
    checkins: u32,
    content_type: &'static str,
    message: Option<String>,
    file_name: Option<String>,
    file_base64: Option<String>,
    error: Option<String>,
}

pub(crate) async fn get(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SwitchStatus>, ApiError> {
    let map = state.switches.read().await;
    let sw = map.get(&id).ok_or_else(|| not_found("no such switch"))?;
    // Content is only disclosed once the switch has actually fired.
    let revealed = if sw.triggered { Some(sw.plaintext.as_slice()) } else { None };
    let (content_type, message, file_name, file_base64) = content_fields(&sw.content, revealed);
    Ok(Json(SwitchStatus {
        id: sw.id,
        label: sw.label.clone(),
        status: sw.status_str(),
        deadline: sw.deadline,
        round: sw.ciphertext.round,
        seconds_remaining: if sw.triggered {
            None
        } else {
            Some((sw.deadline - Utc::now()).num_seconds().max(0))
        },
        checkin_interval_seconds: sw.interval_secs,
        checkins: sw.checkins,
        content_type,
        message,
        file_name,
        file_base64,
        error: sw.last_error.clone(),
    }))
}

pub(crate) async fn run(state: SharedState) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    loop {
        interval.tick().await;
        tick(&state).await;
    }
}

async fn tick(state: &SharedState) {
    let current = state.drand.current_round();
    let due: Vec<(Uuid, u64)> = {
        let map = state.switches.read().await;
        map.values()
            .filter(|s| !s.triggered && s.ciphertext.round <= current)
            .map(|s| (s.id, s.ciphertext.round))
            .collect()
    };

    for (id, round) in due {
        let verified = match state.drand.get_round(round).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%id, error = %e, "switch is due but beacon fetch failed; will retry");
                continue;
            }
        };

        let notify = {
            let mut map = state.switches.write().await;
            let Some(sw) = map.get_mut(&id) else { continue };
            // A check-in may have swapped the ciphertext while we were fetching.
            if sw.triggered || sw.ciphertext.round != round {
                continue;
            }
            match tlock_core::decrypt(&sw.ciphertext, &verified.signature) {
                Ok(pt) if pt == sw.plaintext => {
                    sw.triggered = true;
                    sw.last_error = None;
                    tracing::info!(%id, "dead man's switch TRIGGERED");
                    sw.webhook_url.clone().map(|url| {
                        let link = match &state.public_base_url {
                            Some(base) => format!("{base}/?switch={}", sw.id),
                            None => format!("/?switch={}", sw.id),
                        };
                        (
                            url,
                            serde_json::json!({
                                "event": "switch.triggered",
                                "id": sw.id,
                                "label": sw.label,
                                "round": round,
                                "link": link,
                            }),
                        )
                    })
                }
                Ok(_) => {
                    sw.last_error = Some("decrypted content did not match stored plaintext".into());
                    None
                }
                Err(e) => {
                    sw.last_error = Some(e.to_string());
                    None
                }
            }
        };

        if let Some((url, payload)) = notify {
            let http = state.http.clone();
            tokio::spawn(async move { send_webhook(&http, &url, payload).await });
        }
    }
}
