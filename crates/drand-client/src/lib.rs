//! Minimal async client for the League of Entropy `drand` randomness beacon.
//!
//! This client targets the *unchained* BLS schemes used by production
//! networks such as `quicknet` (`bls-unchained-g1-rfc9380`), where each
//! round's signature is computed independently as
//!
//!     signature_round = H(round_bytes)^{sk}
//!
//! with `H` a hash-to-curve function on G1 (RFC 9380) and `sk` the
//! network's (threshold-shared) secret key. This is exactly the private
//! key needed for Boneh-Franklin identity-based encryption with the
//! round number as the identity string -- which is what makes `tlock`
//! possible: see `tlock-core` for the encryption side.
//!
//! Responsibilities covered here (Project H, Step 1):
//!   * connect to one or more drand HTTP relays, falling back across them
//!     for redundancy,
//!   * fetch and verify beacon signatures with BLS pairing checks,
//!   * convert between wall-clock time and beacon round numbers,
//!   * cache verified rounds in memory so repeated lookups (or a slow
//!     beacon) don't stall callers.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bls12_381_plus::{pairing, G1Affine, G1Projective, G2Affine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;

/// Domain-separation tag used by drand's `bls-unchained-g1-rfc9380`
/// scheme (quicknet and compatible networks) when hashing a round
/// number to a point on G1.
const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// How many verified rounds to keep cached in memory before evicting
/// the oldest ones. Beacon values never change once published, so the
/// cache never needs invalidation -- only bounding.
const DEFAULT_CACHE_CAPACITY: usize = 4096;

#[derive(Debug, Error)]
pub enum DrandError {
    #[error("no drand endpoints configured")]
    NoEndpoints,
    #[error("all {0} configured endpoints failed; last error: {1}")]
    AllEndpointsFailed(usize, String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("malformed beacon response: {0}")]
    Malformed(String),
    #[error("beacon signature failed verification for round {0}")]
    BadSignature(u64),
    #[error("round {round} is in the future (current round is {current}); it has not been produced yet")]
    NotYetAvailable { round: u64, current: u64 },
}

/// Static parameters of a drand chain, fetched once from `/info`.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainInfo {
    #[serde(rename = "public_key")]
    pub public_key_hex: String,
    pub period: u64,
    pub genesis_time: u64,
    pub hash: String,
    #[serde(rename = "groupHash")]
    pub group_hash: String,
    #[serde(rename = "schemeID")]
    pub scheme_id: String,
}

impl ChainInfo {
    /// Decode the network's master public key as a point on G2, as used
    /// by the `bls-unchained-g1-rfc9380` scheme (signatures on G1,
    /// public keys on G2).
    pub fn public_key_g2(&self) -> Result<G2Affine, DrandError> {
        let bytes = hex::decode(&self.public_key_hex)
            .map_err(|e| DrandError::Malformed(format!("public key hex: {e}")))?;
        let arr: [u8; 96] = bytes
            .try_into()
            .map_err(|_| DrandError::Malformed("public key is not 96 bytes (G2)".into()))?;
        Option::from(G2Affine::from_compressed(&arr))
            .ok_or_else(|| DrandError::Malformed("public key is not a valid G2 point".into()))
    }
}

/// A single, raw round as returned by the beacon HTTP API.
#[derive(Debug, Clone, Deserialize)]
pub struct RawRound {
    pub round: u64,
    pub randomness: String,
    pub signature: String,
}

/// A round whose BLS signature has been checked against the chain's
/// public key. Only `VerifiedRound`s are ever handed to callers or
/// placed in the cache.
#[derive(Debug, Clone)]
pub struct VerifiedRound {
    pub round: u64,
    pub randomness: [u8; 32],
    pub signature: G1Affine,
}

struct Cache {
    capacity: usize,
    // BTreeMap keeps insertion-ish order by round number, so eviction
    // of the "oldest" entries is just popping the smallest keys.
    rounds: BTreeMap<u64, VerifiedRound>,
}

impl Cache {
    fn new(capacity: usize) -> Self {
        Self { capacity, rounds: BTreeMap::new() }
    }

    fn insert(&mut self, r: VerifiedRound) {
        self.rounds.insert(r.round, r);
        while self.rounds.len() > self.capacity {
            if let Some((&oldest, _)) = self.rounds.iter().next() {
                self.rounds.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn get(&self, round: u64) -> Option<VerifiedRound> {
        self.rounds.get(&round).cloned()
    }
}

/// Async drand client. Cheap to clone (internals are `Arc`-wrapped).
#[derive(Clone)]
pub struct DrandClient {
    endpoints: Vec<String>,
    http: reqwest::Client,
    pub info: ChainInfo,
    cache: Arc<Mutex<Cache>>,
}

impl DrandClient {
    /// Connect to a drand network, given one or more relay base URLs
    /// (e.g. `https://api.drand.sh/<chain-hash>`). The first endpoint
    /// that answers `/info` successfully determines the chain
    /// parameters; the full list is retained so that fetching
    /// individual rounds can fall back across nodes.
    pub async fn new(endpoints: Vec<String>) -> Result<Self, DrandError> {
        if endpoints.is_empty() {
            return Err(DrandError::NoEndpoints);
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let mut last_err = None;
        let mut info = None;
        for base in &endpoints {
            match http.get(format!("{base}/info")).send().await {
                Ok(resp) => match resp.error_for_status() {
                    Ok(resp) => match resp.json::<ChainInfo>().await {
                        Ok(i) => {
                            info = Some(i);
                            break;
                        }
                        Err(e) => last_err = Some(e.to_string()),
                    },
                    Err(e) => last_err = Some(e.to_string()),
                },
                Err(e) => last_err = Some(e.to_string()),
            }
        }
        let info = info.ok_or_else(|| {
            DrandError::AllEndpointsFailed(endpoints.len(), last_err.unwrap_or_default())
        })?;

        Ok(Self {
            endpoints,
            http,
            info,
            cache: Arc::new(Mutex::new(Cache::new(DEFAULT_CACHE_CAPACITY))),
        })
    }

    /// The smallest round whose scheduled publish time is at or after
    /// `time` -- the round to *encrypt to* so something stays locked
    /// until (at least) `time`.
    ///
    /// Deliberately a *ceiling* division and deliberately different
    /// from [`Self::current_round`] (drand's "which round is active
    /// now" query, which floors). Flooring here would let a target time
    /// that isn't on a round boundary resolve to a round already
    /// published, i.e. unlock *early*.
    ///
    ///     round_at(t) = 1                                      if t <= genesis_time
    ///     round_at(t) = ceil((t - genesis_time) / period) + 1  otherwise
    pub fn round_at(&self, time: SystemTime) -> u64 {
        let unix = time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if unix <= self.info.genesis_time {
            return 1;
        }
        let elapsed = unix - self.info.genesis_time;
        (elapsed + self.info.period - 1) / self.info.period + 1
    }

    /// Convenience: round number for "`duration` from now".
    pub fn round_in(&self, duration: std::time::Duration) -> u64 {
        self.round_at(SystemTime::now() + duration)
    }

    /// Wall-clock time at which `round` is (or was) published:
    /// `genesis_time + (round - 1) * period`.
    pub fn time_of_round(&self, round: u64) -> SystemTime {
        let secs = self.info.genesis_time + (round.saturating_sub(1)) * self.info.period;
        UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    /// The most recent round that should already exist, per drand's own
    /// `CurrentRound` definition (a *floor*):
    ///
    ///     current_round() = floor((now - genesis_time) / period) + 1
    ///
    /// Use this to decide what is fetchable now; never to pick an
    /// encryption target (see [`Self::round_at`]).
    pub fn current_round(&self) -> u64 {
        let unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if unix <= self.info.genesis_time {
            return 1;
        }
        (unix - self.info.genesis_time) / self.info.period + 1
    }

    /// Fetch and verify a round, serving from cache when possible and
    /// falling back across configured endpoints on network failure.
    pub async fn get_round(&self, round: u64) -> Result<VerifiedRound, DrandError> {
        if let Some(cached) = self.cache.lock().await.get(round) {
            return Ok(cached);
        }

        let current = self.current_round();
        if round > current {
            return Err(DrandError::NotYetAvailable { round, current });
        }

        let mut last_err = None;
        for base in &self.endpoints {
            let url = format!("{base}/public/{round}");
            let raw = match self.http.get(&url).send().await {
                Ok(resp) => match resp.error_for_status() {
                    Ok(resp) => match resp.json::<RawRound>().await {
                        Ok(r) => r,
                        Err(e) => {
                            last_err = Some(e.to_string());
                            continue;
                        }
                    },
                    Err(e) => {
                        last_err = Some(e.to_string());
                        continue;
                    }
                },
                Err(e) => {
                    last_err = Some(e.to_string());
                    continue;
                }
            };

            let verified = self.verify(raw)?;
            self.cache.lock().await.insert(verified.clone());
            return Ok(verified);
        }

        Err(DrandError::AllEndpointsFailed(
            self.endpoints.len(),
            last_err.unwrap_or_default(),
        ))
    }

    /// Hash a round number to its G1 identity point, using the same
    /// message digest and ciphersuite drand uses to sign.
    ///
    /// Per drand's protocol spec (`DigestMessage`), the signed message
    /// of an *unchained* scheme (quicknet; the only kind this client
    /// supports) is
    ///
    ///     digest = SHA256(RoundToBytes(round))     (round = 8-byte big-endian)
    ///
    /// (chained schemes also prepend the previous signature; unchained
    /// ones omit it). Hashing the raw round bytes instead would give a
    /// different point than the one drand signs, so signatures would
    /// never verify against a real network. `tlock-core` reuses this
    /// function as the IBE identity hash.
    pub fn hash_round_to_g1(round: u64) -> G1Affine {
        let digest = Sha256::digest(round.to_be_bytes());
        let point: G1Projective = G1Projective::hash_to_curve(digest.as_slice(), DST);
        point.into()
    }

    fn verify(&self, raw: RawRound) -> Result<VerifiedRound, DrandError> {
        let randomness_bytes = hex::decode(&raw.randomness)
            .map_err(|e| DrandError::Malformed(format!("randomness hex: {e}")))?;
        let randomness: [u8; 32] = randomness_bytes
            .try_into()
            .map_err(|_| DrandError::Malformed("randomness is not 32 bytes".into()))?;

        let sig_bytes = hex::decode(&raw.signature)
            .map_err(|e| DrandError::Malformed(format!("signature hex: {e}")))?;
        let sig_arr: [u8; 48] = sig_bytes
            .try_into()
            .map_err(|_| DrandError::Malformed("signature is not 48 bytes (G1)".into()))?;
        let signature: G1Affine = Option::from(G1Affine::from_compressed(&sig_arr))
            .ok_or_else(|| DrandError::Malformed("signature is not a valid G1 point".into()))?;

        let pubkey = self.info.public_key_g2()?;
        let identity = Self::hash_round_to_g1(raw.round);

        // Verify e(signature, G2::generator) == e(H(round), public_key).
        let lhs = pairing(&signature, &G2Affine::generator());
        let rhs = pairing(&identity, &pubkey);
        if lhs != rhs {
            return Err(DrandError::BadSignature(raw.round));
        }

        Ok(VerifiedRound { round: raw.round, randomness, signature })
    }
}
