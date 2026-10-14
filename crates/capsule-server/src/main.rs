//! Capsule server: the user-facing part of Project H (Steps 3, 4 and 5).
//!
//! Features
//!   * time-locked capsules (text or file) with a JSON API + static UI,
//!   * an automatic decryption service (`decryption_service`) that opens
//!     capsules the moment their drand round is published and fires
//!     webhook notifications to the capsule's recipients,
//!   * sealed-bid auctions / commitment scheme (`auction`),
//!   * a dead man's switch (`dead_man_switch`).
//!
//! Storage is in-memory (`RwLock<HashMap<..>>`). The crypto crates know
//! nothing about storage, so swapping in a database only touches this
//! crate. See DESIGN.md.

mod auction;
mod dead_man_switch;
mod decryption_service;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bls12_381_plus::G2Affine;
use chrono::{DateTime, Utc};
use drand_client::DrandClient;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use uuid::Uuid;

/// drand quicknet (3s rounds, unchained BLS-on-G1). `DRAND_ENDPOINTS`
/// (comma separated) overrides this list.
const DEFAULT_ENDPOINTS: &[&str] = &[
    "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    "https://drand.cloudflare.com/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
];

const MAX_CAPSULES: usize = 10_000;
const MAX_RECIPIENTS: usize = 20;
const MAX_LABEL_LEN: usize = 200;
const MAX_BODY_BYTES: usize = 24 * 1024 * 1024;

#[derive(Clone, Debug)]
enum Content {
    Text,
    File { file_name: String },
}

struct Capsule {
    id: Uuid,
    label: Option<String>,
    ciphertext: tlock_core::Ciphertext,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    unlock_time: DateTime<Utc>,
    content: Content,
    decrypted: Option<Vec<u8>>,
    last_error: Option<String>,
    /// Set when decryption failed for a non-network reason (corrupt
    /// ciphertext). Stops the service from retrying forever.
    decrypt_failed: bool,
    webhook_url: Option<String>,
    recipients: Vec<String>,
}

impl Capsule {
    fn status_str(&self) -> &'static str {
        if self.decrypt_failed {
            "failed"
        } else if self.decrypted.is_some() {
            "unlocked"
        } else if Utc::now() >= self.unlock_time {
            "pending-decryption"
        } else {
            "locked"
        }
    }

    fn to_status(&self) -> CapsuleStatus {
        let seconds_remaining = if self.decrypted.is_some() {
            None
        } else {
            Some((self.unlock_time - Utc::now()).num_seconds().max(0))
        };
        let (content_type, message, file_name, file_base64) =
            content_fields(&self.content, self.decrypted.as_deref());
        CapsuleStatus {
            id: self.id,
            label: self.label.clone(),
            round: self.ciphertext.round,
            unlock_time: self.unlock_time,
            status: self.status_str(),
            seconds_remaining,
            content_type,
            message,
            file_name,
            file_base64,
            recipients: self.recipients.clone(),
            error: self.last_error.clone(),
        }
    }
}

struct AppState {
    drand: DrandClient,
    pubkey: G2Affine,
    http: reqwest::Client,
    public_base_url: Option<String>,
    list_enabled: bool,
    store: RwLock<HashMap<Uuid, Capsule>>,
    auctions: RwLock<HashMap<Uuid, auction::Auction>>,
    switches: RwLock<HashMap<Uuid, dead_man_switch::Switch>>,
}

type SharedState = Arc<AppState>;
type ApiError = (StatusCode, String);

fn bad_request(msg: impl Into<String>) -> ApiError {
    (StatusCode::BAD_REQUEST, msg.into())
}
fn not_found(msg: impl Into<String>) -> ApiError {
    (StatusCode::NOT_FOUND, msg.into())
}
fn internal(msg: impl ToString) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string())
}

fn clean_label(label: Option<String>) -> Result<Option<String>, ApiError> {
    match label.map(|l| l.trim().to_string()) {
        None => Ok(None),
        Some(l) if l.is_empty() => Ok(None),
        Some(l) if l.chars().count() > MAX_LABEL_LEN => {
            Err(bad_request(format!("label is longer than {MAX_LABEL_LEN} characters")))
        }
        Some(l) => Ok(Some(l)),
    }
}

/// Shared by capsules and dead man's switches: exactly one of
/// `message` or (`file_base64` + `file_name`).
fn parse_content(
    message: Option<String>,
    file_base64: Option<String>,
    file_name: Option<String>,
) -> Result<(Vec<u8>, Content), ApiError> {
    let (bytes, content) = match (message, file_base64, file_name) {
        (Some(text), None, _) => (text.into_bytes(), Content::Text),
        (None, Some(b64), Some(name)) => {
            if name.len() > 255 {
                return Err(bad_request("file_name is too long"));
            }
            let bytes = STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| bad_request(format!("file_base64 is not valid base64: {e}")))?;
            (bytes, Content::File { file_name: name })
        }
        (None, Some(_), None) => return Err(bad_request("file_base64 requires file_name")),
        _ => {
            return Err(bad_request(
                "provide exactly one of `message` or (`file_base64` + `file_name`)",
            ))
        }
    };
    if bytes.is_empty() {
        return Err(bad_request("content is empty"));
    }
    Ok((bytes, content))
}

fn content_fields(
    content: &Content,
    bytes: Option<&[u8]>,
) -> (&'static str, Option<String>, Option<String>, Option<String>) {
    match (content, bytes) {
        (Content::Text, Some(b)) => ("text", Some(String::from_utf8_lossy(b).into_owned()), None, None),
        (Content::Text, None) => ("text", None, None, None),
        (Content::File { file_name }, Some(b)) => {
            ("file", None, Some(file_name.clone()), Some(STANDARD.encode(b)))
        }
        (Content::File { file_name }, None) => ("file", None, Some(file_name.clone()), None),
    }
}

/// Webhooks are server-side requests to user-supplied URLs, so reject
/// obviously internal targets (SSRF hygiene). This is a string/IP-literal
/// check: it does not defend against DNS names that *resolve* to private
/// addresses -- see DESIGN.md section 7.
fn validate_webhook_url(raw: &str) -> Result<(), ApiError> {
    let url = reqwest::Url::parse(raw).map_err(|e| bad_request(format!("invalid webhook_url: {e}")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(bad_request("webhook_url must be http or https"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| bad_request("webhook_url has no host"))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return Err(bad_request("webhook_url must not point at a local/internal host"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        let internal = match ip {
            IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
            }
            IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (first & 0xfe00) == 0xfc00
                    || (first & 0xffc0) == 0xfe80
            }
        };
        if internal {
            return Err(bad_request("webhook_url must not point at a private IP address"));
        }
    }
    Ok(())
}

/// Best-effort delivery with 3 attempts and exponential backoff. The URL
/// is deliberately never logged (chat-app webhook URLs embed secrets).
async fn send_webhook(http: &reqwest::Client, url: &str, payload: serde_json::Value) {
    for attempt in 1..=3u32 {
        match http.post(url).json(&payload).send().await {
            Ok(r) if r.status().is_success() => {
                tracing::info!("webhook delivered");
                return;
            }
            Ok(r) => tracing::warn!(attempt, status = %r.status(), "webhook returned non-success"),
            Err(e) => tracing::warn!(attempt, error = %e.without_url(), "webhook request failed"),
        }
        tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
    }
    tracing::warn!("webhook gave up after 3 attempts");
}

#[derive(Debug, Deserialize)]
struct CreateCapsuleRequest {
    label: Option<String>,
    message: Option<String>,
    file_name: Option<String>,
    file_base64: Option<String>,
    unlock_in_seconds: Option<i64>,
    unlock_at: Option<DateTime<Utc>>,
    /// Contact labels / emails of the people this capsule is for.
    /// Informational + included in the webhook payload; NOT a
    /// cryptographic access list (see DESIGN.md section 5.1).
    recipients: Option<Vec<String>>,
    webhook_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateCapsuleResponse {
    id: Uuid,
    round: u64,
    unlock_time: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct CapsuleStatus {
    id: Uuid,
    label: Option<String>,
    round: u64,
    unlock_time: DateTime<Utc>,
    status: &'static str,
    seconds_remaining: Option<i64>,
    content_type: &'static str,
    message: Option<String>,
    file_name: Option<String>,
    file_base64: Option<String>,
    recipients: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct CapsuleSummary {
    id: Uuid,
    label: Option<String>,
    unlock_time: DateTime<Utc>,
    status: &'static str,
}

async fn create_capsule(
    State(state): State<SharedState>,
    Json(req): Json<CreateCapsuleRequest>,
) -> Result<Json<CreateCapsuleResponse>, ApiError> {
    let (bytes, content) = parse_content(req.message, req.file_base64, req.file_name)?;
    let label = clean_label(req.label)?;

    let recipients: Vec<String> = req
        .recipients
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    if recipients.len() > MAX_RECIPIENTS {
        return Err(bad_request(format!("at most {MAX_RECIPIENTS} recipients")));
    }
    if recipients.iter().any(|r| r.chars().count() > MAX_LABEL_LEN) {
        return Err(bad_request("a recipient entry is too long"));
    }

    let webhook_url = match req.webhook_url.map(|u| u.trim().to_string()) {
        Some(u) if !u.is_empty() => {
            validate_webhook_url(&u)?;
            Some(u)
        }
        _ => None,
    };

    let unlock_time = match (req.unlock_in_seconds, req.unlock_at) {
        (Some(secs), None) => {
            if secs <= 0 {
                return Err(bad_request("unlock_in_seconds must be positive"));
            }
            Utc::now() + chrono::Duration::seconds(secs)
        }
        (None, Some(t)) => t,
        _ => return Err(bad_request("provide exactly one of `unlock_in_seconds` or `unlock_at`")),
    };
    if unlock_time <= Utc::now() {
        return Err(bad_request("unlock time must be in the future"));
    }

    if state.store.read().await.len() >= MAX_CAPSULES {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "capsule storage is full".into()));
    }

    let round = state.drand.round_at(unlock_time.into());
    let ciphertext = tlock_core::encrypt(&bytes, round, &state.pubkey).map_err(internal)?;
    let actual_unlock_time: DateTime<Utc> = state.drand.time_of_round(round).into();

    let id = Uuid::new_v4();
    state.store.write().await.insert(
        id,
        Capsule {
            id,
            label,
            ciphertext,
            created_at: Utc::now(),
            unlock_time: actual_unlock_time,
            content,
            decrypted: None,
            last_error: None,
            decrypt_failed: false,
            webhook_url,
            recipients,
        },
    );
    tracing::info!(%id, round, unlock_time = %actual_unlock_time, "capsule created");
    Ok(Json(CreateCapsuleResponse { id, round, unlock_time: actual_unlock_time }))
}

async fn get_capsule(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CapsuleStatus>, ApiError> {
    let store = state.store.read().await;
    let capsule = store.get(&id).ok_or_else(|| not_found("no such capsule"))?;
    Ok(Json(capsule.to_status()))
}

/// Disabled unless `CAPSULE_ENABLE_LIST=true`: labels are stored
/// unencrypted, so a public deployment shouldn't enumerate everyone's.
async fn list_capsules(State(state): State<SharedState>) -> Result<Json<Vec<CapsuleSummary>>, ApiError> {
    if !state.list_enabled {
        return Err(not_found("listing is disabled on this server"));
    }
    let store = state.store.read().await;
    let mut list: Vec<CapsuleSummary> = store
        .values()
        .map(|c| CapsuleSummary {
            id: c.id,
            label: c.label.clone(),
            unlock_time: c.unlock_time,
            status: c.status_str(),
        })
        .collect();
    list.sort_by_key(|c| c.unlock_time);
    Ok(Json(list))
}

async fn healthz() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let endpoints: Vec<String> = std::env::var("DRAND_ENDPOINTS")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_else(|_| DEFAULT_ENDPOINTS.iter().map(|s| s.to_string()).collect());

    tracing::info!(?endpoints, "connecting to drand");
    let drand = DrandClient::new(endpoints).await?;
    let pubkey = drand.info.public_key_g2()?;
    tracing::info!(scheme = %drand.info.scheme_id, period = drand.info.period, "connected to drand chain {}", drand.info.hash);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let state: SharedState = Arc::new(AppState {
        drand,
        pubkey,
        http,
        public_base_url: std::env::var("PUBLIC_BASE_URL").ok().map(|u| u.trim_end_matches('/').to_string()),
        list_enabled: std::env::var("CAPSULE_ENABLE_LIST").map(|v| v == "true" || v == "1").unwrap_or(false),
        store: RwLock::new(HashMap::new()),
        auctions: RwLock::new(HashMap::new()),
        switches: RwLock::new(HashMap::new()),
    });

    tokio::spawn(decryption_service::run(state.clone()));
    tokio::spawn(dead_man_switch::run(state.clone()));

    let static_dir = std::env::var("CAPSULE_STATIC_DIR").unwrap_or_else(|_| "static".to_string());
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/capsules", post(create_capsule).get(list_capsules))
        .route("/api/capsules/:id", get(get_capsule))
        .route("/api/auctions", post(auction::create))
        .route("/api/auctions/:id", get(auction::get))
        .route("/api/auctions/:id/bids", post(auction::place_bid))
        .route("/api/switches", post(dead_man_switch::create))
        .route("/api/switches/:id", get(dead_man_switch::get))
        .route("/api/switches/:id/checkin", post(dead_man_switch::checkin))
        .fallback_service(ServeDir::new(static_dir))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // `PORT` is what most PaaS hosts (Render, Railway, Fly, Heroku) inject.
    let bind = std::env::var("CAPSULE_BIND")
        .ok()
        .or_else(|| std::env::var("PORT").ok().map(|p| format!("0.0.0.0:{p}")))
        .unwrap_or_else(|| "0.0.0.0:3000".to_string());
    let addr: SocketAddr = bind.parse()?;
    tracing::info!(%addr, "capsule-server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
