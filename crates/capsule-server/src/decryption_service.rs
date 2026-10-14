//! Automatic decryption service (Project H, Step 4).
//!
//! Every few seconds: find capsules whose round has been reached, fetch
//! and BLS-verify that round (falling back across drand endpoints, see
//! `drand_client::DrandClient::get_round`), decrypt, and notify.
//!
//! Notifications: if a capsule has a `webhook_url`, a JSON POST is sent
//! when it unlocks (3 attempts, exponential backoff). The payload
//! carries metadata and a link but deliberately NOT the plaintext, so a
//! webhook receiver (chat app, Zapier, email relay...) never sees the
//! content unless the recipient opens the link.
//!
//! The loop is stateless and idempotent: a failed network fetch is just
//! retried next tick; a capsule scheduled far in the future is simply
//! skipped until due; a capsule whose *ciphertext* fails the integrity
//! check is flagged `failed` and not retried forever.

use std::time::Duration;

use uuid::Uuid;

use crate::{send_webhook, Content, SharedState};

const POLL_INTERVAL: Duration = Duration::from_secs(3);

pub async fn run(state: SharedState) {
    let mut interval = tokio::time::interval(POLL_INTERVAL);
    loop {
        interval.tick().await;
        tick(&state).await;
    }
}

async fn tick(state: &SharedState) {
    let current_round = state.drand.current_round();
    let due: Vec<Uuid> = {
        let store = state.store.read().await;
        store
            .values()
            .filter(|c| c.decrypted.is_none() && !c.decrypt_failed && c.ciphertext.round <= current_round)
            .map(|c| c.id)
            .collect()
    };

    for id in due {
        match try_unlock(state, id).await {
            Ok(true) => {
                tracing::info!(%id, "capsule unlocked and decrypted");
                notify_unlocked(state, id).await;
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(%id, error = %e, "could not decrypt due capsule"),
        }
    }
}

async fn try_unlock(state: &SharedState, id: Uuid) -> anyhow::Result<bool> {
    let round = {
        let store = state.store.read().await;
        match store.get(&id) {
            Some(c) if c.decrypted.is_none() && !c.decrypt_failed => c.ciphertext.round,
            _ => return Ok(false),
        }
    };

    // Network failure => Err => retried next tick.
    let verified = state.drand.get_round(round).await?;

    let mut store = state.store.write().await;
    let Some(capsule) = store.get_mut(&id) else { return Ok(false) };
    if capsule.decrypted.is_some() {
        return Ok(false);
    }
    match tlock_core::decrypt(&capsule.ciphertext, &verified.signature) {
        Ok(plaintext) => {
            capsule.decrypted = Some(plaintext);
            capsule.last_error = None;
            Ok(true)
        }
        Err(e) => {
            // Not a network problem: retrying cannot help.
            capsule.decrypt_failed = true;
            capsule.last_error = Some(e.to_string());
            Err(anyhow::anyhow!(e.to_string()))
        }
    }
}

async fn notify_unlocked(state: &SharedState, id: Uuid) {
    let (url, payload) = {
        let store = state.store.read().await;
        let Some(c) = store.get(&id) else { return };
        let Some(url) = c.webhook_url.clone() else { return };
        let link = match &state.public_base_url {
            Some(base) => format!("{base}/?id={}", c.id),
            None => format!("/?id={}", c.id),
        };
        let payload = serde_json::json!({
            "event": "capsule.unlocked",
            "id": c.id,
            "label": c.label,
            "recipients": c.recipients,
            "round": c.ciphertext.round,
            "unlock_time": c.unlock_time,
            "content_type": match c.content { Content::Text => "text", Content::File { .. } => "file" },
            "link": link,
        });
        (url, payload)
    };
    let http = state.http.clone();
    tokio::spawn(async move { send_webhook(&http, &url, payload).await });
}
