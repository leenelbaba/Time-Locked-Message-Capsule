# Design Document — Time-Locked Message Capsule

## 1. Architecture

Three crates, cleanly separated by responsibility:

```
 ┌────────────────┐     verified rounds      ┌──────────────┐
 │  drand-client   │ <----------------------- │  drand relay  │ (HTTP,
 │                 │  round<->time conversion │  (quicknet)   │  public)
 └───────┬─────────┘                          └──────────────┘
         │ VerifiedRound { round, signature }
         ▼
 ┌─────────────────┐
 │   tlock-core     │  encrypt(plaintext, round, pubkey) -> Ciphertext
 │  (pure crypto)   │  decrypt(Ciphertext, signature)    -> plaintext
 └───────┬──────────┘
         │ Ciphertext (JSON-serializable, safe to store anywhere)
         ▼
 ┌───────────────────────────────┐
 │        capsule-server          │
 │  axum API + static frontend    │  <-- user
 │  + decryption_service (bg task)│
 └────────────────────────────────┘
```

* **`drand-client`** knows nothing about encryption. It only fetches,
  verifies, caches, and converts round numbers <-> wall-clock time.
* **`tlock-core`** knows nothing about HTTP, storage, or the beacon's
  transport — it takes a public key and a round number as opaque
  inputs and does the IBE math. It's tested offline (see its unit
  test) precisely because it has no network dependency.
* **`capsule-server`** is the only crate that's aware of "capsules" as
  a concept, HTTP, or persistence. It composes the other two.

This separation is what makes Step 5 ("Advanced Features") additions
cheap: threshold decryption or a dead-man's-switch are both just new
call sites around the same `tlock_core::encrypt`/`decrypt`, not
rewrites.

## 2. The cryptographic protocol

### 2.1 Why drand signatures work as IBE private keys

drand's unchained schemes (e.g. `bls-unchained-g1-rfc9380`, used by
`quicknet`) publish, every `period` seconds, a round number `n` and

```
sig_n = H(n)^sk        (a point on G1)
```

where `sk` is the network's threshold-shared secret and `H` is a
hash-to-curve function. The network's declared public key is
`P_pub = sk · P` on G2.

Boneh-Franklin identity-based encryption needs exactly a "master
public key" `P_pub = s·P` and, per identity `id`, a private key
`d_id = s·H(id)`. Set `id := n`. Then `d_id = sig_n` — drand is
already running the IBE key-generation authority, one identity
(round) at a time, and publishing each private key the moment its
round is reached. Nobody, including drand's own operators
individually, can produce `sig_n` before the threshold signing
ceremony for round `n` actually happens.

### 2.2 Encryption scheme (`tlock-core`)

Classic Boneh-Franklin (CRYPTO 2001) with its Fujisaki-Okamoto
transform, using BLS12-381 pairings to match drand:

```
Q_id = HashToG1(SHA256(round_be8))            G1  (exactly the point drand signs; see section 6)
encrypt(round, M):
  σ ←$ {0,1}^256
  r  = H3(σ, M)
  U  = r·P                                   G2  (P = G2 generator)
  V  = σ ⊕ H2(e(Q_id, P_pub)^r)
  W  = M ⊕ H4(σ)
decrypt((U,V,W), d_id):
  σ' = V ⊕ H2(e(d_id, U))         [ = H2(e(Q_id,P_pub)^r) by bilinearity ]
  M' = W ⊕ H4(σ')
  reject unless U == H3(σ',M')·P
```

`M` is a random 256-bit AES-256 key, not the user's real message —
IBE ciphertexts are fixed-size, so `tlock-core` uses the IBE layer
purely as a key-encapsulation mechanism and encrypts the caller's
actual (arbitrary-length) payload with AES-256-GCM under `M`. This
mirrors how `tlock_age` wraps an `age` file key, and is what lets a
30 KB PDF and a two-line text message use the same code path.

The re-derivation check (`U == H3(σ',M')·P`) is what makes this CCA-
secure rather than just "encrypt and hope": a corrupted or tampered
ciphertext fails this check and is rejected before any plaintext is
returned, rather than silently producing garbage.

### 2.3 What's *not* implemented

Two things a production system would add, deliberately left out to
keep the assignment's scope manageable:

* **Byte-level compatibility with `drand/tlock`.** The paper leaves
  H2/H3/H4 as "some cryptographic hash function"; this implementation
  picks SHA-256/SHA-512 with explicit domain-separation tags rather
  than replicating the reference implementation's exact choices. A
  ciphertext from this server will not decrypt with the official
  `tlock` CLI, and vice versa.
* **A formal security proof / audit.** This is coursework, not a
  library to depend on.

## 3. Distributed-system challenges

| Challenge | Approach |
|---|---|
| **Beacon node unavailability** | `DrandClient` is constructed with a *list* of endpoints (quicknet's own relay + a Cloudflare mirror by default). Both chain-info fetch and per-round fetch try each endpoint in order and only fail once all of them do (`DrandError::AllEndpointsFailed`). |
| **Network failures during decryption** | `decryption_service` treats every tick as stateless and idempotent: a failed fetch this tick just gets retried next tick (every 3s), with the error recorded on the capsule (`last_error`) so the API/UI can show it without the whole service crashing. |
| **Caching beacon values** | `drand-client`'s `Cache` stores every *verified* round in memory, keyed by round number, bounded to `DEFAULT_CACHE_CAPACITY` entries with oldest-round eviction. Beacon values are immutable once published, so there's no invalidation to worry about — only bounding memory use. |
| **Messages scheduled far into the future** | Nothing about the design has an upper bound: a capsule just sits with `decrypted: None` until `current_round >= ciphertext.round`, however far away that is. The only practical limit is `round_at`'s `u64` math, which overflows only ~500,000 years out at quicknet's 3-second period. |
| **Clock/round-boundary edge cases** | `round_at` mirrors drand's own definition (`ceil((t - genesis)/period) + 1`, clamped to round 1 for anything at/before genesis) so that a client's chosen unlock time and the server's round selection agree; `time_of_round` is its exact inverse, and the API returns the *actual* round-aligned unlock time (which can be up to one `period` later than what the user typed) rather than their raw input, so the UI never shows a countdown that undershoots. |

## 4. Data model & storage

`capsule-server` stores capsules in `Arc<RwLock<HashMap<Uuid, Capsule>>>`
— deliberately the simplest thing that works. `Capsule` holds the
`tlock_core::Ciphertext` (which is plain-old-data and JSON-serializable
via `serde`), metadata (label, unlock time, content type), and an
`Option<Vec<u8>>` for the plaintext once decrypted. Swapping this for
Postgres/SQLite would mean writing `Ciphertext` (already `Serialize`)
to a `ciphertext_json` column and reconstructing `Capsule` on load —
no change to `tlock-core` or `drand-client` at all.

## 5. Step 5 features (implemented)

### 5.1 Notifications, recipients and webhooks

A capsule may carry `recipients` (free-form names/emails, max 20) and a
`webhook_url`. When `decryption_service` unlocks the capsule it POSTs
`{event, id, label, recipients, round, unlock_time, content_type, link}`
to the webhook (3 attempts, exponential backoff). The payload contains a
link but **never the plaintext**, so a relay (Slack, Zapier, Make, IFTTT ->
email/SMS) never sees the content. This is the integration point for
"email, messaging": the server does not speak SMTP itself, it hands a
JSON event to whatever automation the user already has.

`recipients` is *not* a cryptographic access list. tlock ciphertexts are
decryptable by **anyone** once the round is public; that is the point of
the construction. Restricting readers would need an extra encryption
layer (e.g. wrapping the AES key per recipient); we deliberately do not
claim that property. "Threshold decryption" in the assignment's sense is
already provided one level down: drand's own threshold BLS network is
what produces the round signature, so no single party can release a
capsule early.

### 5.2 Sealed-bid auction / commitment scheme (`auction.rs`)

* The auctioneer creates an auction with a reveal round `R`.
* Every bid is tlock-encrypted to the same `R` and stored as an ordinary
  capsule; the existing decryption service opens all of them when `R`
  is published. So bids cannot be read early by anyone, and all become
  readable simultaneously (no "wait and see" advantage).
* On submission the bidder receives a SHA-256 **commitment** over the
  ciphertext fields. The list of commitments is public before the
  reveal. After the reveal, anyone can recompute the hash of a stored
  ciphertext and compare it with the receipt.
* Bids are refused once `R` has been published (its signature, i.e. the
  decryption key, is then public).
* If every revealed bid parses as a number the API also returns the
  highest one (voting works the same way with text bids).
* Honest limitation: the server stores the ciphertexts, so a malicious
  *server* could drop or reorder bids; commitments make that detectable
  only for bidders who keep their receipt.

### 5.3 Dead man's switch (`dead_man_switch.rs`)

A switch holds one standing tlock ciphertext locked to
`now + check_in_interval`. A check-in (authenticated by a random
128-bit token shown once) re-encrypts the message to a later round and
discards the old ciphertext. If nobody checks in, the deadline round is
published, the service decrypts the ciphertext, verifies it equals the
stored plaintext and marks the switch `triggered`, revealing the content
and firing the webhook.

Trade-offs, stated plainly:

* Re-encryption needs the plaintext, so **the server keeps the plaintext
  in memory while the switch is armed**. A plain capsule does not.
  Release timing is still enforced by the beacon, but confidentiality
  *before* release depends on trusting the server.
* Check-ins are refused once `now >= deadline`: the old round's
  signature may already be public, so the old ciphertext could already
  be open to anyone.
* There is a small unavoidable race at the boundary (a check-in landing
  in the same few seconds as the round); the rule above resolves it in
  favour of "fired".

## 6. Round/time conversion and the signed message (corrections)

Two details were wrong in the first version and are fixed:

1. **Signed message.** For unchained schemes drand signs
   `SHA256(RoundToBytes(round))` (8-byte big-endian round), per its
   protocol spec (`DigestMessage`). `hash_round_to_g1` therefore
   hashes `SHA256(round_be8)` to G1 (DST
   `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`). Hashing the raw
   round bytes would produce a different point and break verification
   and decryption against the real beacon.
2. **Two different round formulas.**
   `current_round() = floor((now-genesis)/period)+1` answers "what has
   been published by now" (drand's `CurrentRound`).
   `round_at(t) = ceil((t-genesis)/period)+1` answers "which round do I
   encrypt to so that it stays locked until at least `t`".
   `time_of_round(r) = genesis + (r-1)*period`. Using the floor for the
   encryption target would unlock up to one period early.

## 7. Deployment and security notes

* The server is a long-running process with a background service and
  in-memory state: host it on a container/PaaS host (Render, Railway,
  Fly.io, a VPS), **not** a static host (GitHub Pages) or a serverless
  platform. Free tiers that sleep will pause decryption and lose all
  capsules on restart.
* Webhook URLs are validated (http/https only, no localhost/private-IP
  literals, redirects disabled) to limit SSRF. A DNS name that resolves
  to a private address is *not* blocked -- for a public deployment put
  the server behind an egress firewall or resolve-and-check.
* The UI escapes all user-provided strings; labels are unencrypted;
  `GET /api/capsules` (list) is disabled unless `CAPSULE_ENABLE_LIST=true`
  because it would enumerate everyone's labels.
* No authentication or rate limiting beyond fixed caps (capsules,
  switches, auctions, bids, body size). Add a reverse-proxy rate limit
  before exposing it widely.
