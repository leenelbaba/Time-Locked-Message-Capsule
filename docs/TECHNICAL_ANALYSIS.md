# Technical Analysis — Time-Locked Message Capsule

## Performance characteristics

* **Encryption cost** is dominated by one pairing computation
  (`e(Q_id, P_pub)`) plus a handful of scalar multiplications on
  BLS12-381 — sub-millisecond on modern hardware, independent of
  message size (the message-size-dependent part is AES-256-GCM over
  the payload, which is essentially free by comparison at the sizes
  this app targets).
* **Decryption cost** is the same shape: one pairing
  (`e(d_id, U)`), a re-derivation check (one scalar multiplication),
  and one AES-256-GCM decrypt.
* **Beacon round lookups are O(1) amortized** thanks to the in-memory
  cache in `drand-client` — a round, once fetched and verified, never
  needs to be re-verified.
* **The decryption service's poll loop is O(capsules-in-memory)** per
  tick (a linear scan to find due capsules). At the scale an
  in-memory demo server is meant for (thousands, not millions, of
  capsules) this is not a bottleneck; a production version backed by
  a real database would replace the scan with an indexed query
  (`WHERE unlock_round <= ? AND decrypted_at IS NULL`).

## Scalability

The design scales along two independent axes:

1. **Number of capsules** — bounded today by available RAM (each
   capsule is a small fixed-size ciphertext plus metadata). Moving
   `capsule-server`'s storage to Postgres/SQLite removes this bound
   entirely without touching `tlock-core` or `drand-client` (see
   `DESIGN.md` §4).
2. **Beacon load** — every capsule targeting the same round shares
   one cached `VerifiedRound`; the decryption service does not fetch
   the beacon once per capsule, only once per *distinct due round*
   across the whole poll cycle (via the cache).

The main scaling limit that *is* architectural rather than an
implementation detail: everything keys off round number, and
`quicknet`'s round period (3s) sets the finest unlock-time granularity
available — you cannot unlock "in 1 second," only "at the next round
boundary."

## Reliability strategies and failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| A configured drand endpoint is down | Requests to it fail | `DrandClient` tries every configured endpoint before giving up (see `DESIGN.md` §3) |
| All drand endpoints are down when a capsule becomes due | That tick's decryption attempt errors out; capsule stays `pending-decryption` | `decryption_service` retries every 3s indefinitely; nothing is lost, no partial state is written |
| A capsule's ciphertext is corrupted (e.g. bad JSON round-trip) | `tlock_core::decrypt`'s Fujisaki-Okamoto check fails | Returns `TlockError::IntegrityCheckFailed` rather than garbage plaintext; recorded as `last_error` on the capsule |
| Server process restarts | All in-memory capsules are lost | Documented limitation (`DESIGN.md` §4); out of scope for the assignment, straightforward to fix with a real datastore |
| Two decryption-service ticks race on the same capsule | Both try to decrypt the same due capsule | Guarded by the store's `RwLock` plus an `if capsule.decrypted.is_some() { return }` check inside the write lock, so the second attempt is a no-op |
| Client submits a past or malformed unlock time | Would create a capsule that's immediately/never meaningfully locked | Rejected at the API layer (`unlock_time <= Utc::now()` check) before any encryption happens |

## Additional failure modes (Step 5 features)

| Failure | Effect | Mitigation |
|---|---|---|
| Webhook receiver is down | Notification not delivered | 3 attempts with exponential backoff, then logged and dropped; the capsule itself is unaffected and still readable by link |
| Webhook URL points at an internal service | SSRF attempt | Rejected at creation (scheme/host/IP-literal checks), redirects disabled; DNS-based bypass is a documented residual risk |
| Check-in races with the deadline round | Switch may fire although the owner checked in | Check-ins refused once `now >= deadline`; the trigger path re-checks the ciphertext round under the write lock |
| Corrupted capsule ciphertext | Integrity check fails every tick | Capsule is flagged `failed` and no longer retried (no infinite retry loop) |
| Bid submitted after the reveal round exists | Bid would be readable immediately | Bidding closed once `current_round() >= reveal round` |

## Applications

* Personal time capsules, scheduled disclosures.
* **Sealed-bid auctions and voting** (implemented): all bids are locked
  to one round and open together; SHA-256 commitments let bidders audit.
* **Dead man's switch** (implemented): release enforced by the beacon;
  costs server-side plaintext retention while armed.
* **Notifications / messaging integration** (implemented as webhooks):
  anything that accepts a webhook can fan out to email, SMS or chat.

## Remaining extensions (not implemented)

* **Per-recipient confidentiality**: encrypt the AES key to each
  recipient's public key in addition to the timelock, so that only they
  can read it after the round.
* **Persistent storage** (SQLite/Postgres) so capsules survive restarts;
  `Ciphertext` is already `Serialize`/`Deserialize`.
* **Authentication, per-user capsule lists and rate limiting.**
* **Chained-scheme drand networks** (this client supports unchained
  schemes only) and byte-compatibility with the reference `tlock`/`age`
  format.
