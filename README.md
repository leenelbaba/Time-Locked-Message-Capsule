# Time-Locked Message Capsule

A `tlock` timelock encryption system built on the League of Entropy's
`drand` randomness beacon, for the Applied Cryptography "Project H"
assignment.

Encrypt a message (or file) so that it can only be decrypted after a
chosen future time — with no trusted party, including this server,
holding a key that could open it early.

## How it works, in one paragraph

drand publishes a fresh BLS signature every few seconds
(`sig_n = H(n)^sk` for round `n`). That signature has exactly the
right shape to be a Boneh-Franklin identity-based-encryption private
key for the identity `n`. So encrypting "to round `n`" is just running
ordinary IBE encryption against drand's public key with identity `n`
— and the corresponding private key doesn't exist yet, anywhere, until
the beacon actually reaches that round. See `DESIGN.md` for the full
write-up.

## Project layout

```
crates/
  drand-client/    async drand HTTP client: fetch + BLS-verify rounds,
                   round <-> time conversion, in-memory caching
  tlock-core/      the timelock encryption itself (Boneh-Franklin IBE
                   + AES-256-GCM), independent of any web framework
  capsule-server/  axum web app (create/check capsules) + the
                   background service that auto-decrypts due capsules
DESIGN.md          architecture + protocol write-up
docs/
  USER_GUIDE.md
  TECHNICAL_ANALYSIS.md
```

## Running it (VS Code / any machine with Rust)

Prerequisites: [Rust](https://rustup.rs) 1.74+ (install the
`rust-analyzer` VS Code extension for inline errors/autocomplete).

```bash
cd timelock-capsule
cargo build          # first build downloads crates.io dependencies
cargo run -p capsule-server
```

Then open **http://localhost:3000** in a browser. The default config
talks to drand's public `quicknet` network over the internet, so you
need network access for both `cargo build` (fetching crates) and at
runtime (fetching beacon rounds).

Useful env vars (see top of `capsule-server/src/main.rs`):

| Var                  | Default                              | Purpose                         |
|----------------------|---------------------------------------|----------------------------------|
| `CAPSULE_BIND`       | `0.0.0.0:3000`                        | server listen address           |
| `DRAND_ENDPOINTS`    | quicknet (api.drand.sh + Cloudflare)  | comma-separated relay URLs      |
| `CAPSULE_STATIC_DIR` | `static`                              | where the frontend files live   |
| `RUST_LOG`           | `info`                                | log verbosity (`tracing`)       |

### Running the crypto tests offline

`tlock-core` has a self-contained unit test that fabricates its own
keypair rather than calling out to drand, so it runs with no network:

```bash
cargo test -p tlock-core
```

### Quick manual smoke test

```bash
# seal a message that unlocks in 15 seconds
curl -s localhost:3000/api/capsules -H 'content-type: application/json' \
  -d '{"message":"hello future","unlock_in_seconds":15}'

# poll it (swap in the id from the response above)
curl -s localhost:3000/api/capsules/<id>
```

## Known limitations (see DESIGN.md / TECHNICAL_ANALYSIS.md for more)

* **Storage is in-memory** (capsules, auctions, switches). Capsules disappear on server restart.
  Swapping in a real database only touches `capsule-server`'s
  `Capsule`/`AppState` types — the crypto crates don't know or care
  how ciphertexts are stored.
* **Not audited, not wire-compatible with `drand/tlock`.** The
  hash-function choices inside `tlock-core` (H2/H3/H4) are a
  from-scratch, documented instantiation of the Boneh-Franklin paper
  for this course project, not a byte-for-byte reimplementation of the
  reference Go/Rust libraries. Don't use this for anything that
  matters.
* **Built without network access to `cargo build`/`cargo test`
  against real dependency versions**, so treat the first build as the
  real correctness check — see the "if the build fails" note in
  `DESIGN.md`.


## Features

* Time-locked capsules (text or files), automatic decryption, webhook
  notifications, recipients
* Sealed-bid auction with public SHA-256 commitments
* Dead man's switch with check-ins
* drand client: multi-endpoint fallback, BLS verification, bounded cache

## Deploying (GitHub -> hosting)

The app is a long-running Rust server with a background decryption
service and in-memory state, so it needs a container/process host
(Render, Railway, Fly.io, a VPS). **GitHub Pages / Netlify / Vercel
static hosting will not work.**

1. Run `cargo build` once locally so `Cargo.lock` is generated, then
   commit it (it's a binary crate - lockfiles should be committed).
2. `git init && git add . && git commit -m "Project H" && git remote add origin <your repo> && git push -u origin main`
3. `.github/workflows/ci.yml` builds and tests on every push.
4. On your host, create a **Docker** web service from the repo (a
   `Dockerfile` is included). It reads `PORT` automatically. Health
   check path: `/healthz`. Optional env vars: `PUBLIC_BASE_URL`
   (used in webhook links, e.g. `https://yourapp.onrender.com`),
   `DRAND_ENDPOINTS`, `CAPSULE_ENABLE_LIST`.
5. The free tiers of most hosts sleep when idle: while asleep nothing
   is decrypted, and every capsule is lost on restart. Fine for a demo,
   so create fresh capsules right before presenting.

Local Docker test: `docker build -t capsule . && docker run -p 3000:3000 capsule`

## If `cargo build` fails

This code could not be compiled where it was written. The most likely
trouble spots are third-party API names in `bls12_381_plus` (check
docs.rs for the pinned version):

* `G1Projective::hash_to_curve(msg, dst)` in `drand-client` (some
  versions expose `hash::<ExpandMsgXmd<Sha256>>(msg, dst)` instead)
* `Scalar::from_bytes_wide`, `Vec::<u8>::from(&Gt)`, and `Gt * Scalar`
  in `tlock-core`
* `Option::from(G1Affine::from_compressed(..))` conversions

Send the compiler errors back and they are quick fixes.
