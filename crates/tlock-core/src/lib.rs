//! Timelock (`tlock`) encryption core (Project H, Step 2).
//!
//! # The idea
//!
//! drand publishes, for every round `n`, a BLS signature
//!
//!     sig_n = H(n)^sk
//!
//! where `sk` is the network's (threshold-shared) master secret and `H`
//! hashes the round number onto the curve. That is *exactly* the shape
//! of a Boneh-Franklin identity-based-encryption (IBE) private key for
//! the identity `id = n`, with the network's declared public key
//! `P_pub = sk * P` acting as the IBE master public key.
//!
//! So: to encrypt a message "to round `n`", we run ordinary BF-IBE
//! encryption for identity `n`. Nobody -- including us -- can compute
//! the matching private key `sig_n` before round `n` is actually
//! reached, because that requires the drand network's threshold
//! signing ceremony to run. Once it does, `sig_n` becomes public and
//! *anyone* holding the ciphertext can decrypt. This is what makes the
//! lock trustless and irreversible: there is no key held by us, or by
//! drand, that decrypts early.
//!
//! # Scheme
//!
//! This module implements classic Boneh-Franklin IBE (`Ident. Based
//! Encryption from the Weil Pairing`, CRYPTO 2001) with its built-in
//! Fujisaki-Okamoto CCA transform, instantiated over BLS12-381 to match
//! drand's `bls-unchained-g1-rfc9380` scheme (identities/signatures on
//! G1, master public key on G2):
//!
//!     Q_id      = H1(id) = HashToG1(SHA256(round_be8))  ∈ G1   (exactly what drand signs)
//!     encrypt(id, M):
//!       σ  ←$ {0,1}^256
//!       r  = H3(σ, M)                            ∈ Z_q
//!       U  = r·P                                 ∈ G2   (P = G2 generator)
//!       V  = σ ⊕ H2(e(Q_id, P_pub)^r)
//!       W  = M ⊕ H4(σ)
//!       ciphertext = (U, V, W)
//!     decrypt((U, V, W), d_id):                  d_id = sig_n = sk·Q_id
//!       σ' = V ⊕ H2(e(d_id, U))                  [ e(d_id,U) = e(Q_id,P_pub)^r by bilinearity ]
//!       M' = W ⊕ H4(σ')
//!       reject unless U == H3(σ', M')·P           (re-derivation check, guards malleability)
//!
//! `M` here is a random 256-bit key, not the caller's actual message:
//! IBE ciphertexts are fixed-size, so we use `M` as an AES-256-GCM key
//! and encrypt the caller's real (arbitrary-length) payload with that,
//! exactly as `tlock_age` wraps an `age` file key. This is what lets
//! Step 2's "various data types (text, files, etc.)" requirement work
//! without redoing the pairing math per byte.
//!
//! # Security note
//!
//! This is a teaching implementation written for a course project. It
//! has not been audited, and its hash-function choices (H2/H3/H4, all
//! built from SHA-256/512 with domain-separation tags below) are not
//! guaranteed to be bit-compatible with the reference `drand/tlock` Go
//! implementation or `tlock-rs`. For anything beyond coursework, use
//! an audited library (`tlock_age`, `drand/tlock`).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use bls12_381_plus::{pairing, G1Affine, G2Affine, G2Projective, Gt, Scalar};
use drand_client::DrandClient;
use group::Group;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlockError {
    #[error("payload too large: {0} bytes (limit is 64 MiB per capsule)")]
    PayloadTooLarge(usize),
    #[error("malformed ciphertext: {0}")]
    Malformed(String),
    #[error("decryption failed: ciphertext integrity check did not pass (wrong key, corrupted data, or this capsule was not actually locked to the given round)")]
    IntegrityCheckFailed,
    #[error("AES-GCM error: {0}")]
    Aead(String),
}

const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// A timelock ciphertext: the IBE encapsulation `(U, V, W)` plus the
/// AES-256-GCM-encrypted payload it protects. Safe to store or
/// transmit in the clear -- that's the entire point of tlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// The drand round this capsule unlocks at.
    pub round: u64,
    /// `U = r·P`, compressed G2 point (96 bytes).
    #[serde(with = "b64")]
    pub u: Vec<u8>,
    /// `V = σ ⊕ H2(e(Q_id, P_pub)^r)` (32 bytes).
    #[serde(with = "b64")]
    pub v: Vec<u8>,
    /// `W = key ⊕ H4(σ)` (32 bytes).
    #[serde(with = "b64")]
    pub w: Vec<u8>,
    /// AES-GCM nonce (12 bytes).
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    /// AES-256-GCM ciphertext of the caller's actual payload
    /// (includes the 16-byte auth tag).
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// H2: GT -> 256 bits. `Gt` has no canonical wire format in the base
/// pairing crate, but the pairing's output is a deterministic function
/// of its inputs regardless of encoding, so hashing *some* fixed
/// serialization of it is all H2 needs to be a well-defined random
/// oracle for our purposes.
fn h2(gt: &Gt) -> [u8; 32] {
    let bytes: Vec<u8> = Vec::from(gt);
    let mut hasher = Sha256::new();
    hasher.update(b"TLOCK-CAPSULE-H2");
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// H3: (σ, key) -> scalar in Z_q. SHA-512 gives exactly the 64 bytes
/// `Scalar::from_bytes_wide` needs for a uniform reduction mod q.
fn h3(sigma: &[u8; 32], key: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"TLOCK-CAPSULE-H3");
    hasher.update(sigma);
    hasher.update(key);
    let digest: [u8; 64] = hasher.finalize().into();
    Scalar::from_bytes_wide(&digest)
}

/// H4: σ -> 256 bits.
fn h4(sigma: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TLOCK-CAPSULE-H4");
    hasher.update(sigma);
    hasher.finalize().into()
}

/// Encrypt `plaintext` so that it can only be recovered once drand
/// round `round` has been published and verified. `drand_pubkey` is
/// the target network's master public key (`ChainInfo::public_key_g2`).
pub fn encrypt(plaintext: &[u8], round: u64, drand_pubkey: &G2Affine) -> Result<Ciphertext, TlockError> {
    if plaintext.len() > MAX_PAYLOAD_BYTES {
        return Err(TlockError::PayloadTooLarge(plaintext.len()));
    }

    let mut rng = OsRng;

    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    let mut sigma = [0u8; 32];
    rng.fill_bytes(&mut sigma);

    let r = h3(&sigma, &key);

    let identity: G1Affine = DrandClient::hash_round_to_g1(round);
    let gid: Gt = pairing(&identity, drand_pubkey);
    let gid_r: Gt = gid * r;

    let u_point: G2Affine = (G2Projective::generator() * r).into();

    let v = xor32(&sigma, &h2(&gid_r));
    let w = xor32(&key, &h4(&sigma));

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let payload = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| TlockError::Aead(e.to_string()))?;

    Ok(Ciphertext {
        round,
        u: u_point.to_compressed().to_vec(),
        v: v.to_vec(),
        w: w.to_vec(),
        nonce: nonce_bytes.to_vec(),
        payload,
    })
}

/// Decrypt a [`Ciphertext`] given `d_id`, the verified drand BLS
/// signature for `ciphertext.round` (i.e. a [`drand_client::VerifiedRound::signature`]).
/// Callers are responsible for having actually verified that
/// signature against the network's public key before calling this --
/// `tlock-core` only handles the IBE/AEAD math, not beacon trust.
pub fn decrypt(ciphertext: &Ciphertext, d_id: &G1Affine) -> Result<Vec<u8>, TlockError> {
    let u_arr: [u8; 96] = ciphertext
        .u
        .as_slice()
        .try_into()
        .map_err(|_| TlockError::Malformed("U is not 96 bytes".into()))?;
    let u_point: G2Affine = Option::from(G2Affine::from_compressed(&u_arr))
        .ok_or_else(|| TlockError::Malformed("U is not a valid G2 point".into()))?;

    let v: [u8; 32] = ciphertext
        .v
        .as_slice()
        .try_into()
        .map_err(|_| TlockError::Malformed("V is not 32 bytes".into()))?;
    let w: [u8; 32] = ciphertext
        .w
        .as_slice()
        .try_into()
        .map_err(|_| TlockError::Malformed("W is not 32 bytes".into()))?;

    let gid_r: Gt = pairing(d_id, &u_point);
    let sigma = xor32(&v, &h2(&gid_r));
    let key = xor32(&w, &h4(&sigma));

    // Fujisaki-Okamoto re-derivation check: reject anything that
    // wasn't produced by an honest `encrypt` call with this key/sigma.
    let r_check = h3(&sigma, &key);
    let u_check: G2Affine = (G2Projective::generator() * r_check).into();
    if u_check != u_point {
        return Err(TlockError::IntegrityCheckFailed);
    }

    let nonce_arr: [u8; 12] = ciphertext
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| TlockError::Malformed("nonce is not 12 bytes".into()))?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(&nonce_arr), ciphertext.payload.as_slice())
        .map_err(|_| TlockError::IntegrityCheckFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This test only exercises the algebra (it fabricates a master
    /// keypair locally rather than talking to a real beacon), so it
    /// can run offline. Round-trips `encrypt`/`decrypt` and checks
    /// that a wrong `d_id` is rejected rather than producing garbage.
    #[test]
    fn round_trip_and_rejects_wrong_key() {
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 64];
        rng.fill_bytes(&mut sk_bytes);
        let sk = Scalar::from_bytes_wide(&sk_bytes);
        let pubkey: G2Affine = (G2Projective::generator() * sk).into();

        let round = 424242u64;
        let identity = DrandClient::hash_round_to_g1(round);
        let d_id: G1Affine = (identity * sk).into();

        let msg = b"the capsule is open";
        let ct = encrypt(msg, round, &pubkey).unwrap();
        let pt = decrypt(&ct, &d_id).unwrap();
        assert_eq!(pt, msg);

        // Wrong round's key must not decrypt.
        let other_identity = DrandClient::hash_round_to_g1(round + 1);
        let wrong_d_id: G1Affine = (other_identity * sk).into();
        assert!(decrypt(&ct, &wrong_d_id).is_err());
    }
}
