//! Ed25519 signatures, nonce generation, and (for the optional parameter) X25519
//! sealed-box encryption.
//!
//! Authentication is done with Ed25519 *signatures*: the server only needs to
//! know that a packet was produced by the holder of a client's private key and
//! that the signed contents are intact. Replay is handled separately (nonces).
//!
//! The optional RESPONSE `param` additionally needs *confidentiality* on the
//! wire, so it is encrypted with an anonymous sealed box to the server's X25519
//! public key (ephemeral X25519 + ECDH + HKDF-SHA256 → XChaCha20-Poly1305). Only
//! the server's X25519 private key can decrypt; no per-client secrets are shared.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroizing;

/// Nonce size in bytes. 32 bytes == 256 bits, the protocol minimum.
pub const NONCE_LEN: usize = 32;

/// X25519 public-key size, and XChaCha20-Poly1305 nonce size.
const X25519_KEY_LEN: usize = 32;
const XNONCE_LEN: usize = 24;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error(
        "invalid private key: expected {} bytes",
        ed25519_dalek::SECRET_KEY_LENGTH
    )]
    BadPrivateKey,
    #[error("invalid public key")]
    BadPublicKey,
    #[error("invalid signature encoding")]
    BadSignature,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid encryption key")]
    BadEncryptionKey,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
}

/// A randomly generated, single-use challenge value.
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
    /// Generate a fresh nonce from the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut bytes);
        Nonce(bytes)
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        let bytes = B64.decode(s)?;
        let arr: [u8; NONCE_LEN] = bytes.try_into().map_err(|_| CryptoError::BadSignature)?;
        Ok(Nonce(arr))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the raw value at full length in logs; show a short prefix.
        write!(
            f,
            "Nonce({}…)",
            &self.to_base64()[..8.min(self.to_base64().len())]
        )
    }
}

/// A freshly generated Ed25519 keypair, encoded for placing in config files.
pub struct GeneratedKeys {
    /// Base64 of the 32-byte private key seed. Treat as a secret.
    pub private_key_b64: String,
    /// Base64 of the 32-byte public key.
    pub public_key_b64: String,
}

/// Generate a new Ed25519 keypair using the OS CSPRNG.
pub fn generate_keypair() -> GeneratedKeys {
    let signing = SigningKey::generate(&mut OsRng);
    // Wrap the secret bytes so they are zeroized on drop.
    let secret = Zeroizing::new(signing.to_bytes());
    GeneratedKeys {
        private_key_b64: B64.encode(secret.as_ref()),
        public_key_b64: B64.encode(signing.verifying_key().to_bytes()),
    }
}

/// Load a [`SigningKey`] from a base64-encoded 32-byte seed. The decoded secret
/// bytes are held in zeroizing storage so they do not linger in memory.
pub fn load_signing_key(private_key_b64: &str) -> Result<SigningKey, CryptoError> {
    let decoded = Zeroizing::new(B64.decode(private_key_b64)?);
    let seed: [u8; ed25519_dalek::SECRET_KEY_LENGTH] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadPrivateKey)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Load a [`VerifyingKey`] (public key) from base64.
pub fn load_verifying_key(public_key_b64: &str) -> Result<VerifyingKey, CryptoError> {
    let decoded = B64.decode(public_key_b64)?;
    let bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadPublicKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::BadPublicKey)
}

/// Sign a payload, returning the base64-encoded signature.
pub fn sign_payload(signing_key: &SigningKey, payload: &[u8]) -> String {
    let sig = signing_key.sign(payload);
    B64.encode(sig.to_bytes())
}

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Sign a payload, returning the raw 64-byte signature (for the binary wire).
pub fn sign_payload_raw(signing_key: &SigningKey, payload: &[u8]) -> [u8; SIGNATURE_LEN] {
    signing_key.sign(payload).to_bytes()
}

/// Verify a raw 64-byte signature over `payload` (uses `verify_strict`).
pub fn verify_payload_raw(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    verifying_key
        .verify_strict(payload, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Verify a base64-encoded signature over `payload` against `verifying_key`.
///
/// Uses `verify_strict` to reject signatures made with weak/torsion-tainted
/// public keys, eliminating malleability edge cases.
pub fn verify_payload(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_b64: &str,
) -> Result<(), CryptoError> {
    let sig_bytes = B64.decode(signature_b64)?;
    let sig_arr: [u8; ed25519_dalek::SIGNATURE_LENGTH] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Short, non-secret fingerprint of a public key, useful for diagnostics. This
/// is the base64 of the first 8 bytes of the key — it is not used for any
/// authorization decision.
pub fn public_key_fingerprint(public_key_b64: &str) -> Result<String, CryptoError> {
    let key = load_verifying_key(public_key_b64)?;
    Ok(B64.encode(&key.to_bytes()[..8]))
}

// ----------------------- Sealed-box encryption -----------------------
//
// `seal`/`open` are an anonymous sealed box: a fresh ephemeral X25519 keypair to
// the recipient's X25519 public key. The shared secret is run through HKDF-SHA256
// (salt = both public keys, info = a per-use context) into an XChaCha20-Poly1305
// key; the context is also the AEAD associated data, so a ciphertext for one
// context can't be opened in another. The blob carries the ephemeral public key
// and AEAD nonce. `seal` returns the ephemeral *secret* so the sender (client)
// can later open the server's authenticated reply.
//
// `seal_reply`/`open_reply` carry the server → client CHALLENGE. They key off the
// server's *static* X25519 secret and the client's ephemeral public key
// (static-ephemeral ECDH), so only the holder of the server's secret can produce
// a reply the client accepts — authenticating the server without per-client keys.

/// Context strings that domain-separate the three seal uses. They feed the HKDF
/// `info` and the AEAD associated data, so a ciphertext produced for one context
/// can never be opened in another (no cross-context confusion).
pub const CTX_WIRE: &[u8] = b"signedpulse:v1:wire"; // full-packet, client → server
pub const CTX_PARAM: &[u8] = b"signedpulse:v1:param"; // the RESPONSE parameter
const CTX_REPLY: &[u8] = b"signedpulse:v1:reply"; // server → client CHALLENGE

/// Raw 32-byte X25519 public/secret material as used on the wire.
pub type X25519Bytes = [u8; X25519_KEY_LEN];

/// Generate an X25519 keypair, returned as base64 (secret, public). The secret
/// goes in the server config; the public key is distributed to clients.
pub fn generate_encryption_keypair() -> (String, String) {
    let secret = XStaticSecret::random_from_rng(OsRng);
    let public = XPublicKey::from(&secret);
    (B64.encode(secret.to_bytes()), B64.encode(public.to_bytes()))
}

/// Decode a base64-encoded 32-byte X25519 key (public or secret).
pub fn x25519_from_base64(b64: &str) -> Result<X25519Bytes, CryptoError> {
    B64.decode(b64)?
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadEncryptionKey)
}

/// Derive the AEAD key from the X25519 shared secret, bound to both public keys
/// (as HKDF salt) and the context (as HKDF info).
fn derive_key(shared: &[u8], pub_a: &X25519Bytes, pub_b: &X25519Bytes, info: &[u8]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(2 * X25519_KEY_LEN);
    salt.extend_from_slice(pub_a);
    salt.extend_from_slice(pub_b);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .expect("32 is a valid HKDF-SHA256 output length");
    key
}

/// Anonymous sealed box: seal `plaintext` to `recipient_pub` under `context`.
/// Returns the raw blob (`eph_pub(32) || xnonce(24) || ct`) and the ephemeral
/// secret (so the sender can later `open_reply` an authenticated response).
pub fn seal(
    recipient_pub: &X25519Bytes,
    plaintext: &[u8],
    context: &[u8],
) -> Result<(Vec<u8>, X25519Bytes), CryptoError> {
    let recipient = XPublicKey::from(*recipient_pub);
    let eph_secret = XStaticSecret::random_from_rng(OsRng);
    let eph_pub_bytes = XPublicKey::from(&eph_secret).to_bytes();

    let shared = eph_secret.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(CryptoError::EncryptionFailed);
    }
    let key = Zeroizing::new(derive_key(
        shared.as_bytes(),
        &eph_pub_bytes,
        recipient_pub,
        context,
    ));

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: context,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut blob = Vec::with_capacity(X25519_KEY_LEN + XNONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&eph_pub_bytes);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok((blob, eph_secret.to_bytes()))
}

/// Open an anonymous sealed blob with `recipient_secret` under `context`.
/// Returns the plaintext and the sender's ephemeral public key.
pub fn open(
    recipient_secret: &X25519Bytes,
    blob: &[u8],
    context: &[u8],
) -> Result<(Vec<u8>, X25519Bytes), CryptoError> {
    if blob.len() < X25519_KEY_LEN + XNONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let secret = XStaticSecret::from(*recipient_secret);
    let recipient_pub = XPublicKey::from(&secret).to_bytes();

    let eph_pub_bytes: X25519Bytes = blob[..X25519_KEY_LEN]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce_bytes = &blob[X25519_KEY_LEN..X25519_KEY_LEN + XNONCE_LEN];
    let ciphertext = &blob[X25519_KEY_LEN + XNONCE_LEN..];

    let shared = secret.diffie_hellman(&XPublicKey::from(eph_pub_bytes));
    if !shared.was_contributory() {
        return Err(CryptoError::DecryptionFailed);
    }
    let key = Zeroizing::new(derive_key(
        shared.as_bytes(),
        &eph_pub_bytes,
        &recipient_pub,
        context,
    ));

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: context,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok((plaintext, eph_pub_bytes))
}

/// Seal a server→client reply authenticated by the server's *static* secret, to
/// the client's ephemeral public key. Because the key is derived from the
/// server's static key, only the holder of `server_secret` can produce a blob
/// the client will accept — this authenticates the server to the client. Blob is
/// `xnonce(24) || ct` (the sender public key is the known server static key).
pub fn seal_reply(
    server_secret: &X25519Bytes,
    client_eph_pub: &X25519Bytes,
    plaintext: &[u8],
    bind: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let secret = XStaticSecret::from(*server_secret);
    let server_pub = XPublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&XPublicKey::from(*client_eph_pub));
    if !shared.was_contributory() {
        return Err(CryptoError::EncryptionFailed);
    }
    let key = Zeroizing::new(derive_key(
        shared.as_bytes(),
        &server_pub,
        client_eph_pub,
        CTX_REPLY,
    ));

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    // AAD ties the reply to its request transcript (`bind`, e.g. the client's
    // HELLO nonce) so a captured CHALLENGE can't be replayed into the client
    // against a different HELLO.
    let aad = reply_aad(bind);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut blob = Vec::with_capacity(XNONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Open a server-authenticated reply: the client uses its ephemeral secret and
/// the server's *static* public key (which it has pinned as `server_encryption_key`).
/// Decryption succeeding proves the reply came from the holder of the server's
/// static secret.
pub fn open_reply(
    client_eph_secret: &X25519Bytes,
    server_pub: &X25519Bytes,
    blob: &[u8],
    bind: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < XNONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let secret = XStaticSecret::from(*client_eph_secret);
    let shared = secret.diffie_hellman(&XPublicKey::from(*server_pub));
    if !shared.was_contributory() {
        return Err(CryptoError::DecryptionFailed);
    }
    // Salt order must match seal_reply: server static pub, then client eph pub.
    let client_eph_pub = XPublicKey::from(&secret).to_bytes();
    let key = Zeroizing::new(derive_key(
        shared.as_bytes(),
        server_pub,
        &client_eph_pub,
        CTX_REPLY,
    ));

    let nonce_bytes = &blob[..XNONCE_LEN];
    let ciphertext = &blob[XNONCE_LEN..];
    let aad = reply_aad(bind);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Build the reply AEAD additional-data: the reply context tag followed by the
/// request-binding bytes. Both sides must compute this identically.
fn reply_aad(bind: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CTX_REPLY.len() + bind.len());
    aad.extend_from_slice(CTX_REPLY);
    aad.extend_from_slice(bind);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::response_signing_payload;

    #[test]
    fn nonce_is_correct_length_and_random() {
        let a = Nonce::generate();
        let b = Nonce::generate();
        assert_eq!(a.as_bytes().len(), NONCE_LEN);
        assert_eq!(NONCE_LEN * 8, 256, "nonce must be at least 256 bits");
        assert_ne!(a.0, b.0, "two fresh nonces must not collide");
    }

    #[test]
    fn nonce_base64_round_trips() {
        let n = Nonce::generate();
        let parsed = Nonce::from_base64(&n.to_base64()).unwrap();
        assert_eq!(n.0, parsed.0);
    }

    #[test]
    fn sign_and_verify_succeeds_for_matching_key() {
        let keys = generate_keypair();
        let sk = load_signing_key(&keys.private_key_b64).unwrap();
        let vk = load_verifying_key(&keys.public_key_b64).unwrap();
        let payload = response_signing_payload("s1", "c1", "bm9uY2U=", 1234, "");
        let sig = sign_payload(&sk, &payload);
        assert!(verify_payload(&vk, &payload, &sig).is_ok());
    }

    #[test]
    fn verify_fails_for_tampered_payload() {
        let keys = generate_keypair();
        let sk = load_signing_key(&keys.private_key_b64).unwrap();
        let vk = load_verifying_key(&keys.public_key_b64).unwrap();
        let sig = sign_payload(&sk, b"original");
        assert!(matches!(
            verify_payload(&vk, b"tampered", &sig),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_fails_for_wrong_public_key() {
        let signer = generate_keypair();
        let other = generate_keypair();
        let sk = load_signing_key(&signer.private_key_b64).unwrap();
        let wrong_vk = load_verifying_key(&other.public_key_b64).unwrap();
        let sig = sign_payload(&sk, b"hello");
        assert!(verify_payload(&wrong_vk, b"hello", &sig).is_err());
    }

    #[test]
    fn generated_private_key_round_trips() {
        let keys = generate_keypair();
        assert!(load_signing_key(&keys.private_key_b64).is_ok());
        assert!(load_verifying_key(&keys.public_key_b64).is_ok());
    }

    fn server_keys() -> (X25519Bytes, X25519Bytes) {
        let (s, p) = generate_encryption_keypair();
        (
            x25519_from_base64(&s).unwrap(),
            x25519_from_base64(&p).unwrap(),
        )
    }

    #[test]
    fn seal_open_round_trips() {
        let (secret, public) = server_keys();
        let (blob, _) = seal(&public, b"deploy-v1.4.2", CTX_PARAM).unwrap();
        let (plaintext, _) = open(&secret, &blob, CTX_PARAM).unwrap();
        assert_eq!(plaintext, b"deploy-v1.4.2");
    }

    #[test]
    fn open_fails_with_wrong_server_key() {
        let (_secret, public) = server_keys();
        let (other_secret, _) = server_keys();
        let (blob, _) = seal(&public, b"secret", CTX_PARAM).unwrap();
        assert!(matches!(
            open(&other_secret, &blob, CTX_PARAM),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn open_fails_on_tampered_ciphertext() {
        let (secret, public) = server_keys();
        let (mut blob, _) = seal(&public, b"secret", CTX_PARAM).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open(&secret, &blob, CTX_PARAM).is_err());
    }

    #[test]
    fn open_fails_with_wrong_context() {
        // Domain separation: a ciphertext sealed under one context must not open
        // under another (prevents wire/param/reply cross-confusion).
        let (secret, public) = server_keys();
        let (blob, _) = seal(&public, b"x", CTX_WIRE).unwrap();
        assert!(open(&secret, &blob, CTX_PARAM).is_err());
        assert!(open(&secret, &blob, CTX_WIRE).is_ok());
    }

    #[test]
    fn authenticated_reply_round_trip_and_forgery_rejected() {
        // client → server (anonymous, WIRE), server → client (authenticated reply).
        let (server_sec, server_pub) = server_keys();
        let (hello_blob, client_eph_sec) = seal(&server_pub, b"HELLO", CTX_WIRE).unwrap();
        let (hello, client_eph_pub) = open(&server_sec, &hello_blob, CTX_WIRE).unwrap();
        assert_eq!(hello, b"HELLO");

        let bind = b"hello-nonce-xyz";
        let reply_blob = seal_reply(&server_sec, &client_eph_pub, b"CHALLENGE", bind).unwrap();
        let reply = open_reply(&client_eph_sec, &server_pub, &reply_blob, bind).unwrap();
        assert_eq!(reply, b"CHALLENGE");

        // A reply bound to one HELLO nonce must not open under a different bind,
        // so a captured CHALLENGE can't be replayed against another HELLO.
        assert!(open_reply(&client_eph_sec, &server_pub, &reply_blob, b"other-nonce").is_err());

        // A forger without the server's static secret cannot produce a reply the
        // client accepts (server authentication).
        let (attacker_sec, _) = server_keys();
        let forged = seal_reply(&attacker_sec, &client_eph_pub, b"CHALLENGE", bind).unwrap();
        assert!(open_reply(&client_eph_sec, &server_pub, &forged, bind).is_err());
    }

    #[test]
    fn seal_is_nondeterministic() {
        let (_secret, public) = server_keys();
        // Ephemeral key + random nonce mean identical plaintext yields different
        // ciphertext each time, so a sniffer cannot correlate repeated params.
        assert_ne!(
            seal(&public, b"same", CTX_PARAM).unwrap().0,
            seal(&public, b"same", CTX_PARAM).unwrap().0
        );
    }
}
