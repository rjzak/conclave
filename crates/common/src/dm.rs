// SPDX-License-Identifier: Apache-2.0

//! End-to-end encryption for direct messages.
//!
//! A shared symmetric key is derived from the two users' ed25519 identity keys,
//! each converted to its X25519 (Montgomery) form for a static Diffie-Hellman
//! exchange. Both sides compute the same key from their own private key and the
//! other's public key, so the relaying server — which never holds a private key
//! — cannot read the messages. Users can compare the [`fingerprint`] of a peer's
//! key out of band to detect a server substituting its own key.

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, Generate};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha384};

use crate::net::{SigningKey, VerifyingKey};

/// HKDF info string, domain-separating the derived key to this use.
const DM_INFO: &[u8] = b"conclave-direct-message";

/// Length of the XChaCha20-Poly1305 nonce prepended to each ciphertext.
const NONCE_LEN: usize = 24;

/// Derive the shared 256-bit key for direct messages between the local user
/// (holding `my_signing`) and the peer identified by `their_verifying`. Both
/// users compute the same key.
///
/// # Panics
///
/// Never in practice: expanding 32 bytes of HKDF output cannot fail.
#[must_use]
pub fn shared_key(my_signing: &SigningKey, their_verifying: &VerifyingKey) -> [u8; 32] {
    // ed25519 -> X25519 static Diffie-Hellman: their public point times our
    // secret scalar yields the same shared point on both sides.
    let shared = (their_verifying.to_montgomery() * my_signing.to_scalar()).to_bytes();
    let hkdf = Hkdf::<Sha384>::new(None, &shared);
    let mut key = [0u8; 32];
    hkdf.expand(DM_INFO, &mut key)
        .expect("HKDF expand of 32 bytes never fails");
    key
}

/// Encrypt a direct-message payload. The output is `nonce || ciphertext`.
///
/// # Panics
///
/// Never in practice: XChaCha20-Poly1305 encryption cannot fail.
#[must_use]
#[track_caller]
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_bytes: [u8; NONCE_LEN] = Generate::generate();
    let nonce: &XNonce = (&nonce_bytes).into();
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("XChaCha20-Poly1305 encryption never fails");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a payload produced by [`encrypt`].
///
/// # Errors
///
/// Fails if the payload is malformed or authentication does not verify.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return Err(anyhow!("Direct message too short"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = <&XNonce>::try_from(nonce_bytes).map_err(|_| anyhow!("Invalid nonce"))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Direct message decryption failed: {e}"))
}

/// A hex SHA-384 fingerprint of a public key, for verifying a peer's identity
/// out of band.
#[must_use]
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(96);
    for byte in Sha384::digest(public_key) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, fingerprint, shared_key};
    use crate::net::random_keypair;

    #[test]
    fn both_sides_derive_the_same_key() {
        let (alice_secret, alice_public) = random_keypair();
        let (bob_secret, bob_public) = random_keypair();
        // Alice uses her secret and Bob's public; Bob uses his secret and
        // Alice's public. The keys must match.
        assert_eq!(
            shared_key(&alice_secret, &bob_public),
            shared_key(&bob_secret, &alice_public)
        );
    }

    #[test]
    fn round_trips_a_message() {
        let (alice_secret, alice_public) = random_keypair();
        let (bob_secret, bob_public) = random_keypair();
        let sealed = encrypt(&shared_key(&alice_secret, &bob_public), b"hello bob");
        let opened = decrypt(&shared_key(&bob_secret, &alice_public), &sealed).unwrap();
        assert_eq!(opened, b"hello bob");
    }

    #[test]
    fn a_wrong_key_fails_to_decrypt() {
        let (alice_secret, _alice_public) = random_keypair();
        let (_bob_secret, bob_public) = random_keypair();
        let (eve_secret, _eve_public) = random_keypair();
        let sealed = encrypt(&shared_key(&alice_secret, &bob_public), b"secret");
        // Eve derives a different shared key and cannot open the message.
        assert!(decrypt(&shared_key(&eve_secret, &bob_public), &sealed).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_hex() {
        let (_secret, public) = random_keypair();
        let printed = fingerprint(&public.to_bytes());
        assert_eq!(printed.len(), 96); // SHA-384 = 48 bytes = 96 hex chars
        assert_eq!(printed, fingerprint(&public.to_bytes()));
    }
}
