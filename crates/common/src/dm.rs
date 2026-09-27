// SPDX-License-Identifier: Apache-2.0

//! End-to-end encryption for direct messages, and for the files users send each
//! other alongside them.
//!
//! A shared symmetric key is derived from the two users' ed25519 identity keys,
//! each converted to its X25519 (Montgomery) form for a static Diffie-Hellman
//! exchange. Both sides compute the same key from their own private key and the
//! other's public key, so the relaying server — which never holds a private key
//! — cannot read the messages. Users can compare the fingerprint of a peer's
//! key out of band to detect a server substituting its own key.
//!
//! A file transfer uses the same key: its name and each of its chunks are
//! sealed separately, so the server relaying them learns only how large the
//! file claims to be.

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, Generate};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

use crate::net::{SigningKey, VerifyingKey};

/// HKDF info string, domain-separating the derived key to this use.
const DM_INFO: &[u8] = b"conclave-direct-message";

/// Length of the XChaCha20-Poly1305 nonce prepended to each ciphertext.
const NONCE_LEN: usize = 24;

/// Bytes [`encrypt`] adds to a plaintext: the prepended nonce and the trailing
/// authentication tag. Lets a relay bound a ciphertext against the plaintext
/// size it was promised without being able to read either.
pub const OVERHEAD: usize = NONCE_LEN + 16;

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

/// Which message in a conversation a reaction is about.
///
/// A conversation has two sides, each numbering its own messages from zero, so a
/// number alone is ambiguous: `own` says which side's numbering to read it in.
/// It is written from the point of view of whoever *sent* the reaction, so the
/// receiving side flips it — their "my message" is the reader's "theirs".
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DmMessageRef {
    /// The number the message's author gave it.
    pub id: u32,

    /// Whether the message belongs to whoever sent this reaction.
    pub own: bool,
}

/// What a direct message's ciphertext holds once opened.
///
/// Sealed messages all look alike from outside, which is the point: a reaction
/// is not distinguishable from a message, and neither is readable.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DmPayload {
    /// Something somebody said.
    Text {
        /// The sender's own number for this message, which a reaction can name.
        /// Unique within what that sender has sent this session, which is as
        /// long as a conversation lasts.
        id: u32,

        /// The message.
        text: String,
    },

    /// An emoji put on an earlier message in this conversation, or taken back.
    Reaction {
        /// The message reacted to.
        target: DmMessageRef,

        /// The emoji.
        emoji: char,

        /// Whether the reaction was added or taken back.
        add: bool,
    },
}

impl DmPayload {
    /// The bytes to seal for this payload.
    ///
    /// # Panics
    ///
    /// Never in practice: these types always serialize.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("a DM payload always serializes")
    }

    /// Read a payload out of opened ciphertext.
    ///
    /// # Errors
    ///
    /// Fails if the bytes are not a payload this version understands — a peer
    /// speaking an older or newer dialect, rather than a decryption failure,
    /// which is worth telling apart when reporting it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).map_err(|e| anyhow!("Unrecognised direct message: {e}"))
    }
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
    fn overhead_matches_the_ciphertext_expansion() {
        let (alice_secret, _alice_public) = random_keypair();
        let (_bob_secret, bob_public) = random_keypair();
        let key = shared_key(&alice_secret, &bob_public);
        for len in [0usize, 1, 64, 65536] {
            let sealed = encrypt(&key, &vec![0u8; len]);
            assert_eq!(sealed.len(), len + super::OVERHEAD);
        }
    }

    #[test]
    fn a_payload_round_trips_through_the_envelope() {
        use super::{DmMessageRef, DmPayload};

        let (alice_secret, alice_public) = random_keypair();
        let (bob_secret, bob_public) = random_keypair();
        let to_bob = shared_key(&alice_secret, &bob_public);
        let to_alice = shared_key(&bob_secret, &alice_public);

        let text = DmPayload::Text {
            id: 7,
            text: "hello bob".to_string(),
        };
        let sealed = encrypt(&to_bob, &text.to_vec());
        // The words are not in the ciphertext, which is the whole point.
        assert!(!sealed.windows(9).any(|w| w == b"hello bob"));
        let opened = DmPayload::from_bytes(&decrypt(&to_alice, &sealed).unwrap()).unwrap();
        assert!(matches!(opened, DmPayload::Text { id: 7, text } if text == "hello bob"));

        let reaction = DmPayload::Reaction {
            target: DmMessageRef { id: 7, own: false },
            emoji: '★',
            add: true,
        };
        let sealed = encrypt(&to_bob, &reaction.to_vec());
        // Nor is the emoji: a relay sees a sealed payload either way and cannot
        // tell a reaction from something said, let alone which emoji it was.
        let star = '★'.to_string().into_bytes();
        assert!(!sealed.windows(star.len()).any(|w| w == star.as_slice()));
        let opened = DmPayload::from_bytes(&decrypt(&to_alice, &sealed).unwrap()).unwrap();
        assert!(matches!(
            opened,
            DmPayload::Reaction {
                target: DmMessageRef { id: 7, own: false },
                emoji: '★',
                add: true
            }
        ));
    }

    #[test]
    fn bytes_that_are_not_a_payload_are_told_apart_from_a_bad_key() {
        use super::DmPayload;

        // Decryption succeeding and the contents making no sense are different
        // failures, and the second one says so.
        assert!(DmPayload::from_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_hex() {
        let (_secret, public) = random_keypair();
        let printed = fingerprint(&public.to_bytes());
        assert_eq!(printed.len(), 96); // SHA-384 = 48 bytes = 96 hex chars
        assert_eq!(printed, fingerprint(&public.to_bytes()));
    }
}
