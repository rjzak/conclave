// SPDX-License-Identifier: Apache-2.0

use ml_kem::array::typenum::Unsigned;

pub use ml_dsa::{Generate, KeyExport, KeyInit, Keypair, Signer, Verifier};
pub use ml_kem::{Decapsulate, Encapsulate, Kem, TryKeyInit};

/// ML-DSA parameter set (FIPS 204, security category 5) used for tracker signing keys.
pub type MlDsa = ml_dsa::MlDsa87;

/// ML-DSA-87 public key, used to verify tracker signatures.
pub type MlDsaPublicKey = ml_dsa::VerifyingKey<MlDsa>;

/// ML-DSA-87 private key, used by a tracker to sign its server listing.
///
/// This is held as the 32-byte seed the expanded key is derived from, which is the serialization
/// FIPS 204 recommends.
pub type MlDsaPrivateKey = ml_dsa::SigningKey<MlDsa>;

/// Detached ML-DSA-87 signature.
pub type MlDsaSignature = ml_dsa::Signature<MlDsa>;

/// Byte encoding of an [`MlDsaPublicKey`].
pub type EncodedMlDsaPublicKey = ml_dsa::EncodedVerifyingKey<MlDsa>;

/// Byte encoding of an [`MlDsaSignature`].
pub type EncodedMlDsaSignature = ml_dsa::EncodedSignature<MlDsa>;

/// The 32-byte seed an [`MlDsaPrivateKey`] is derived from.
pub type MlDsaSeed = ml_dsa::Seed;

/// Length in bytes of an encoded ML-DSA-87 public key.
pub const ML_DSA_PUBLIC_KEY_BYTES: usize = <MlDsaPublicKey as ml_dsa::KeySizeUser>::KeySize::USIZE;

/// Length in bytes of an ML-DSA-87 private key seed.
pub const ML_DSA_SEED_BYTES: usize = <MlDsaPrivateKey as ml_dsa::KeySizeUser>::KeySize::USIZE;

/// Length in bytes of an encoded ML-DSA-87 signature.
///
/// `ml-dsa` doesn't export the trait that names the signature size, but the encoded form is a
/// `repr(transparent)` wrapper around a byte array, so its size is the length. The `parameter_sizes`
/// test pins the result.
pub const ML_DSA_SIGNATURE_BYTES: usize = size_of::<EncodedMlDsaSignature>();

/// ML-KEM parameter set (FIPS 203, security category 5) used for the transport handshake.
pub type MlKem = ml_kem::MlKem1024;

/// ML-KEM-1024 encapsulation (public) key.
pub type MlKemPublicKey = ml_kem::EncapsulationKey<MlKem>;

/// ML-KEM-1024 decapsulation (private) key.
pub type MlKemPrivateKey = ml_kem::DecapsulationKey<MlKem>;

/// ML-KEM-1024 ciphertext: the encapsulated form of a shared secret.
pub type MlKemCiphertext = ml_kem::Ciphertext<MlKem>;

/// Length in bytes of an encoded ML-KEM-1024 public key.
pub const ML_KEM_PUBLIC_KEY_BYTES: usize = <MlKemPublicKey as ml_kem::KeySizeUser>::KeySize::USIZE;

/// Length in bytes of an ML-KEM-1024 ciphertext.
pub const ML_KEM_CIPHERTEXT_BYTES: usize = <MlKem as Kem>::CiphertextSize::USIZE;

#[cfg(test)]
mod tests {
    use super::*;

    /// The handshake and the tracker protocol both hard-code these lengths on the wire, so they
    /// have to match what FIPS 203/204 specify.
    #[test]
    fn parameter_sizes() {
        assert_eq!(ML_DSA_PUBLIC_KEY_BYTES, 2592);
        assert_eq!(ML_DSA_SEED_BYTES, 32);
        assert_eq!(ML_DSA_SIGNATURE_BYTES, 4627);
        assert_eq!(ML_KEM_PUBLIC_KEY_BYTES, 1568);
        assert_eq!(ML_KEM_CIPHERTEXT_BYTES, 1568);
    }

    /// A freshly generated key pair round-trips through its byte encodings and verifies.
    #[test]
    fn mldsa_round_trip() {
        let private_key = MlDsaPrivateKey::generate();
        let public_key = private_key.verifying_key();

        let seed = private_key.to_seed();
        let reloaded = MlDsaPrivateKey::from_seed(&seed);
        assert_eq!(reloaded.verifying_key(), public_key);

        let message = b"conclave";
        let signature = reloaded.sign(message);

        let encoded = signature.encode();
        assert_eq!(encoded.len(), ML_DSA_SIGNATURE_BYTES);
        let decoded = MlDsaSignature::try_from(encoded.as_ref()).unwrap();

        let encoded: &[u8] = &public_key.encode();
        let public_key = MlDsaPublicKey::decode(&EncodedMlDsaPublicKey::try_from(encoded).unwrap());
        assert!(public_key.verify(message, &decoded).is_ok());
        assert!(public_key.verify(b"not conclave", &decoded).is_err());
    }

    /// Encapsulation and decapsulation agree on the shared secret, including across the byte
    /// encoding of the public key and ciphertext that the handshake sends over the wire.
    #[test]
    fn mlkem_round_trip() {
        let (private_key, public_key) = MlKem::generate_keypair();

        let encoded = public_key.to_bytes();
        assert_eq!(encoded.len(), ML_KEM_PUBLIC_KEY_BYTES);
        let public_key = MlKemPublicKey::new(&encoded).unwrap();

        let (ciphertext, sent) = public_key.encapsulate();
        assert_eq!(ciphertext.len(), ML_KEM_CIPHERTEXT_BYTES);

        let mut buffer = [0u8; ML_KEM_CIPHERTEXT_BYTES];
        buffer.copy_from_slice(ciphertext.as_ref());
        let received = private_key.decapsulate(&MlKemCiphertext::from(buffer));
        assert_eq!(sent, received);
    }
}
