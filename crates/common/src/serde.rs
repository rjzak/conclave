// SPDX-License-Identifier: Apache-2.0

use crate::pqc::{
    EncodedMlDsaPublicKey, KeyExport, ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SEED_BYTES,
    ML_DSA_SIGNATURE_BYTES, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSeed, MlDsaSignature,
};

use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize an ML-DSA 87 public key as a base64 string
///
/// # Errors
///
/// Returns an error if serialization fails
#[inline]
pub fn serialize_mldsa_public_key<S>(k: &MlDsaPublicKey, s: S) -> anyhow::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let key = base64::engine::general_purpose::STANDARD.encode(k.encode());
    s.serialize_str(&key)
}

/// Serialize an ML-DSA 87 private key as a base64 string
///
/// The key is stored as the 32-byte seed it is derived from, the serialization recommended by
/// FIPS 204.
///
/// # Errors
///
/// Returns an error if serialization fails
#[inline]
pub fn serialize_mldsa_private_key<S>(k: &MlDsaPrivateKey, s: S) -> anyhow::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let key = base64::engine::general_purpose::STANDARD.encode(k.to_bytes());
    s.serialize_str(&key)
}

/// Deserialize an ML-DSA 87 public key from a base64 string
///
/// # Errors
///
/// Returns an error if the key is empty, if decoding fails, or if it isn't the right length
#[inline]
pub fn deserialize_mldsa_public_key<'de, D>(
    deserializer: D,
) -> anyhow::Result<MlDsaPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let key = String::deserialize(deserializer)?;
    if key.is_empty() {
        return Err(Error::custom("Public key is empty!"));
    }

    let key = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(Error::custom)?;

    decode_mldsa_public_key(&key).map_err(Error::custom)
}

/// Deserialize an ML-DSA 87 private key from a base64 string
///
/// # Errors
///
/// Returns an error if the key is empty, if decoding fails, or if it isn't a 32-byte seed
#[inline]
pub fn deserialize_mldsa_private_key<'de, D>(
    deserializer: D,
) -> anyhow::Result<MlDsaPrivateKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let key = String::deserialize(deserializer)?;
    if key.is_empty() {
        return Err(Error::custom("Private key is empty!"));
    }

    let key = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(Error::custom)?;

    let seed = MlDsaSeed::try_from(key.as_slice()).map_err(|_| {
        Error::custom(format!(
            "Private key was {} bytes long instead of the expected {ML_DSA_SEED_BYTES} bytes!",
            key.len()
        ))
    })?;

    Ok(MlDsaPrivateKey::from_seed(&seed))
}

/// Serialize an ML-DSA 87 public key as raw bytes, for use on the wire rather than in a config
/// file.
///
/// # Errors
///
/// Returns an error if serialization fails
#[inline]
pub fn serialize_mldsa_public_key_bytes<S>(
    k: &MlDsaPublicKey,
    s: S,
) -> anyhow::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(&k.encode())
}

/// Deserialize an ML-DSA 87 public key from raw bytes
///
/// # Errors
///
/// Returns an error if the bytes aren't a well-formed public key
#[inline]
pub fn deserialize_mldsa_public_key_bytes<'de, D>(
    deserializer: D,
) -> anyhow::Result<MlDsaPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let bytes = deserialize_bytes(deserializer)?;
    decode_mldsa_public_key(&bytes).map_err(Error::custom)
}

/// Serialize an ML-DSA 87 signature as raw bytes
///
/// # Errors
///
/// Returns an error if serialization fails
#[inline]
pub fn serialize_mldsa_signature<S>(
    signature: &MlDsaSignature,
    s: S,
) -> anyhow::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(&signature.encode())
}

/// Deserialize an ML-DSA 87 signature from raw bytes
///
/// # Errors
///
/// Returns an error if the bytes aren't a well-formed signature
#[inline]
pub fn deserialize_mldsa_signature<'de, D>(
    deserializer: D,
) -> anyhow::Result<MlDsaSignature, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let bytes = deserialize_bytes(deserializer)?;
    if bytes.len() != ML_DSA_SIGNATURE_BYTES {
        return Err(Error::custom(format!(
            "Signature was {} bytes long instead of the expected {ML_DSA_SIGNATURE_BYTES} bytes!",
            bytes.len()
        )));
    }

    MlDsaSignature::try_from(bytes.as_slice()).map_err(|_| Error::custom("Signature is malformed!"))
}

/// Decode an ML-DSA 87 public key from its encoded form, reporting a length mismatch as an
/// `anyhow` error so both the base64 and the raw-bytes deserializers can share the message.
fn decode_mldsa_public_key(bytes: &[u8]) -> anyhow::Result<MlDsaPublicKey> {
    let encoded = EncodedMlDsaPublicKey::try_from(bytes).map_err(|_| {
        anyhow::anyhow!(
            "Public key was {} bytes long instead of the expected {ML_DSA_PUBLIC_KEY_BYTES} bytes!",
            bytes.len()
        )
    })?;

    Ok(MlDsaPublicKey::decode(&encoded))
}

/// Read a byte string, accepting whichever of the byte or sequence representations the format
/// happens to use.
fn deserialize_bytes<'de, D>(deserializer: D) -> anyhow::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BytesVisitor;

    impl<'de> serde::de::Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> anyhow::Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> anyhow::Result<Vec<u8>, E> {
            Ok(v)
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> anyhow::Result<Vec<u8>, A::Error> {
            // The hint comes off the wire, so it only preallocates up to the largest byte string
            // this module reads: an ML-DSA 87 signature.
            let hint = seq.size_hint().unwrap_or_default();
            let mut bytes = Vec::with_capacity(hint.min(ML_DSA_SIGNATURE_BYTES));
            while let Some(byte) = seq.next_element()? {
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_bytes(BytesVisitor)
}

/// Serialize an ed25519 public key as a hex string
///
/// # Errors
///
/// Returns an error if serialization fails
#[inline]
pub fn serialize_dalek_public_key<S>(k: &VerifyingKey, s: S) -> anyhow::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let key = base64::engine::general_purpose::STANDARD.encode(k.as_bytes());
    s.serialize_str(&key)
}

/// Deserialize an ed25519 public key from a hex string
///
/// # Errors
///
/// Returns an error if the key is empty or if decoding fails
#[inline]
pub fn deserialize_dalek_public_key<'de, D>(
    deserializer: D,
) -> anyhow::Result<VerifyingKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let key = String::deserialize(deserializer)?;
    if key.is_empty() {
        return Err(Error::custom("Public key is empty!"));
    }

    let key = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(Error::custom)?;
    if key.len() != 32 {
        return Err(Error::custom(format!(
            "Public key was {} bytes long instead of the expected 32 bytes!",
            key.len()
        )));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key);
    VerifyingKey::from_bytes(&key_array).map_err(Error::custom)
}

/// Serialize an ed25519 private key as a hex string
///
/// # Errors
///
/// Returns an error if serialization fails
#[inline]
pub fn serialize_dalek_private_key<S>(k: &SigningKey, s: S) -> anyhow::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let key = base64::engine::general_purpose::STANDARD.encode(k.as_bytes());
    s.serialize_str(&key)
}

/// Deserialize an ed25519 private key from a hex string
///
/// # Errors
///
/// Returns an error if the key is empty or if decoding fails
#[inline]
pub fn deserialize_dalek_private_key<'de, D>(
    deserializer: D,
) -> anyhow::Result<SigningKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let key = String::deserialize(deserializer)?;
    if key.is_empty() {
        return Err(Error::custom("Public key is empty!"));
    }

    let key = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(Error::custom)?;
    if key.len() != 32 {
        return Err(Error::custom(format!(
            "Public key was {} bytes long instead of the expected 32 bytes!",
            key.len()
        )));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key);
    Ok(SigningKey::from_bytes(&key_array))
}
