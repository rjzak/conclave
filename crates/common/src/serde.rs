// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::VerifyingKey;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize an ML-DSA 87 public key as a hex string
///
/// # Errors
///
/// Returns an error if serialization fails
#[inline]
pub fn serialize_mldsa_public_key<S>(
    k: &mldsa87::PublicKey,
    s: S,
) -> anyhow::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let key = hex::encode(k.as_bytes());
    s.serialize_str(&key)
}

/// Serialize an ML-DSA 87 private key as a hex string
///
/// # Errors
///
/// Returns an error if serialization fails
#[inline]
pub fn serialize_mldsa_private_key<S>(
    k: &mldsa87::SecretKey,
    s: S,
) -> anyhow::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let key = hex::encode(k.as_bytes());
    s.serialize_str(&key)
}

/// Deserialize an ML-DSA 87 public key from a hex string
///
/// # Errors
///
/// Returns an error if the key is empty or if decoding fails
#[inline]
pub fn deserialize_mldsa_public_key<'de, D>(
    deserializer: D,
) -> anyhow::Result<mldsa87::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let key = String::deserialize(deserializer)?;
    if key.is_empty() {
        return Err(Error::custom("Public key is empty!"));
    }

    let key = hex::decode(key).map_err(Error::custom)?;
    mldsa87::PublicKey::from_bytes(&key).map_err(Error::custom)
}

/// Deserialize an ML-DSA 87 private key from a hex string
///
/// # Errors
///
/// Returns an error if the key is empty or if decoding fails
#[inline]
pub fn deserialize_mldsa_private_key<'de, D>(
    deserializer: D,
) -> anyhow::Result<mldsa87::SecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let key = String::deserialize(deserializer)?;
    if key.is_empty() {
        return Err(Error::custom("Private key is empty!"));
    }

    let key = hex::decode(key).map_err(Error::custom)?;
    mldsa87::SecretKey::from_bytes(&key).map_err(Error::custom)
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
    let key = hex::encode(k.as_bytes());
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

    let key = hex::decode(key).map_err(Error::custom)?;
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
