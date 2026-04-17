// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use chrono::Duration;
use ed25519_dalek::VerifyingKey;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::SignedMessage;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Response to protocol handshake
pub const RESPONSE: &[u8] = b"Tracker";

/// One-minute expiration for a server's advertisement on a tracker.
pub const SERVER_EXPIRATION: std::time::Duration = std::time::Duration::from_mins(1);

/// Tracker advertisement
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Advertise {
    /// Name of the server
    pub name: String,

    /// Description of the server
    pub description: String,

    /// Version of Conclave running the server
    pub version: Version,

    /// Whether the server allows guest users
    pub anonymous: bool,

    /// Number of users currently connected to the server
    pub users_connected: u32,

    /// For how long the server has been running
    pub uptime: Duration,

    /// URL of the server as advertised using the unencrypted port so the client can get
    /// the server's public key and has a chance to verify it.
    pub url: String,

    /// Server's public key
    pub key: VerifyingKey,
}

impl Advertise {
    /// Serialize with Postcard.
    ///
    /// # Panics
    ///
    /// A panic should be impossible.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn to_vec(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("`Advertise` failed to serialize")
    }

    /// Deserialize with Postcard.
    ///
    /// # Errors
    ///
    /// Postcard error is the data isn't valid or complete.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    /// Serialize a list of servers with Postcard.
    ///
    /// # Panics
    ///
    /// A panic should be impossible.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn servers_to_vec(servers: &[Advertise]) -> Vec<u8> {
        postcard::to_stdvec(servers).expect("`Advertise` failed to serialize")
    }
}

impl Hash for Advertise {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Only some fields should be considered for hashing, so that small changes do trigger
        // a replacement in the tracker's hashmap
        self.name.hash(state);
        self.version.hash(state);
        self.url.hash(state);
        self.key.hash(state);
    }
}

/// Signed list of servers known to the tracker
#[derive(Clone, Deserialize, Serialize)]
pub struct SignedServerList {
    /// List of servers known to the tracker
    pub servers: Vec<Advertise>,

    /// Tracker version
    pub version: Version,

    /// Tracker's signature of the list
    pub signature: mldsa87::SignedMessage,
}

impl SignedServerList {
    /// Create a signed server list
    #[inline]
    #[must_use]
    pub fn new(
        servers: Vec<Advertise>,
        version: Version,
        private_key: &mldsa87::SecretKey,
    ) -> Self {
        let mut servers_bytes = Advertise::servers_to_vec(&servers);
        servers_bytes.extend(version.to_string().as_bytes());
        let signature = mldsa87::sign(&servers_bytes, private_key);

        Self {
            servers,
            version,
            signature,
        }
    }

    /// Get the raw signature bytes
    #[inline]
    #[must_use]
    pub fn signature_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }

    /// Verify the server list given the public key
    #[inline]
    #[must_use]
    pub fn verify(&self, public_key: &mldsa87::PublicKey) -> bool {
        let mut servers_bytes = Advertise::servers_to_vec(&self.servers);
        servers_bytes.extend(self.version.to_string().as_bytes());
        servers_bytes == mldsa87::open(&self.signature, public_key).unwrap_or_default()
    }
}

impl std::fmt::Debug for SignedServerList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedServerList")
            .field("servers", &self.servers)
            .field("version", &self.version)
            .field("signature", &self.signature.as_bytes())
            .finish()
    }
}

/// Tracker protocol messages
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Serialize)]
pub enum TrackerProtocol {
    /// When the client wants to get a list of servers
    GetServers,

    /// When the client wants to get a tracker's public key
    KeyRequest,

    /// When the server wishes to advertise itself
    AdvertiseServer(Advertise),

    /// List of servers response
    ServersList(SignedServerList),

    /// Tracker's public key
    TrackerKey(mldsa87::PublicKey),
}

impl std::fmt::Debug for TrackerProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use pqcrypto_traits::sign::PublicKey;

        match self {
            TrackerProtocol::GetServers => f.write_str("TrackerProtocol::GetServers"),
            TrackerProtocol::KeyRequest => f.write_str("TrackerProtocol::KeyRequest"),
            TrackerProtocol::AdvertiseServer(server) => f
                .debug_struct("TrackerProtocol::AdvertiseServer")
                .field("server", server)
                .finish(),
            TrackerProtocol::ServersList(list) => f
                .debug_struct("TrackerProtocol::ServersList")
                .field("list", list)
                .finish(),
            TrackerProtocol::TrackerKey(key) => f
                .debug_struct("TrackerProtocol::TrackerKey")
                .field("key", &hex::encode(key.as_bytes()))
                .finish(),
        }
    }
}

impl TrackerProtocol {
    /// Send the message to the server
    ///
    /// # Errors
    ///
    /// Networking errors are possible
    #[inline]
    pub async fn send(&self, stream: &mut TcpStream) -> anyhow::Result<()> {
        let bytes = postcard::to_stdvec(&self)?;
        stream.write_u32(u32::try_from(bytes.len())?).await?;
        stream.write_all(&bytes).await?;

        Ok(())
    }

    /// Receive a message from the server
    ///
    /// # Errors
    ///
    /// Networking errors are possible
    #[inline]
    pub async fn receive(stream: &mut TcpStream) -> anyhow::Result<Self> {
        let len = stream.read_u32().await?;
        let mut bytes = vec![0u8; len as usize];
        stream.read_exact(&mut bytes).await?;

        postcard::from_bytes(&bytes).map_err(|e| anyhow!("Failed to deserialize message: {e}"))
    }
}
