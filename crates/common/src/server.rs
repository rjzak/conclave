// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Duration, Local};
pub use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Response to protocol handshake
pub const RESPONSE: &[u8] = b"Server";

/// Protocol for getting the server's public key
pub mod unencrypted {
    use anyhow::{Result, anyhow};
    use ed25519_dalek::VerifyingKey;
    use semver::Version;
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Unencrypted messages to the server
    #[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
    pub enum ClientToServer {
        /// Request the server's public key
        KeyRequest,

        /// Request the server's version
        VersionRequest,

        /// Switch to encrypted connection
        GoCrypto,
    }

    impl ClientToServer {
        /// Send the message to the server
        ///
        /// # Errors
        ///
        /// Networking errors are possible
        #[inline]
        pub async fn send(&self, stream: &mut TcpStream) -> Result<()> {
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
        pub async fn receive(stream: &mut TcpStream) -> Result<Self> {
            let len = stream.read_u32().await?;
            let mut bytes = vec![0u8; len as usize];
            stream.read_exact(&mut bytes).await?;

            postcard::from_bytes(&bytes).map_err(|e| anyhow!("Failed to deserialize message: {e}"))
        }
    }

    /// Unencrypted messages from the server
    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
    pub enum ServerToClient {
        /// Server's public key
        PublicKey(VerifyingKey),

        /// Server's version
        Version(Version),
    }

    impl ServerToClient {
        /// Send the message to the client
        ///
        /// # Errors
        ///
        /// Networking errors are possible
        #[inline]
        pub async fn send(&self, stream: &mut TcpStream) -> Result<()> {
            let bytes = postcard::to_stdvec(&self)?;
            stream.write_u32(u32::try_from(bytes.len())?).await?;
            stream.write_all(&bytes).await?;

            Ok(())
        }

        /// Receive a message from the client
        ///
        /// # Errors
        ///
        /// Networking errors are possible
        #[inline]
        pub async fn receive(stream: &mut TcpStream) -> Result<Self> {
            let len = stream.read_u32().await?;
            let mut bytes = vec![0u8; len as usize];
            stream.read_exact(&mut bytes).await?;

            postcard::from_bytes(&bytes).map_err(|e| anyhow!("Failed to deserialize message: {e}"))
        }
    }
}

/// Server's information response, also used by the client to keep track
/// of servers
#[derive(Debug, Clone, Hash, Deserialize, Serialize)]
pub struct ServerInformation {
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

    /// URL of the server as advertised
    pub url: String,

    /// Public key
    pub key: VerifyingKey,
}

/// User authentication
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct UserAuthentication {
    /// User name
    pub username: String,

    /// Password
    pub password: String,
}

impl std::fmt::Debug for UserAuthentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserAuthentication({})", self.username)
    }
}

impl From<(String, String)> for UserAuthentication {
    fn from((username, password): (String, String)) -> Self {
        Self { username, password }
    }
}

impl From<(&str, &str)> for UserAuthentication {
    fn from((username, password): (&str, &str)) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

/// Information about a connected user
#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct ConnectedUser {
    /// Display name of the user which might be different from their username
    pub display_name: String,

    /// Whether the user is an administrator
    pub admin: bool,

    /// Time since the user connected
    pub connected_since: Duration,

    /// User's ID, if authenticated.
    pub user_id: Option<u32>,

    /// User-provided local time, used to display timezone offsets.
    pub timezone: Option<DateTime<Local>>,
}

/// Client to Server messages for encrypted connections
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ServerMessagesEncrypted {
    /// Ask the server for information about itself
    ServerInformationRequest,

    /// User tries to authenticate
    /// Send the display name and the optional authentication message
    /// Server responds with Server Information if successful
    ServerAuthenticationRequest((String, Option<DateTime<Local>>, Option<UserAuthentication>)),

    /// Ask the server for a list of connected users
    ListConnectedUsersRequest,

    /// Do nothing message to keep the connection alive.
    KeepAlive,

    /// Drop the connection.
    Disconnect,
}

impl ServerMessagesEncrypted {
    /// Serialize with Postcard.
    ///
    /// # Panics
    ///
    /// A panic should be impossible.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn to_vec(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("`ServerMessagesEncrypted` failed to serialize")
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
}

/// Server to Client messages for encrypted connections
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ClientMessagesEncrypted {
    /// Server's response with information about itself
    ServerInformationResponse(ServerInformation),

    /// Receive a list of connected users
    ListConnectedUsersResponse(Vec<ConnectedUser>),

    /// Server error response
    Error(ServerError),

    /// Do nothing message to keep the connection alive.
    KeepAlive,

    /// Drop the connection.
    Disconnect,
}

impl ClientMessagesEncrypted {
    /// Serialize with Postcard.
    ///
    /// # Panics
    ///
    /// A panic should be impossible.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn to_vec(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("`ClientMessagesEncrypted` failed to serialize")
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
}

/// Server error responses
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ServerError {
    /// Authentication was incorrect
    AuthenticationFailed,

    /// No authentication provided when this is required
    AuthenticationRequired,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::AuthenticationFailed => write!(f, "Authentication failed"),
            ServerError::AuthenticationRequired => write!(f, "Authentication required"),
        }
    }
}

impl std::error::Error for ServerError {}
