// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Response to protocol handshake
pub const RESPONSE: &[u8] = b"Server";

/// Messages sent to the server from the client
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ServerMessages {
    /// Messages for establishing the encryption connection
    Unencrypted(ServerMessagesUnencrypted),

    /// Messages once the encryption connection is established
    Encrypted(ServerMessagesEncrypted),
}

/// Messages back to the client from the server
#[derive(Debug, Deserialize, Serialize)]
pub enum ClientMessages {
    /// Messages for establishing the encryption connection
    Unencrypted(ClientMessagesUnencrypted),

    /// Messages once the encryption connection is established
    Encrypted(ClientMessagesEncrypted),
}

/// Client to Server messages for unencrypted connections
#[derive(Debug, Deserialize, Serialize)]
pub enum ServerMessagesUnencrypted {
    /// Ask the server for its public key
    KeyRequest,

    /// Switch to encrypted connection
    SwitchToEncrypted,

    /// Drop the connection.
    Disconnect,
}

/// Server to Client messages for unencrypted connections

#[derive(Debug, Deserialize, Serialize)]
pub enum ClientMessagesUnencrypted {
    /// Server's response with the public key
    KeyResponse(VerifyingKey),

    /// Drop the connection.
    Disconnect,
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
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct UserAuthentication {
    /// User name
    pub username: String,

    /// Password
    pub password: String,
}

impl Debug for UserAuthentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserAuthentication({})", self.username)
    }
}

/// Information about a connected user
#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct ConnectedUser {
    /// Display name of the user which might be different from their username
    pub display_name: String,

    /// Whether the user is authenticated
    pub authenticated: bool,

    /// Whether the user is an administrator
    pub admin: bool,

    /// Time since the user connected
    pub connected_since: Duration,
}

/// Client to Server messages for encrypted connections
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ServerMessagesEncrypted {
    /// Ask the server for information about itself
    ServerInformationRequest,

    /// User tries to authenticate
    ServerAuthenticationRequest(UserAuthentication),

    /// Ask the server for a list of connected users
    ListConnectedUsersRequest,

    /// Do nothing message to keep the connection alive.
    KeepAlive,

    /// Drop the connection.
    Disconnect,
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

    /// Do nothing message to keep the connection alive.
    KeepAlive,

    /// Drop the connection.
    Disconnect,
}
