// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Response to protocol handshake
pub const RESPONSE: &[u8] = b"Server";

/// Server messages for unencrypted connections
#[derive(Debug, Deserialize, Serialize)]
pub enum ServerProtocolUnencrypted {
    /// Ask the server for its public key
    KeyRequest,

    /// Server's response with the public key
    KeyResponse(VerifyingKey),
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
#[derive(Debug, Hash, Deserialize, Serialize)]
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

/// Server messages for encrypted connections
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
pub enum ServerProtocolEncrypted {
    /// Ask the server for information about itself
    ServerInformationRequest,

    /// Server's response with information about itself
    ServerInformationResponse(ServerInformation),

    /// User tries to authenticate
    ServerAuthenticationRequest(UserAuthentication),

    /// Ask the server for a list of connected users
    ListConnectedUsersRequest,

    /// Receive a list of connected users
    ListConnectedUsersResponse(Vec<ConnectedUser>),
}
