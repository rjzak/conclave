// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::{Deserialize, Serialize};

/// One-minute expiration for a server's advertisement on a tracker.
pub const SERVER_EXPIRATION: Duration = Duration::from_secs(60);

/// Tracker advertisement
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct Advertise {
    /// Name of the server
    pub name: String,

    /// Description of the server
    pub description: String,

    /// Version of Conclave running the server
    pub version: Version,

    /// Whether the server allows guest users
    pub anonymous: bool,

    /// URL of the server as advertised
    pub url: String,

    /// Server's public key
    pub key: VerifyingKey,
}

/// Tracker protocol messages
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
pub enum TrackerProtocol {
    /// When the client wants to get a list of servers
    GetServers,

    /// When the server wishes to advertise itself
    AdvertiseServer(Advertise),

    /// List of servers response
    ServersList(Vec<Advertise>),
}
