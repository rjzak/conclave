// SPDX-License-Identifier: Apache-2.0

use semver::Version;
use serde::{Deserialize, Serialize};

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
}

/// Tracker protocol messages
#[derive(Debug, Deserialize, Serialize)]
pub enum TrackerProtocol {
    /// When the client wants to get a list of servers
    GetServers,

    /// When the server wishes to advertise itself
    AdvertiseServer(Advertise),

    /// List of servers response
    ServersList(Vec<Advertise>),
}
