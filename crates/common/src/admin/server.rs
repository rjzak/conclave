// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Client to Server administrative messages
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ServerAdminMessagesEncrypted {
    /// Set the server's display name.
    SetServerName(String),

    /// Set the server's description.
    SetServerDescription(String),

    /// Set whether anonymous users are allowed.
    SetAllowAnonymous(bool),

    /// Request the list of user accounts.
    ListUsers,

    /// Create a user account.
    CreateUser(CreateUser),

    /// Delete a user account by user ID
    DeleteUser(u32),

    /// Request the list of configured trackers.
    ListTrackers,

    /// Add a tracker by host and port.
    AddTracker(Tracker),

    /// Remove a tracker by host and port.
    RemoveTracker(Tracker),
}

/// Create a user account
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateUser {
    /// Login name for the new account
    pub username: String,

    /// Initial password
    pub password: String,

    /// Group(s) for initial membership
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Tracker information
#[derive(Debug, Deserialize, Serialize)]
pub struct Tracker {
    /// Tracker host (domain or IP)
    pub host: String,

    /// Tracker port
    pub port: u16,
}
