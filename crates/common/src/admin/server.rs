// SPDX-License-Identifier: Apache-2.0

use crate::tracker::{Tracker, TrackerWithKey};

use chrono::{DateTime, Utc};
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

    /// Request the list of groups.
    ListGroups,

    /// Create a user account.
    CreateUser(CreateUser),

    /// Delete a user account by user ID
    DeleteUser(u32),

    /// Add an existing user to a group.
    AddUserToGroup(GroupMembership),

    /// Remove an existing user from a group.
    RemoveUserFromGroup(GroupMembership),

    /// Request the list of configured trackers.
    ListTrackers,

    /// Add a tracker by host and port.
    AddTracker(Tracker),

    /// Remove a tracker by host and port.
    RemoveTracker(Tracker),

    /// Kick a connected user by connection id.
    KickUser(u32),
}

/// Server to Client administrative messages
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ClientAdminMessagesEncrypted {
    /// The list of user accounts.
    UsersResponse(Vec<AdminUser>),

    /// The list of groups a user may belong to.
    GroupsResponse(Vec<Group>),

    /// The configured trackers as `(host, port)` pairs.
    TrackersResponse(Vec<TrackerWithKey>),

    /// Acknowledges that an administrative action succeeded.
    ActionOk,
}

/// A user account as seen by an administrator.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminUser {
    /// Database id of the account
    pub id: u32,

    /// Login name
    pub username: String,

    /// Whether the account belongs to the administrators group
    pub admin: bool,

    /// Whether the account is enabled (a disabled account has no password set)
    pub enabled: bool,

    /// Whether the account is read-only (cannot make changes: upload, post, delete, etc. despite permissions)
    pub readonly: bool,

    /// Account creation date
    pub created: DateTime<Utc>,

    /// Groups for which the account has membership
    pub groups: Vec<String>,
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

/// A group that user accounts may belong to.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Group {
    /// Database id of the group
    pub id: u32,

    /// Group name (unique)
    pub name: String,

    /// Optional human-readable description
    pub description: Option<String>,
}

/// A user account's membership in a group, both identified by id.
#[derive(Debug, Deserialize, Serialize)]
pub struct GroupMembership {
    /// Id of the user account
    pub uid: u32,

    /// Id of the group
    pub gid: u32,
}
