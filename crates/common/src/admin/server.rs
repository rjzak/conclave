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

    /// Create a group, optionally with a description and colour.
    CreateGroup(CreateGroup),

    /// Rename a group and set its description and colour.
    EditGroup(Group),

    /// Delete a group by id.
    DeleteGroup(u32),

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
    KickUser(u16),

    /// Enable or disable chat on the server.
    SetChatEnabled(bool),

    /// Request the list of chatrooms and their group restrictions.
    ListChatrooms,

    /// Create a chatroom, optionally restricted to the given group ids.
    CreateChatroom {
        /// Chatroom name (must be unique)
        name: String,
        /// Group ids the room is restricted to; empty means open to everyone.
        groups: Vec<u32>,
    },

    /// Rename a chatroom and replace its group restrictions.
    EditChatroom {
        /// Chatroom id
        id: u16,
        /// New chatroom name
        name: String,
        /// Group ids the room is restricted to; empty means open to everyone.
        groups: Vec<u32>,
    },

    /// Delete a chatroom by id.
    DeleteChatroom(u16),
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

    /// The chatrooms and their group restrictions.
    ChatroomsResponse(Vec<Chatroom>),

    /// Acknowledges that an administrative action succeeded.
    ActionOk,
}

/// A chatroom as seen by an administrator, including its group restrictions.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Chatroom {
    /// Database id of the chatroom
    pub id: u16,

    /// Chatroom name
    pub name: String,

    /// Group ids the room is restricted to; empty means open to everyone.
    pub groups: Vec<u32>,
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

    /// Optional RGB colour; members' names are tinted a mix of their groups'
    /// colours. Red is reserved for the admin group.
    pub color: Option<[u8; 3]>,
}

/// Group creation request.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateGroup {
    /// Group name (must be unique)
    pub name: String,

    /// Optional human-readable description
    pub description: Option<String>,

    /// Optional RGB colour; red is reserved for the admin group.
    pub color: Option<[u8; 3]>,
}

/// Whether an RGB colour is "red-like" and therefore reserved for the admin
/// group: a strong red channel with weak green and blue.
#[must_use]
pub fn is_reserved_red([r, g, b]: [u8; 3]) -> bool {
    r >= 150 && g <= 70 && b <= 70
}

/// A user account's membership in a group, both identified by id.
#[derive(Debug, Deserialize, Serialize)]
pub struct GroupMembership {
    /// Id of the user account
    pub uid: u32,

    /// Id of the group
    pub gid: u32,
}
