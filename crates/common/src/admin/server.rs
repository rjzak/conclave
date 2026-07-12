// SPDX-License-Identifier: Apache-2.0

use crate::files::{DirAcl, ShareInfo};
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

    /// Enable or disable threaded discussions (forums) on the server.
    SetForumsEnabled(bool),

    /// Request the list of forum topics and their group restrictions.
    ListForumTopics,

    /// Create a forum topic, optionally restricted to the given group ids.
    CreateForumTopic {
        /// Topic name (must be unique)
        name: String,
        /// Topic description
        description: String,
        /// Group ids the topic is restricted to; empty means open to everyone.
        groups: Vec<u32>,
    },

    /// Rename a forum topic, update its description, and replace its groups.
    EditForumTopic {
        /// Topic id
        id: u32,
        /// New topic name
        name: String,
        /// New topic description
        description: String,
        /// Group ids the topic is restricted to; empty means open to everyone.
        groups: Vec<u32>,
    },

    /// Delete a forum topic by id (removes its threads and posts).
    DeleteForumTopic(u32),

    /// Request the server-wide limits (max upload size, max connections).
    GetServerLimits,

    /// Set the maximum accepted upload size in bytes; `None` removes the cap.
    SetMaxUploadSize(Option<u64>),

    /// Set the maximum number of concurrent connections; `None` removes the limit.
    SetMaxConnections(Option<u16>),

    /// Request read-only information about the shared directory (path, disk use).
    GetShareInfo,

    /// Read the access-control list of a shared directory (empty path = root).
    GetFileAcl(String),

    /// Replace the access-control list of a shared directory.
    SetFileAcl {
        /// Directory path relative to the share root
        path: String,
        /// The new access-control list
        acl: DirAcl,
    },
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

    /// The forum topics and their group restrictions.
    ForumTopicsResponse(Vec<AdminForumTopic>),

    /// The server-wide limits (max upload size, max connections).
    ServerLimitsResponse(ServerLimits),

    /// Read-only information about the shared directory, or `None` if the server
    /// is not sharing files.
    ShareInfoResponse(Option<ShareInfo>),

    /// The access-control list of a shared directory.
    FileAclResponse {
        /// Directory path relative to the share root
        path: String,
        /// The directory's access-control list
        acl: DirAcl,
    },

    /// Acknowledges that an administrative action succeeded.
    ActionOk,
}

/// Server-wide limits an administrator can view and change.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct ServerLimits {
    /// Maximum accepted upload size in bytes, or `None` for uncapped.
    pub max_upload_size: Option<u64>,

    /// Maximum number of concurrent connections, or `None` for unlimited.
    pub max_connections: Option<u16>,
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

/// A forum topic as seen by an administrator, including its group restrictions.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminForumTopic {
    /// Database id of the topic
    pub id: u32,

    /// Topic name
    pub name: String,

    /// Topic description
    pub description: String,

    /// Group ids the topic is restricted to; empty means open to everyone.
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
