// SPDX-License-Identifier: Apache-2.0

use conclave_common::net::{DefaultEncryptedStream, EncryptedWrite};
use conclave_common::server::{
    ChatEvent, ChatroomInfo, ClientMessagesEncrypted, ConnectedUser, ServerInformation,
    ServerMessagesEncrypted, UserDetails,
};
use std::collections::HashMap;
use std::ops::Not;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration, Local};
use conclave_common::admin::server::{
    AdminUser, Chatroom, ClientAdminMessagesEncrypted, CreateUser, Group, GroupMembership,
    ServerAdminMessagesEncrypted,
};
use conclave_common::tracker::{Tracker, TrackerWithKey};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Maximum time to wait for a request to be written to the server. A stalled or
/// half-open socket would otherwise hold the connection's write lock forever.
const SEND_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);

/// A single rendered line in a chatroom conversation.
#[derive(Clone, Debug)]
pub enum ChatLine {
    /// A system notice, e.g. a user coming or going.
    System(String),

    /// A message posted by a user.
    Message {
        /// Local time the message was received.
        time: DateTime<Local>,
        /// Author's display name.
        display_name: String,
        /// Message text.
        message: String,
    },
}

/// Local view of a chatroom the user has joined. History is not preserved, so
/// this only accumulates while the room is open.
#[derive(Clone, Debug, Default)]
pub struct ChatRoom {
    /// Display names of the members currently present.
    pub users: Vec<String>,

    /// The conversation so far this session.
    pub lines: Vec<ChatLine>,
}

/// Connection information
#[allow(dead_code)]
#[derive(Clone)]
pub struct ConclaveConnection {
    /// Encrypted connection to a server
    pub(crate) connection:
        Arc<RwLock<EncryptedWrite<{ conclave_common::net::DEFAULT_REKEY_INTERVAL }>>>,

    /// Server information. A `std` lock (never held across an `.await`) so the
    /// GUI can read it synchronously without `block_on` on the render thread.
    pub(crate) server_info: Arc<std::sync::RwLock<ServerInformation>>,

    /// List of connected users. A `std` lock (never held across an `.await`) so
    /// the GUI can read it synchronously without `block_on` on the render thread.
    pub(crate) connected_users: Arc<std::sync::RwLock<Vec<ConnectedUser>>>,

    /// Most recently received per-user details (from a [`Self::request_user_details`]).
    pub(crate) user_details: Arc<std::sync::RwLock<Option<UserDetails>>>,

    /// Display name shown for the user on this server
    pub(crate) display_name: Arc<RwLock<String>>,

    /// Whether the authenticated user is an administrator (from `SessionInfo`).
    pub(crate) is_admin: Arc<AtomicBool>,

    /// Latest administrative user list (populated for admins on request).
    pub(crate) admin_users: Arc<std::sync::RwLock<Vec<AdminUser>>>,

    /// Latest administrative group list (populated for admins on request).
    pub(crate) admin_groups: Arc<std::sync::RwLock<Vec<Group>>>,

    /// Latest administrative tracker list (populated for admins on request).
    pub(crate) admin_trackers: Arc<std::sync::RwLock<Vec<TrackerWithKey>>>,

    /// Most recent administrative action error, if any.
    pub(crate) admin_error: Arc<std::sync::RwLock<Option<String>>>,

    /// Chatrooms this user may access (from the server).
    pub(crate) chatrooms_available: Arc<std::sync::RwLock<Vec<ChatroomInfo>>>,

    /// Latest administrative chatroom list (populated for admins on request).
    pub(crate) admin_chatrooms: Arc<std::sync::RwLock<Vec<Chatroom>>>,

    /// Local state of each joined chatroom, keyed by room id.
    pub(crate) chat_rooms: Arc<std::sync::RwLock<HashMap<u32, ChatRoom>>>,

    /// Join handle for the task which listens for messages from the server
    pub(crate) listen_handle: Arc<JoinHandle<()>>,

    /// When the connection was established
    pub(crate) connection_time: DateTime<Local>,
}

impl ConclaveConnection {
    /// Create a connection object
    #[allow(clippy::too_many_lines)]
    pub fn new(conn: DefaultEncryptedStream, info: ServerInformation, display_name: &str) -> Self {
        let (mut read, write) = conn.into_split();
        let server_info = Arc::new(std::sync::RwLock::new(info));
        let connected_users = Arc::new(std::sync::RwLock::new(Vec::new()));

        let mut conn = ConclaveConnection {
            connection: Arc::new(RwLock::new(write)),
            server_info: server_info.clone(),
            connected_users: connected_users.clone(),
            user_details: Arc::new(std::sync::RwLock::new(None)),
            display_name: Arc::new(RwLock::new(display_name.to_string())),
            is_admin: Arc::new(AtomicBool::new(false)),
            admin_users: Arc::new(std::sync::RwLock::new(Vec::new())),
            admin_groups: Arc::new(std::sync::RwLock::new(Vec::new())),
            admin_trackers: Arc::new(std::sync::RwLock::new(Vec::new())),
            admin_error: Arc::new(std::sync::RwLock::new(None)),
            chatrooms_available: Arc::new(std::sync::RwLock::new(Vec::new())),
            admin_chatrooms: Arc::new(std::sync::RwLock::new(Vec::new())),
            chat_rooms: Arc::new(std::sync::RwLock::new(HashMap::new())),
            listen_handle: Arc::new(tokio::spawn(tokio::time::sleep(
                tokio::time::Duration::from_millis(1),
            ))),
            connection_time: Local::now(),
        };

        let conn_clone = conn.clone();
        let reader = tokio::spawn(async move {
            loop {
                let data = match read.recv().await {
                    Ok(data) => data,
                    // A recv error (EOF on disconnect, network failure, or a
                    // desynced cipher) is unrecoverable. End the task instead of
                    // `continue`-ing: on a closed socket `recv()` returns `Err`
                    // immediately every iteration, which would busy-spin a worker
                    // and flood the logs. Ending it also makes `connected_since()`
                    // report the connection as gone.
                    Err(e) => {
                        tracing::info!("Connection closed: {e}");
                        break;
                    }
                };

                let protocol = match ClientMessagesEncrypted::from_bytes(&data) {
                    Ok(protocol) => protocol,
                    Err(e) => {
                        tracing::error!("Error decoding encrypted message: {e:?}");
                        continue;
                    }
                };
                tracing::trace!("Received encrypted message: {:?}", protocol);

                match protocol {
                    ClientMessagesEncrypted::KeepAlive => (),
                    ClientMessagesEncrypted::Disconnect => break,
                    ClientMessagesEncrypted::ServerInformationResponse(info) => {
                        conn_clone
                            .server_info
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone_from(&info);
                    }
                    ClientMessagesEncrypted::ListConnectedUsersResponse(users) => {
                        conn_clone
                            .connected_users
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone_from(&users);
                    }
                    ClientMessagesEncrypted::UserDetailsResponse(details) => {
                        *conn_clone
                            .user_details
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = details;
                    }
                    ClientMessagesEncrypted::ChatRoomsResponse(rooms) => {
                        *conn_clone
                            .chatrooms_available
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = rooms;
                    }
                    ClientMessagesEncrypted::ChatJoined { room, users } => {
                        let mut rooms = conn_clone
                            .chat_rooms
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        rooms.entry(room).or_default().users = users;
                    }
                    ClientMessagesEncrypted::ChatActivity(event) => {
                        conn_clone.apply_chat_event(event);
                    }
                    ClientMessagesEncrypted::SessionInfo { admin, .. } => {
                        conn_clone.is_admin.store(admin, Ordering::SeqCst);
                    }
                    ClientMessagesEncrypted::AdministrativeResponse(admin_msg) => match admin_msg {
                        ClientAdminMessagesEncrypted::UsersResponse(users) => {
                            *conn_clone
                                .admin_users
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = users;
                        }
                        ClientAdminMessagesEncrypted::GroupsResponse(groups) => {
                            *conn_clone
                                .admin_groups
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = groups;
                        }
                        ClientAdminMessagesEncrypted::TrackersResponse(trackers) => {
                            *conn_clone
                                .admin_trackers
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = trackers;
                        }
                        ClientAdminMessagesEncrypted::ChatroomsResponse(chatrooms) => {
                            *conn_clone
                                .admin_chatrooms
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = chatrooms;
                        }
                        ClientAdminMessagesEncrypted::ActionOk => {
                            *conn_clone
                                .admin_error
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                        }
                        x => {
                            tracing::warn!("Received unexpected admin message: {x:?}");
                        }
                    },
                    ClientMessagesEncrypted::Error(e) => {
                        *conn_clone
                            .admin_error
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(e.to_string());
                    }
                    x => tracing::warn!("Received unexpected encrypted message: {x:?}"),
                }
            }
        });

        conn.listen_handle = Arc::new(reader);
        conn
    }

    /// Send an encrypted request to the server, bounded by [`SEND_TIMEOUT`] so a
    /// dead or unresponsive socket surfaces as an error instead of wedging the
    /// connection's write lock.
    async fn send_request(&self, request: &[u8]) -> Result<()> {
        let mut guard = self.connection.write().await;
        tokio::time::timeout(SEND_TIMEOUT, guard.send(request))
            .await
            .map_err(|_| anyhow!("Timed out sending request to server"))?
    }

    /// Get a copy of the server information. Synchronous: callable directly from
    /// the GUI render thread without blocking on the async runtime. Kept current
    /// by the server pushing [`ClientMessagesEncrypted::ServerInformationResponse`]
    /// whenever it changes.
    #[must_use]
    pub fn server_info(&self) -> ServerInformation {
        self.server_info
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Get a copy of the connected users. Synchronous: callable directly from the
    /// GUI render thread without blocking on the async runtime.
    #[must_use]
    pub fn get_connected_users(&self) -> Vec<ConnectedUser> {
        self.connected_users
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The most recently received per-user details, if any. Populated in response
    /// to [`Self::request_user_details`].
    #[must_use]
    pub fn user_details(&self) -> Option<UserDetails> {
        self.user_details
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Request extra details about a connected user by connection id. The reply
    /// arrives asynchronously and is available from [`Self::user_details`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn request_user_details(&self, connection_id: u32) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::UserDetailsRequest(connection_id).to_vec())
            .await
    }

    // ── Chat ──────────────────────────────────────────────────────────────

    /// Apply a chat activity event to the local room state.
    fn apply_chat_event(&self, event: ChatEvent) {
        let mut rooms = self
            .chat_rooms
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match event {
            ChatEvent::Joined { room, display_name } => {
                let entry = rooms.entry(room).or_default();
                if !entry.users.contains(&display_name) {
                    entry.users.push(display_name.clone());
                }
                entry
                    .lines
                    .push(ChatLine::System(format!("{display_name} has joined")));
            }
            ChatEvent::Left { room, display_name } => {
                let entry = rooms.entry(room).or_default();
                entry.users.retain(|u| u != &display_name);
                entry
                    .lines
                    .push(ChatLine::System(format!("{display_name} has left")));
            }
            ChatEvent::Message {
                room,
                display_name,
                message,
                at,
            } => {
                rooms
                    .entry(room)
                    .or_default()
                    .lines
                    .push(ChatLine::Message {
                        time: at.with_timezone(&Local),
                        display_name,
                        message,
                    });
            }
        }
    }

    /// The chatrooms this user may access, as last reported by the server.
    #[must_use]
    pub fn chatrooms_available(&self) -> Vec<ChatroomInfo> {
        self.chatrooms_available
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// A snapshot of a joined chatroom's local state, if present.
    #[must_use]
    pub fn chat_room(&self, room: u32) -> Option<ChatRoom> {
        self.chat_rooms
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&room)
            .cloned()
    }

    /// The most recently received administrative chatroom list.
    #[must_use]
    pub fn admin_chatrooms(&self) -> Vec<Chatroom> {
        self.admin_chatrooms
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Request the list of chatrooms this user may access; the reply is available
    /// from [`Self::chatrooms_available`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn request_chatrooms(&self) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ChatRoomsRequest.to_vec())
            .await
    }

    /// Join a chatroom by id.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn chat_join(&self, room: u32) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ChatJoin(room).to_vec())
            .await
    }

    /// Leave a chatroom by id and clear its local (unsaved) state.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn chat_leave(&self, room: u32) -> Result<()> {
        self.chat_rooms
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&room);
        self.send_request(&ServerMessagesEncrypted::ChatLeave(room).to_vec())
            .await
    }

    /// Post a message to a chatroom.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn chat_send(&self, room: u32, message: String) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ChatSend { room, message }.to_vec())
            .await
    }

    /// Whether the authenticated user on this connection is an administrator.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.is_admin.load(Ordering::SeqCst)
    }

    /// The most recently received administrative user list.
    #[must_use]
    pub fn admin_users(&self) -> Vec<AdminUser> {
        self.admin_users
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The most recently received administrative group list.
    #[must_use]
    pub fn admin_groups(&self) -> Vec<Group> {
        self.admin_groups
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The most recently received administrative tracker list.
    #[must_use]
    pub fn admin_trackers(&self) -> Vec<TrackerWithKey> {
        self.admin_trackers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The most recent administrative action error, if any.
    #[must_use]
    pub fn admin_error(&self) -> Option<String> {
        self.admin_error
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// (Admin) Set the server's display name.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_set_server_name(&self, name: String) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetServerName(name),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Set the server's description.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_set_server_description(&self, description: String) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetServerDescription(description),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Request the list of user accounts; the reply arrives asynchronously
    /// and is available from [`Self::admin_users`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_list_users(&self) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::ListUsers,
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Request the list of groups a user may belong to; the reply
    /// arrives asynchronously and is available from [`Self::admin_groups`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_list_groups(&self) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::ListGroups,
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Add an existing user account to a group by id.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_add_user_to_group(&self, uid: u32, gid: u32) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::AddUserToGroup(GroupMembership { uid, gid }),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Remove an existing user account from a group by id.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_remove_user_from_group(&self, uid: u32, gid: u32) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::RemoveUserFromGroup(GroupMembership { uid, gid }),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Create a user account with initial group memberships.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_create_user(
        &self,
        username: String,
        password: String,
        groups: Vec<String>,
    ) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::CreateUser(CreateUser {
                    username,
                    password,
                    groups,
                }),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Delete a user account by login name.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_delete_user(&self, uid: u32) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::DeleteUser(uid),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Request the configured trackers; the reply arrives asynchronously
    /// and is available from [`Self::admin_trackers`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_list_trackers(&self) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::ListTrackers,
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Add a tracker by host and port.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_add_tracker(&self, host: String, port: u16) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::AddTracker(Tracker { host, port }),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Remove a tracker by host and port.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_remove_tracker(&self, host: String, port: u16) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::RemoveTracker(Tracker { host, port }),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Kick a connected user by connection id.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_kick_user(&self, connection_id: u32) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::KickUser(connection_id),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Enable or disable chat on the server.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_set_chat_enabled(&self, enabled: bool) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetChatEnabled(enabled),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Request the chatroom list; the reply is available from
    /// [`Self::admin_chatrooms`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_list_chatrooms(&self) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::ListChatrooms,
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Create a chatroom, restricted to the given group ids.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_create_chatroom(&self, name: String, groups: Vec<u32>) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::CreateChatroom { name, groups },
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Rename a chatroom and replace its group restrictions.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_edit_chatroom(&self, id: u32, name: String, groups: Vec<u32>) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::EditChatroom { id, name, groups },
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Delete a chatroom by id.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_delete_chatroom(&self, id: u32) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::DeleteChatroom(id),
            )
            .to_vec(),
        )
        .await
    }

    /// Send a keep-alive message to the server
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn send_keep_alive(&self) -> Result<()> {
        let request = ServerMessagesEncrypted::KeepAlive.to_vec();
        self.send_request(&request).await
    }

    /// When the connection was established, if still connected.
    #[inline]
    #[must_use]
    pub fn connected_since(&self) -> Option<&DateTime<Local>> {
        self.listen_handle
            .is_finished()
            .not()
            .then_some(&self.connection_time)
    }

    /// Connection duration, if still connected.
    #[inline]
    #[must_use]
    pub fn connection_duration(&self) -> Option<Duration> {
        self.listen_handle
            .is_finished()
            .not()
            .then_some(self.connection_time.signed_duration_since(Local::now()))
    }

    /// Send a disconnect message to the server and close the connection.
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn disconnect(&self) -> Result<()> {
        let request = ServerMessagesEncrypted::Disconnect.to_vec();
        let result = self.send_request(&request).await;
        self.listen_handle.abort();
        result
    }
}

impl std::fmt::Debug for ConclaveConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conclave Client Connection")
    }
}
