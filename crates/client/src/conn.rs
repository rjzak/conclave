// SPDX-License-Identifier: Apache-2.0

use conclave_common::dm;
use conclave_common::files::{DirAcl, FileEntry, ShareInfo};
use conclave_common::forum::{
    ForumPost, ForumSignature, ForumThreadInfo, ForumTopic, NewForumPost, NewForumThread,
};
use conclave_common::net::{DefaultEncryptedStream, EncryptedWrite, SigningKey, VerifyingKey};
use conclave_common::server::{
    ChatEvent, ChatroomInfo, ClientMessagesEncrypted, ConnectedUser, ServerInformation,
    ServerMessagesEncrypted, UserDetails,
};
use std::collections::HashMap;
use std::ops::Not;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

/// Source of process-unique ids so two connections (even to the same server)
/// can be told apart in the GUI.
static NEXT_LOCAL_ID: AtomicU16 = AtomicU16::new(0);

/// A shared-directory listing: the directory path and its entries.
type FileListing = (String, Vec<FileEntry>);

/// A directory path paired with its access-control list.
type NamedAcl = (String, DirAcl);

use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration, Local};
use conclave_common::admin::server::{
    AdminForumTopic, AdminUser, Chatroom, ClientAdminMessagesEncrypted, CreateGroup, CreateUser,
    Group, GroupMembership, ServerAdminMessagesEncrypted, ServerLimits,
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

/// A single direct message in a conversation with another user. History is not
/// preserved, so a thread only accumulates while the connection is open.
#[derive(Clone, Debug)]
pub struct DmMessage {
    /// Local time the message was sent or received.
    pub time: DateTime<Local>,

    /// Whether this side sent the message (`true`) or received it (`false`).
    pub from_me: bool,

    /// Whether the message travelled end-to-end encrypted.
    pub encrypted: bool,

    /// Message text (or a placeholder if it could not be decrypted).
    pub text: String,
}

/// A file download in progress or completed, accumulated from streamed chunks.
#[derive(Clone, Debug)]
pub struct Download {
    /// Path (relative to the share root) being downloaded.
    pub path: String,

    /// Total size in bytes reported by the server.
    pub size: u64,

    /// Bytes received so far.
    pub data: Vec<u8>,

    /// Whether all chunks have arrived.
    pub done: bool,
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
    pub(crate) chat_rooms: Arc<std::sync::RwLock<HashMap<u16, ChatRoom>>>,

    /// Forum topics this user may access (from the server).
    pub(crate) forum_topics: Arc<std::sync::RwLock<Vec<ForumTopic>>>,

    /// Latest administrative forum-topic list (populated for admins on request).
    pub(crate) admin_forum_topics: Arc<std::sync::RwLock<Vec<AdminForumTopic>>>,

    /// Threads within each topic, keyed by topic id.
    pub(crate) forum_threads: Arc<std::sync::RwLock<HashMap<u32, Vec<ForumThreadInfo>>>>,

    /// Posts within each open thread, keyed by thread id.
    pub(crate) forum_posts: Arc<std::sync::RwLock<HashMap<u32, Vec<ForumPost>>>>,

    /// Most recent shared-directory listing: `(path, entries)`.
    pub(crate) file_listing: Arc<std::sync::RwLock<Option<FileListing>>>,

    /// The current/last file download.
    pub(crate) download: Arc<std::sync::RwLock<Option<Download>>>,

    /// Most recent shared-directory ACL fetched for administration.
    pub(crate) file_acl: Arc<std::sync::RwLock<Option<NamedAcl>>>,

    /// Read-only shared-directory info (path, disk use) for administrators.
    pub(crate) admin_share_info: Arc<std::sync::RwLock<Option<ShareInfo>>>,

    /// Server-wide limits (max upload size, max connections) for administrators.
    pub(crate) admin_limits: Arc<std::sync::RwLock<Option<ServerLimits>>>,

    /// Latest file-operation notice (e.g. upload status) for the Files window.
    pub(crate) file_notice: Arc<std::sync::RwLock<Option<String>>>,

    /// Direct-message conversations, keyed by the peer's connection id.
    pub(crate) dms: Arc<std::sync::RwLock<HashMap<u16, Vec<DmMessage>>>>,

    /// Peers whose newly-arrived direct message should surface a window if one
    /// is not already open; drained by the GUI each frame.
    pub(crate) dm_open_requests: Arc<std::sync::RwLock<Vec<u16>>>,

    /// This client's ed25519 identity key, used to derive the shared key for
    /// end-to-end encrypted direct messages.
    pub(crate) signing_key: Arc<SigningKey>,

    /// Join handle for the task which listens for messages from the server
    pub(crate) listen_handle: Arc<JoinHandle<()>>,

    /// When the connection was established
    pub(crate) connection_time: DateTime<Local>,

    /// This viewer's own shared timezone (whole hours relative to GMT sent at
    /// connect), so the GUI can show other users' offsets relative to us.
    /// `None` if not shared.
    pub(crate) own_timezone: Option<i16>,

    /// Process-unique id for this connection, distinguishing it from other
    /// connections (including a second connection to the same server).
    pub(crate) local_id: u16,
}

impl ConclaveConnection {
    /// Create a connection object
    #[allow(clippy::too_many_lines)]
    pub fn new(
        conn: DefaultEncryptedStream,
        info: ServerInformation,
        display_name: &str,
        signing_key: SigningKey,
        own_timezone: Option<i16>,
    ) -> Self {
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
            forum_topics: Arc::new(std::sync::RwLock::new(Vec::new())),
            admin_forum_topics: Arc::new(std::sync::RwLock::new(Vec::new())),
            forum_threads: Arc::new(std::sync::RwLock::new(HashMap::new())),
            forum_posts: Arc::new(std::sync::RwLock::new(HashMap::new())),
            file_listing: Arc::new(std::sync::RwLock::new(None)),
            download: Arc::new(std::sync::RwLock::new(None)),
            file_acl: Arc::new(std::sync::RwLock::new(None)),
            admin_share_info: Arc::new(std::sync::RwLock::new(None)),
            admin_limits: Arc::new(std::sync::RwLock::new(None)),
            file_notice: Arc::new(std::sync::RwLock::new(None)),
            dms: Arc::new(std::sync::RwLock::new(HashMap::new())),
            dm_open_requests: Arc::new(std::sync::RwLock::new(Vec::new())),
            signing_key: Arc::new(signing_key),
            listen_handle: Arc::new(tokio::spawn(tokio::time::sleep(
                tokio::time::Duration::from_millis(1),
            ))),
            connection_time: Local::now(),
            own_timezone,
            local_id: NEXT_LOCAL_ID.fetch_add(1, Ordering::Relaxed),
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
                    ClientMessagesEncrypted::ForumTopicsResponse(topics) => {
                        *conn_clone
                            .forum_topics
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = topics;
                    }
                    ClientMessagesEncrypted::ForumThreadsResponse { topic, threads } => {
                        conn_clone
                            .forum_threads
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(topic, threads);
                    }
                    ClientMessagesEncrypted::ForumThreadResponse { thread, posts } => {
                        conn_clone
                            .forum_posts
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(thread, posts);
                    }
                    ClientMessagesEncrypted::ForumThreadEvent { topic, thread } => {
                        let mut map = conn_clone
                            .forum_threads
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let list = map.entry(topic).or_default();
                        // Replace any existing entry, then float to the top as the
                        // most recently active thread.
                        list.retain(|t| t.id != thread.id);
                        list.insert(0, thread);
                    }
                    ClientMessagesEncrypted::ForumPostEvent { post } => {
                        let mut map = conn_clone
                            .forum_posts
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(list) = map.get_mut(&post.thread)
                            && !list.iter().any(|p| p.id == post.id)
                        {
                            // The server echoes to the sender too, so guard dupes.
                            list.push(post);
                        }
                    }
                    ClientMessagesEncrypted::ForumPostDeleted { thread, post } => {
                        let mut map = conn_clone
                            .forum_posts
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(list) = map.get_mut(&thread) {
                            // Promote replies to the deleted post's parent, matching
                            // the server, so the tree stays connected.
                            let parent =
                                list.iter().find(|p| p.id == post).and_then(|p| p.reply_to);
                            for p in list.iter_mut() {
                                if p.reply_to == Some(post) {
                                    p.reply_to = parent;
                                }
                            }
                            list.retain(|p| p.id != post);
                        }
                    }
                    ClientMessagesEncrypted::FileListResponse { path, entries } => {
                        *conn_clone
                            .file_listing
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some((path, entries));
                    }
                    ClientMessagesEncrypted::FileDownloadBegin { path, size } => {
                        *conn_clone
                            .download
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Download {
                            path,
                            size,
                            data: Vec::new(),
                            done: false,
                        });
                    }
                    ClientMessagesEncrypted::FileDownloadChunk { data } => {
                        if let Some(download) = conn_clone
                            .download
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .as_mut()
                        {
                            download.data.extend_from_slice(&data);
                        }
                    }
                    ClientMessagesEncrypted::FileDownloadEnd => {
                        if let Some(download) = conn_clone
                            .download
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .as_mut()
                        {
                            download.done = true;
                        }
                    }
                    ClientMessagesEncrypted::FileUploadReady => {
                        *conn_clone
                            .file_notice
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some("Uploading…".to_string());
                    }
                    ClientMessagesEncrypted::FileUploadComplete => {
                        *conn_clone
                            .file_notice
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some("Upload complete.".to_string());
                    }
                    ClientMessagesEncrypted::DirectMessageReceived {
                        from,
                        from_display_name: _,
                        encrypted,
                        payload,
                    } => {
                        conn_clone.apply_direct_message(from, encrypted, &payload);
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
                        ClientAdminMessagesEncrypted::ForumTopicsResponse(topics) => {
                            *conn_clone
                                .admin_forum_topics
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = topics;
                        }
                        ClientAdminMessagesEncrypted::FileAclResponse { path, acl } => {
                            *conn_clone
                                .file_acl
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some((path, acl));
                        }
                        ClientAdminMessagesEncrypted::ShareInfoResponse(info) => {
                            *conn_clone
                                .admin_share_info
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = info;
                        }
                        ClientAdminMessagesEncrypted::ServerLimitsResponse(limits) => {
                            *conn_clone
                                .admin_limits
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(limits);
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

    /// A process-unique id for this connection, so two connections (even to the
    /// same server) can be distinguished when keying GUI windows.
    #[must_use]
    pub const fn local_id(&self) -> u16 {
        self.local_id
    }

    /// This viewer's own shared timezone (whole hours east of GMT), if shared.
    #[must_use]
    pub const fn own_timezone(&self) -> Option<i16> {
        self.own_timezone
    }

    /// The display name this connection logged in with. Synchronous: the name is
    /// set once at connect and never changes, so a non-blocking read suffices.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.display_name
            .try_read()
            .map(|name| name.clone())
            .unwrap_or_default()
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
    pub async fn request_user_details(&self, connection_id: u16) -> Result<()> {
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
    pub fn chat_room(&self, room: u16) -> Option<ChatRoom> {
        self.chat_rooms
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&room)
            .cloned()
    }

    /// Record an inbound direct message from `peer`, decrypting it when it
    /// arrived end-to-end encrypted.
    fn apply_direct_message(&self, peer: u16, encrypted: bool, payload: &[u8]) {
        let text = if encrypted {
            match self.peer_verifying_key(peer) {
                Some(their_key) => {
                    let key = dm::shared_key(&self.signing_key, &their_key);
                    dm::decrypt(&key, payload).map_or_else(
                        |_| "[unable to decrypt]".to_string(),
                        |bytes| String::from_utf8_lossy(&bytes).into_owned(),
                    )
                }
                None => "[unable to decrypt]".to_string(),
            }
        } else {
            String::from_utf8_lossy(payload).into_owned()
        };
        self.push_dm(
            peer,
            DmMessage {
                time: Local::now(),
                from_me: false,
                encrypted,
                text,
            },
        );
        // Ask the GUI to open a window for this conversation if one is not
        // already showing.
        self.dm_open_requests
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(peer);
    }

    /// Append a direct message to the conversation with `peer`.
    fn push_dm(&self, peer: u16, message: DmMessage) {
        self.dms
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(peer)
            .or_default()
            .push(message);
    }

    /// The identity public key `peer` advertised, if any.
    fn peer_public_key(&self, peer: u16) -> Option<[u8; 32]> {
        self.connected_users
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|user| user.id == peer)
            .and_then(|user| user.public_key)
    }

    /// `peer`'s identity key parsed into a [`VerifyingKey`], if usable.
    fn peer_verifying_key(&self, peer: u16) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(&self.peer_public_key(peer)?).ok()
    }

    /// Whether direct messages with `peer` can be end-to-end encrypted (the peer
    /// provided a usable identity key).
    #[must_use]
    pub fn dm_encrypted_with(&self, peer: u16) -> bool {
        self.peer_verifying_key(peer).is_some()
    }

    /// A hex fingerprint of `peer`'s identity key, for out-of-band verification.
    #[must_use]
    pub fn peer_key_fingerprint(&self, peer: u16) -> Option<String> {
        self.peer_public_key(peer).as_ref().map(dm::fingerprint)
    }

    /// Drain the peers whose inbound direct message should open a window. Empty
    /// once consumed, so manually closing a window is not immediately undone
    /// (a later message re-requests it).
    #[must_use]
    pub fn take_dm_open_requests(&self) -> Vec<u16> {
        std::mem::take(
            &mut *self
                .dm_open_requests
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// A snapshot of the direct-message conversation with `peer`.
    #[must_use]
    pub fn dm_thread(&self, peer: u16) -> Vec<DmMessage> {
        self.dms
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&peer)
            .cloned()
            .unwrap_or_default()
    }

    /// Send a direct message to `peer`. It is end-to-end encrypted when the peer
    /// provided an identity key; otherwise it is relayed as plaintext (still
    /// over the encrypted link to the server).
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn send_dm(&self, peer: u16, message: String) -> Result<()> {
        let (encrypted, payload) = match self.peer_verifying_key(peer) {
            Some(their_key) => {
                let key = dm::shared_key(&self.signing_key, &their_key);
                (true, dm::encrypt(&key, message.as_bytes()))
            }
            None => (false, message.clone().into_bytes()),
        };
        // Record locally first so the message appears immediately.
        self.push_dm(
            peer,
            DmMessage {
                time: Local::now(),
                from_me: true,
                encrypted,
                text: message,
            },
        );
        let request = ServerMessagesEncrypted::DirectMessage {
            to: peer,
            encrypted,
            payload,
        };
        self.send_request(&request.to_vec()).await
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

    /// Request a shared-directory listing (`path` relative to the share root,
    /// empty for the root). The reply is available from [`Self::file_listing`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn request_file_list(&self, path: String) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::FileListRequest { path }.to_vec())
            .await
    }

    /// Request a file download; chunks accumulate into [`Self::download`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn request_file_download(&self, path: String) -> Result<()> {
        // Reset any prior transfer so progress reflects this one.
        *self
            .download
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.send_request(&ServerMessagesEncrypted::FileDownloadRequest { path }.to_vec())
            .await
    }

    /// The most recent shared-directory listing, if any.
    #[must_use]
    pub fn file_listing(&self) -> Option<FileListing> {
        self.file_listing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// A snapshot of the current/last file download, if any.
    #[must_use]
    pub fn download(&self) -> Option<Download> {
        self.download
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Clear the current download (e.g. after saving it).
    pub fn clear_download(&self) {
        *self
            .download
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// (Admin) Request read-only shared-directory info; the reply is available
    /// from [`Self::admin_share_info`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_get_share_info(&self) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::GetShareInfo,
            )
            .to_vec(),
        )
        .await
    }

    /// The most recently fetched shared-directory info, if any.
    #[must_use]
    pub fn admin_share_info(&self) -> Option<ShareInfo> {
        self.admin_share_info
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// (Admin) Request the server-wide limits; the reply is available from
    /// [`Self::admin_limits`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_get_server_limits(&self) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::GetServerLimits,
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Set the maximum accepted upload size in bytes (`None` removes it).
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_set_max_upload_size(&self, max: Option<u64>) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetMaxUploadSize(max),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Set the maximum number of concurrent connections (`None` removes
    /// the limit).
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_set_max_connections(&self, max: Option<u16>) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetMaxConnections(max),
            )
            .to_vec(),
        )
        .await
    }

    /// The most recently fetched server-wide limits, if any.
    #[must_use]
    pub fn admin_limits(&self) -> Option<ServerLimits> {
        *self
            .admin_limits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// (Admin) Request a shared directory's ACL; the reply is available from
    /// [`Self::file_acl`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_get_file_acl(&self, path: String) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::GetFileAcl(path),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Replace a shared directory's ACL.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_set_file_acl(&self, path: String, acl: DirAcl) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetFileAcl { path, acl },
            )
            .to_vec(),
        )
        .await
    }

    /// The most recently fetched shared-directory ACL, if any.
    #[must_use]
    pub fn file_acl(&self) -> Option<NamedAcl> {
        self.file_acl
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Upload `data` to `path` (relative to the share root). Streams the request,
    /// chunks, and end; status lands in [`Self::file_notice`], errors in
    /// [`Self::admin_error`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn upload_file(&self, path: String, data: Vec<u8>) -> Result<()> {
        let size = data.len() as u64;
        self.send_request(&ServerMessagesEncrypted::FileUploadRequest { path, size }.to_vec())
            .await?;
        for chunk in data.chunks(64 * 1024) {
            self.send_request(
                &ServerMessagesEncrypted::FileUploadChunk {
                    data: chunk.to_vec(),
                }
                .to_vec(),
            )
            .await?;
        }
        self.send_request(&ServerMessagesEncrypted::FileUploadEnd.to_vec())
            .await
    }

    /// Delete a shared file or empty directory (relative to the share root).
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn delete_file(&self, path: String) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::FileDeleteRequest { path }.to_vec())
            .await
    }

    /// Create a new remote directory (relative to the share root).
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn create_dir(&self, path: String) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::FileMkdirRequest { path }.to_vec())
            .await
    }

    /// The latest file-operation notice (e.g. upload status), if any.
    #[must_use]
    pub fn file_notice(&self) -> Option<String> {
        self.file_notice
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Set the file-operation notice (e.g. a client-side error).
    pub fn set_file_notice(&self, message: String) {
        *self
            .file_notice
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(message);
    }

    /// Clear the current file-operation notice.
    pub fn clear_file_notice(&self) {
        *self
            .file_notice
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Join a chatroom by id.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn chat_join(&self, room: u16) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ChatJoin(room).to_vec())
            .await
    }

    /// Leave a chatroom by id and clear its local (unsaved) state.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn chat_leave(&self, room: u16) -> Result<()> {
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
    pub async fn chat_send(&self, room: u16, message: String) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ChatSend { room, message }.to_vec())
            .await
    }

    // ── Forums ──────────────────────────────────────────────────────────────

    /// Whether the server has forums enabled.
    #[must_use]
    pub fn forums_enabled(&self) -> bool {
        self.server_info().forums_enabled
    }

    /// The forum topics this user may access, as last reported by the server.
    #[must_use]
    pub fn forum_topics(&self) -> Vec<ForumTopic> {
        self.forum_topics
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The threads last received for a topic (empty until requested).
    #[must_use]
    pub fn forum_threads(&self, topic: u32) -> Vec<ForumThreadInfo> {
        self.forum_threads
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&topic)
            .cloned()
            .unwrap_or_default()
    }

    /// The posts for an open thread, or `None` if it has not been opened yet.
    #[must_use]
    pub fn forum_posts(&self, thread: u32) -> Option<Vec<ForumPost>> {
        self.forum_posts
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&thread)
            .cloned()
    }

    /// Request the forum topics this user may access.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn request_forum_topics(&self) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ForumTopicsRequest.to_vec())
            .await
    }

    /// Request the threads within a topic; the reply lands in [`Self::forum_threads`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn request_forum_threads(&self, topic: u32) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ForumThreadsRequest { topic }.to_vec())
            .await
    }

    /// Open a thread: subscribe to its posts. The current posts land in
    /// [`Self::forum_posts`].
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn open_forum_thread(&self, thread: u32) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ForumThreadOpen { thread }.to_vec())
            .await
    }

    /// Close a thread: unsubscribe and drop its local posts.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn close_forum_thread(&self, thread: u32) -> Result<()> {
        self.forum_posts
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&thread);
        self.send_request(&ServerMessagesEncrypted::ForumThreadClose { thread }.to_vec())
            .await
    }

    /// Start a new thread. When `sign` is set, the body is signed with this
    /// client's identity key.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn new_forum_thread(
        &self,
        topic: u32,
        subject: String,
        body: String,
        markdown: bool,
        sign: bool,
    ) -> Result<()> {
        let signature = sign.then(|| ForumSignature::sign(&self.signing_key, &body));
        self.send_request(
            &ServerMessagesEncrypted::ForumNewThread(NewForumThread {
                topic,
                subject,
                body,
                markdown,
                signature,
            })
            .to_vec(),
        )
        .await
    }

    /// Reply within a thread, optionally to a specific post and optionally signed.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn new_forum_post(
        &self,
        thread: u32,
        reply_to: Option<u32>,
        body: String,
        markdown: bool,
        sign: bool,
    ) -> Result<()> {
        let signature = sign.then(|| ForumSignature::sign(&self.signing_key, &body));
        self.send_request(
            &ServerMessagesEncrypted::ForumNewPost(NewForumPost {
                thread,
                reply_to,
                body,
                markdown,
                signature,
            })
            .to_vec(),
        )
        .await
    }

    /// (Admin) Delete a forum post by id.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn delete_forum_post(&self, post: u32) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ForumDeletePost { post }.to_vec())
            .await
    }

    /// The most recently received administrative forum-topic list.
    #[must_use]
    pub fn admin_forum_topics(&self) -> Vec<AdminForumTopic> {
        self.admin_forum_topics
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// (Admin) Request the forum topics with their group restrictions.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_list_forum_topics(&self) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::ListForumTopics,
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Enable or disable forums on the server.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_set_forums_enabled(&self, enabled: bool) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetForumsEnabled(enabled),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Create a forum topic restricted to the given group ids.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_create_forum_topic(
        &self,
        name: String,
        description: String,
        groups: Vec<u32>,
    ) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::CreateForumTopic {
                    name,
                    description,
                    groups,
                },
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Rename a forum topic, update its description, and replace groups.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_edit_forum_topic(
        &self,
        id: u32,
        name: String,
        description: String,
        groups: Vec<u32>,
    ) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::EditForumTopic {
                    id,
                    name,
                    description,
                    groups,
                },
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Delete a forum topic and its threads and posts.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_delete_forum_topic(&self, id: u32) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::DeleteForumTopic(id),
            )
            .to_vec(),
        )
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

    /// (Admin) Create a group with an optional description and colour.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_create_group(
        &self,
        name: String,
        description: Option<String>,
        color: Option<[u8; 3]>,
    ) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::CreateGroup(CreateGroup {
                    name,
                    description,
                    color,
                }),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Rename a group and set its description and colour.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_edit_group(
        &self,
        id: u32,
        name: String,
        description: Option<String>,
        color: Option<[u8; 3]>,
    ) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::EditGroup(Group {
                    id,
                    name,
                    description,
                    color,
                }),
            )
            .to_vec(),
        )
        .await
    }

    /// (Admin) Delete a group by id.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_delete_group(&self, id: u32) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::DeleteGroup(id),
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
    pub async fn admin_kick_user(&self, connection_id: u16) -> Result<()> {
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
    pub async fn admin_edit_chatroom(&self, id: u16, name: String, groups: Vec<u32>) -> Result<()> {
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
    pub async fn admin_delete_chatroom(&self, id: u16) -> Result<()> {
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
