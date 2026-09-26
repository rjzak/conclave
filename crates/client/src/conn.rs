// SPDX-License-Identifier: Apache-2.0

use conclave_common::dm;
use conclave_common::files::{DirAcl, FileEntry, ShareInfo};
use conclave_common::forum::{
    ForumPost, ForumSignature, ForumThreadInfo, ForumTopic, NewForumPost, NewForumThread,
};
use conclave_common::net::{DefaultEncryptedStream, EncryptedWrite, SigningKey, VerifyingKey};
use conclave_common::poll::{NewPoll, Poll, PollVote};
use conclave_common::server::{
    ChatEvent, ChatTopic, ChatroomInfo, ClientMessagesEncrypted, ConnectedUser, ServerInformation,
    ServerMessagesEncrypted, UserDetails,
};

use std::collections::HashMap;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

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

/// What one entry in a direct-message conversation holds.
#[derive(Clone, Debug)]
pub enum DmBody {
    /// A text message (or a placeholder if it could not be decrypted).
    Text(String),

    /// A file offered to, or by, the other user. The transfer's live state is
    /// looked up with [`ConclaveConnection::file_transfer`] rather than copied
    /// here, so the entry stays correct as the transfer progresses.
    File(u64),

    /// A note from this client about the conversation, such as a file that
    /// could not be read. Never sent or received.
    Notice(String),
}

/// A single direct message in a conversation with another user. History is not
/// preserved, so a thread only accumulates while the connection is open.
#[derive(Clone, Debug)]
pub struct DmMessage {
    /// Local time the message was sent or received.
    pub time: DateTime<Local>,

    /// Whether this side sent the message (`true`) or received it (`false`).
    pub from_me: bool,

    /// What the entry holds: a message, or a file transfer.
    pub body: DmBody,
}

/// How far along a user-to-user file transfer is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferState {
    /// Offered; waiting for the recipient to accept or decline.
    Offered,

    /// Accepted, and the bytes are moving.
    Transferring,

    /// Every byte arrived (incoming) or was sent (outgoing).
    Complete,

    /// The recipient declined the file.
    Declined,

    /// The transfer ended early; the string says why.
    Failed(String),
}

/// A file being sent to, or received from, another user alongside a
/// conversation. Like the messages themselves, transfers live only as long as
/// the connection.
#[derive(Clone, Debug)]
pub struct FileTransfer {
    /// Local key, which a [`DmBody::File`] entry refers to.
    pub key: u64,

    /// The other user's connection id.
    pub peer: u16,

    /// Whether this client is the one sending the file.
    pub outgoing: bool,

    /// The file's name, with no directory part.
    pub name: String,

    /// The file's size in bytes, before encryption.
    pub size: u64,

    /// Bytes sent or received so far, before encryption.
    pub progress: u64,

    /// How far along the transfer is.
    pub state: TransferState,

    /// The local file: the one being sent (outgoing), or the one a received
    /// file is written to, once the user has accepted it (incoming).
    pub path: Option<PathBuf>,
}

impl FileTransfer {
    /// Transfer id on the wire, chosen by whichever side is sending.
    #[inline]
    #[must_use]
    pub const fn wire_id(&self) -> u32 {
        // The key packs the id in the middle; see `transfer_key`.
        #[allow(clippy::cast_possible_truncation)]
        ((self.key >> 1) as u32)
    }

    /// Fraction of the file transferred so far, in `0.0..=1.0`.
    #[inline]
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fraction(&self) -> f32 {
        if self.size == 0 {
            return 1.0;
        }
        (self.progress as f32 / self.size as f32).clamp(0.0, 1.0)
    }
}

/// Reduce a name a peer sent to something safe to show and to use as the
/// default for a save dialog: the final path component only, never a path, a
/// traversal, or an empty string.
fn sanitize_file_name(name: &str) -> String {
    let trimmed = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_start_matches('.');
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Where an incoming file is written while it is still arriving. Keeping it
/// beside the destination means the move into place is a rename on the same
/// filesystem, and that a failed transfer never clobbers an existing file.
fn partial_path(destination: &Path) -> PathBuf {
    let mut name = destination.as_os_str().to_os_string();
    name.push(".conclave-part");
    PathBuf::from(name)
}

/// Key a transfer by the peer it is with, the id whichever side is sending
/// chose, and the direction. Ids are only unique per sender, so the peer and
/// the direction are both needed to tell two transfers apart.
#[inline]
const fn transfer_key(peer: u16, id: u32, outgoing: bool) -> u64 {
    ((peer as u64) << 33) | ((id as u64) << 1) | (outgoing as u64)
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

    /// The room's current topic and who set it, or `None` if unset.
    pub topic: Option<ChatTopic>,
}

/// Connection information
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

    /// The poll attached to each open thread that has one, keyed by thread id,
    /// as this user is allowed to see it.
    pub(crate) forum_polls: Arc<std::sync::RwLock<HashMap<u32, Poll>>>,

    /// The server's banner image (a PNG), if it has one set.
    pub(crate) server_banner: Arc<std::sync::RwLock<Option<Vec<u8>>>>,

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

    /// File transfers with other users, keyed by [`transfer_key`]. Holds only
    /// each transfer's metadata: the bytes are streamed to or from disk.
    pub(crate) transfers: Arc<std::sync::RwLock<HashMap<u64, FileTransfer>>>,

    /// Open handle to the partial file each incoming transfer is being written
    /// to. Chunks go straight to disk, so a large file never has to fit in
    /// memory, and the destination is only replaced once the file is complete.
    pub(crate) incoming_files: Arc<std::sync::RwLock<HashMap<u64, std::fs::File>>>,

    /// Source of transfer ids for the files this client offers. Unique per
    /// connection, which is all the protocol requires.
    pub(crate) next_transfer_id: Arc<AtomicU32>,

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
            forum_polls: Arc::new(std::sync::RwLock::new(HashMap::new())),
            server_banner: Arc::new(std::sync::RwLock::new(None)),
            file_listing: Arc::new(std::sync::RwLock::new(None)),
            download: Arc::new(std::sync::RwLock::new(None)),
            file_acl: Arc::new(std::sync::RwLock::new(None)),
            admin_share_info: Arc::new(std::sync::RwLock::new(None)),
            admin_limits: Arc::new(std::sync::RwLock::new(None)),
            file_notice: Arc::new(std::sync::RwLock::new(None)),
            dms: Arc::new(std::sync::RwLock::new(HashMap::new())),
            dm_open_requests: Arc::new(std::sync::RwLock::new(Vec::new())),
            transfers: Arc::new(std::sync::RwLock::new(HashMap::new())),
            incoming_files: Arc::new(std::sync::RwLock::new(HashMap::new())),
            next_transfer_id: Arc::new(AtomicU32::new(0)),
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
                    ClientMessagesEncrypted::ChatJoined { room, users, topic } => {
                        let mut rooms = conn_clone
                            .chat_rooms
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let entry = rooms.entry(room).or_default();
                        entry.users = users;
                        entry.topic = topic;
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
                    ClientMessagesEncrypted::ServerBannerResponse(banner) => {
                        *conn_clone
                            .server_banner
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = banner;
                    }
                    ClientMessagesEncrypted::ForumThreadsResponse { topic, threads } => {
                        conn_clone
                            .forum_threads
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(topic, threads);
                    }
                    ClientMessagesEncrypted::ForumThreadResponse {
                        thread,
                        posts,
                        poll,
                    } => {
                        conn_clone
                            .forum_posts
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(thread, posts);
                        let mut polls = conn_clone
                            .forum_polls
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        match poll {
                            Some(poll) => polls.insert(thread, poll),
                            None => polls.remove(&thread),
                        };
                    }
                    ClientMessagesEncrypted::ForumPollUpdate { thread, poll } => {
                        conn_clone
                            .forum_polls
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(thread, poll);
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
                        payload,
                    } => {
                        conn_clone.apply_direct_message(from, &payload);
                    }
                    ClientMessagesEncrypted::DirectFileOffered {
                        from,
                        from_display_name: _,
                        transfer,
                        size,
                        name,
                    } => {
                        conn_clone.apply_file_offer(from, transfer, size, &name);
                    }
                    ClientMessagesEncrypted::DirectFileAnswered {
                        from,
                        transfer,
                        accept,
                    } => {
                        conn_clone.apply_file_answer(from, transfer, accept);
                    }
                    ClientMessagesEncrypted::DirectFileChunk {
                        from,
                        transfer,
                        data,
                    } => {
                        conn_clone.apply_file_chunk(from, transfer, &data);
                    }
                    ClientMessagesEncrypted::DirectFileEnded { from, transfer } => {
                        conn_clone.apply_file_end(from, transfer);
                    }
                    ClientMessagesEncrypted::DirectFileFailed {
                        peer,
                        transfer,
                        outgoing,
                        reason,
                    } => {
                        conn_clone.fail_transfer(transfer_key(peer, transfer, outgoing), &reason);
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
            ChatEvent::Topic {
                room,
                display_name,
                topic,
            } => {
                // Stamp the local time so the log shows when the topic changed.
                let time = Local::now().format("%H:%M:%S");
                let entry = rooms.entry(room).or_default();
                let line = if topic.trim().is_empty() {
                    entry.topic = None;
                    format!("{time} {display_name} cleared the topic")
                } else {
                    entry.topic = Some(ChatTopic {
                        text: topic.clone(),
                        set_by: display_name.clone(),
                    });
                    format!("{time} {display_name} set the topic to: {topic}")
                };
                entry.lines.push(ChatLine::System(line));
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

    /// Record an inbound direct message from `peer`, decrypting it to the key
    /// shared with them.
    ///
    /// Every direct message is end-to-end encrypted, and nothing on the wire can
    /// claim otherwise, so a payload that does not decrypt was not encrypted to
    /// this user: it is marked as such rather than displayed as whatever bytes
    /// arrived.
    fn apply_direct_message(&self, peer: u16, payload: &[u8]) {
        let text = self
            .peer_shared_key(peer)
            .and_then(|key| dm::decrypt(&key, payload).ok())
            .map_or_else(
                || "[unable to decrypt]".to_string(),
                |bytes| String::from_utf8_lossy(&bytes).into_owned(),
            );
        self.push_dm(
            peer,
            DmMessage {
                time: Local::now(),
                from_me: false,
                body: DmBody::Text(text),
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

    /// The identity public key `peer` presented, if they are still connected.
    fn peer_public_key(&self, peer: u16) -> Option<[u8; 32]> {
        self.connected_users
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|user| user.id == peer)
            .map(|user| user.public_key)
    }

    /// `peer`'s identity key parsed into a [`VerifyingKey`], if usable.
    fn peer_verifying_key(&self, peer: u16) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(&self.peer_public_key(peer)?).ok()
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

    /// Send an end-to-end encrypted direct message to `peer`.
    ///
    /// # Errors
    ///
    /// Fails if `peer` has left, leaving no key to encrypt to, or on a network
    /// error. There is deliberately no plaintext fallback: a message that cannot
    /// be encrypted is not sent at all.
    pub async fn send_dm(&self, peer: u16, message: String) -> Result<()> {
        let Some(shared) = self.peer_shared_key(peer) else {
            let reason =
                "That user is no longer connected, so the message cannot be encrypted to them"
                    .to_string();
            self.push_dm(
                peer,
                DmMessage {
                    time: Local::now(),
                    from_me: true,
                    body: DmBody::Notice(reason.clone()),
                },
            );
            return Err(anyhow!(reason));
        };
        // Record locally first so the message appears immediately.
        self.push_dm(
            peer,
            DmMessage {
                time: Local::now(),
                from_me: true,
                body: DmBody::Text(message.clone()),
            },
        );
        let request = ServerMessagesEncrypted::DirectMessage {
            to: peer,
            payload: dm::encrypt(&shared, message.as_bytes()),
        };
        self.send_request(&request.to_vec()).await
    }

    /// A snapshot of one file transfer, if it is still known.
    #[must_use]
    pub fn file_transfer(&self, key: u64) -> Option<FileTransfer> {
        self.transfers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned()
    }

    /// Apply `change` to a transfer, if it is still known.
    fn update_transfer(&self, key: u64, change: impl FnOnce(&mut FileTransfer)) {
        if let Some(transfer) = self
            .transfers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&key)
        {
            change(transfer);
        }
    }

    /// End a transfer with a reason, discarding anything received for it. A
    /// transfer that already finished is left alone, so a late notice (the peer
    /// disconnecting, say) cannot undo a completed file.
    fn fail_transfer(&self, key: u64, reason: &str) {
        let partial = self
            .incoming_files
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key)
            .is_some();
        let mut ended = false;
        self.update_transfer(key, |transfer| {
            if matches!(
                transfer.state,
                TransferState::Offered | TransferState::Transferring
            ) {
                transfer.state = TransferState::Failed(reason.to_string());
                ended = true;
            }
        });
        // Only the half-written file goes; the destination the user chose is
        // left as it was, since nothing was ever moved into place. An outgoing
        // transfer's path is the user's own file, which is never touched.
        if partial
            && ended
            && let Some(transfer) = self.file_transfer(key)
            && !transfer.outgoing
            && let Some(path) = transfer.path
        {
            let _ = std::fs::remove_file(partial_path(&path));
        }
    }

    /// The end-to-end key shared with `peer`, if they are still connected.
    fn peer_shared_key(&self, peer: u16) -> Option<[u8; 32]> {
        self.peer_verifying_key(peer)
            .map(|their_key| dm::shared_key(&self.signing_key, &their_key))
    }

    /// Record an inbound file offer and surface the conversation so the user can
    /// answer it.
    ///
    /// The name arrives encrypted to the key shared with `peer`: an offer whose
    /// name does not decrypt is not something this client can receive, so it is
    /// declined rather than shown with an undecipherable name and a body nobody
    /// could read.
    fn apply_file_offer(&self, peer: u16, id: u32, size: u64, name: &[u8]) {
        let Some(name) = self
            .peer_shared_key(peer)
            .and_then(|key| dm::decrypt(&key, name).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        else {
            self.push_dm(
                peer,
                DmMessage {
                    time: Local::now(),
                    from_me: false,
                    body: DmBody::Notice(
                        "Declined a file that was not encrypted to this user".to_string(),
                    ),
                },
            );
            self.spawn_file_decline(peer, id);
            return;
        };
        // Whatever the sender called it, only the final component is a name: a
        // peer must not be able to steer where the file is written.
        let name = sanitize_file_name(&name);

        let key = transfer_key(peer, id, false);
        self.transfers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                key,
                FileTransfer {
                    key,
                    peer,
                    outgoing: false,
                    name,
                    size,
                    progress: 0,
                    state: TransferState::Offered,
                    path: None,
                },
            );
        self.push_dm(
            peer,
            DmMessage {
                time: Local::now(),
                from_me: false,
                body: DmBody::File(key),
            },
        );
        // An offer needs an answer, so surface the conversation the same way an
        // inbound message does.
        self.dm_open_requests
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(peer);
    }

    /// Apply the recipient's answer to a file this client offered, starting the
    /// send when they accepted.
    fn apply_file_answer(&self, peer: u16, id: u32, accept: bool) {
        let key = transfer_key(peer, id, true);
        if !accept {
            self.update_transfer(key, |transfer| {
                if transfer.state == TransferState::Offered {
                    transfer.state = TransferState::Declined;
                }
            });
            return;
        }
        let mut start = false;
        self.update_transfer(key, |transfer| {
            if transfer.state == TransferState::Offered {
                transfer.state = TransferState::Transferring;
                start = true;
            }
        });
        if start {
            self.spawn_file_send(key);
        }
    }

    /// Accumulate one chunk of an incoming file.
    fn apply_file_chunk(&self, peer: u16, id: u32, data: &[u8]) {
        let key = transfer_key(peer, id, false);
        let Some(transfer) = self.file_transfer(key) else {
            return;
        };
        if transfer.state != TransferState::Transferring {
            return;
        }
        let Some(plaintext) = self
            .peer_shared_key(peer)
            .and_then(|shared| dm::decrypt(&shared, data).ok())
        else {
            self.fail_transfer(key, "A chunk of the file could not be decrypted");
            self.spawn_file_cancel(peer, id, false);
            return;
        };

        let received = plaintext.len() as u64;
        if transfer.progress.saturating_add(received) > transfer.size {
            self.fail_transfer(key, "The sender sent more than the file they offered");
            self.spawn_file_cancel(peer, id, false);
            return;
        }
        let written = self
            .incoming_files
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&key)
            .map(|file| std::io::Write::write_all(file, &plaintext));
        match written {
            Some(Ok(())) => self.update_transfer(key, |transfer| transfer.progress += received),
            Some(Err(e)) => {
                self.fail_transfer(key, &format!("Could not write the file: {e}"));
                self.spawn_file_cancel(peer, id, false);
            }
            None => {
                self.fail_transfer(key, "The file is no longer open for writing");
                self.spawn_file_cancel(peer, id, false);
            }
        }
    }

    /// Finish an incoming file: close the partial file and move it to the
    /// destination the user chose when they accepted the offer.
    fn apply_file_end(&self, peer: u16, id: u32) {
        let key = transfer_key(peer, id, false);
        let Some(transfer) = self.file_transfer(key) else {
            return;
        };
        if transfer.state != TransferState::Transferring {
            return;
        }
        let file = self
            .incoming_files
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
        // Flushed and closed before the rename, so nothing is still in flight.
        let flushed = match file {
            Some(mut file) => std::io::Write::flush(&mut file),
            None => Ok(()),
        };
        let Some(destination) = transfer.path.clone() else {
            self.fail_transfer(key, "No destination was chosen for the file");
            return;
        };

        let outcome = flushed.and_then(|()| {
            if transfer.progress == transfer.size {
                std::fs::rename(partial_path(&destination), &destination)
            } else {
                Err(std::io::Error::other("the file arrived incomplete"))
            }
        });
        match outcome {
            Ok(()) => {
                self.update_transfer(key, |transfer| transfer.state = TransferState::Complete);
            }
            Err(e) => {
                let _ = std::fs::remove_file(partial_path(&destination));
                self.update_transfer(key, |transfer| {
                    transfer.state = TransferState::Failed(format!(
                        "Could not save {}: {e}",
                        destination.display()
                    ));
                });
            }
        }
    }

    /// Offer a local file to `peer`. Nothing is sent until they accept; the
    /// server may refuse the offer outright if the file is over its limit.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read, or on a network error.
    pub async fn offer_file(&self, peer: u16, path: &Path) -> Result<()> {
        // A file is only ever sent end-to-end encrypted. Once the peer has left
        // there is no key to encrypt to, so the offer is refused here rather
        // than falling back to handing the file to the server.
        let Some(shared) = self.peer_shared_key(peer) else {
            let reason = "That user is no longer connected, so a file cannot be encrypted to them"
                .to_string();
            self.push_dm(
                peer,
                DmMessage {
                    time: Local::now(),
                    from_me: true,
                    body: DmBody::Notice(reason.clone()),
                },
            );
            return Err(anyhow!(reason));
        };

        let size = match std::fs::metadata(path) {
            Ok(metadata) => metadata.len(),
            Err(e) => {
                // Nothing was offered, so there is no transfer to show as
                // failed: say so in the conversation instead.
                let reason = format!("Cannot read {}: {e}", path.display());
                self.push_dm(
                    peer,
                    DmMessage {
                        time: Local::now(),
                        from_me: true,
                        body: DmBody::Notice(reason.clone()),
                    },
                );
                return Err(anyhow!(reason));
            }
        };
        let name = path.file_name().map_or_else(
            || "file".to_string(),
            |name| name.to_string_lossy().into_owned(),
        );

        let name_payload = dm::encrypt(&shared, name.as_bytes());

        let id = self.next_transfer_id.fetch_add(1, Ordering::Relaxed);
        let key = transfer_key(peer, id, true);
        self.transfers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                key,
                FileTransfer {
                    key,
                    peer,
                    outgoing: true,
                    name,
                    size,
                    progress: 0,
                    state: TransferState::Offered,
                    path: Some(path.to_path_buf()),
                },
            );
        self.push_dm(
            peer,
            DmMessage {
                time: Local::now(),
                from_me: true,
                body: DmBody::File(key),
            },
        );

        let sent = self
            .send_request(
                &ServerMessagesEncrypted::DirectFileOffer {
                    to: peer,
                    transfer: id,
                    size,
                    name: name_payload,
                }
                .to_vec(),
            )
            .await;
        if let Err(e) = &sent {
            // The offer never reached the server, so nothing will ever answer
            // it: show it as failed rather than waiting forever.
            self.fail_transfer(key, &e.to_string());
        }
        sent
    }

    /// Accept an offered file, to be written to `destination` once it arrives.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn accept_file(&self, key: u64, destination: PathBuf) -> Result<()> {
        let Some(transfer) = self.file_transfer(key) else {
            return Err(anyhow!("That file transfer is no longer available"));
        };
        if transfer.outgoing || transfer.state != TransferState::Offered {
            return Err(anyhow!("That file is not waiting to be accepted"));
        }
        // Open the partial file before accepting: a destination that cannot be
        // written is worth finding out about before the sender starts.
        let partial = partial_path(&destination);
        let file = std::fs::File::create(&partial)
            .map_err(|e| anyhow!("Cannot write {}: {e}", partial.display()))?;
        self.incoming_files
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, file);
        self.update_transfer(key, |transfer| {
            transfer.path = Some(destination);
            transfer.state = TransferState::Transferring;
        });
        self.send_request(
            &ServerMessagesEncrypted::DirectFileAnswer {
                to: transfer.peer,
                transfer: transfer.wire_id(),
                accept: true,
            }
            .to_vec(),
        )
        .await
    }

    /// Decline an offered file.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn decline_file(&self, key: u64) -> Result<()> {
        let Some(transfer) = self.file_transfer(key) else {
            return Err(anyhow!("That file transfer is no longer available"));
        };
        if transfer.outgoing || transfer.state != TransferState::Offered {
            return Err(anyhow!("That file is not waiting to be answered"));
        }
        self.update_transfer(key, |transfer| transfer.state = TransferState::Declined);
        self.send_request(
            &ServerMessagesEncrypted::DirectFileAnswer {
                to: transfer.peer,
                transfer: transfer.wire_id(),
                accept: false,
            }
            .to_vec(),
        )
        .await
    }

    /// Abandon a transfer that has not finished, from either end.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn cancel_file(&self, key: u64) -> Result<()> {
        let Some(transfer) = self.file_transfer(key) else {
            return Err(anyhow!("That file transfer is no longer available"));
        };
        if !matches!(
            transfer.state,
            TransferState::Offered | TransferState::Transferring
        ) {
            return Err(anyhow!("That file transfer has already finished"));
        }
        self.fail_transfer(key, "Cancelled");
        self.send_request(
            &ServerMessagesEncrypted::DirectFileCancel {
                to: transfer.peer,
                transfer: transfer.wire_id(),
                outgoing: transfer.outgoing,
            }
            .to_vec(),
        )
        .await
    }

    /// Decline an offer this client will not even show the user, ignoring a send
    /// failure: the conversation already says why it was refused.
    fn spawn_file_decline(&self, peer: u16, id: u32) {
        let conn = self.clone();
        tokio::spawn(async move {
            let _ = conn
                .send_request(
                    &ServerMessagesEncrypted::DirectFileAnswer {
                        to: peer,
                        transfer: id,
                        accept: false,
                    }
                    .to_vec(),
                )
                .await;
        });
    }

    /// Tell the peer to abandon a transfer, ignoring a send failure: the caller
    /// has already recorded locally why the transfer ended. `outgoing` says
    /// whether this client is the one sending the file.
    fn spawn_file_cancel(&self, peer: u16, id: u32, outgoing: bool) {
        let conn = self.clone();
        tokio::spawn(async move {
            let _ = conn
                .send_request(
                    &ServerMessagesEncrypted::DirectFileCancel {
                        to: peer,
                        transfer: id,
                        outgoing,
                    }
                    .to_vec(),
                )
                .await;
        });
    }

    /// Stream an accepted file to its recipient, one encrypted chunk at a time,
    /// off the connection's reader task.
    fn spawn_file_send(&self, key: u64) {
        let conn = self.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.send_file(key).await {
                let reason = e.to_string();
                conn.fail_transfer(key, &reason);
                if let Some(transfer) = conn.file_transfer(key) {
                    conn.spawn_file_cancel(transfer.peer, transfer.wire_id(), true);
                }
            }
        });
    }

    /// Read the file from disk and send it in chunks, ending with
    /// [`ServerMessagesEncrypted::DirectFileEnd`].
    async fn send_file(&self, key: u64) -> Result<()> {
        use std::io::Read as _;

        let transfer = self
            .file_transfer(key)
            .ok_or_else(|| anyhow!("That file transfer is no longer available"))?;
        let source = transfer
            .path
            .clone()
            .ok_or_else(|| anyhow!("The file to send is no longer known"))?;
        // Derived once: the shared key costs a scalar multiplication, and every
        // chunk of the file uses the same one. The peer had a key when the offer
        // went out; if they have somehow lost one since, the file is not sent.
        let shared = self
            .peer_shared_key(transfer.peer)
            .ok_or_else(|| anyhow!("That user has no identity key to encrypt the file to"))?;

        let mut file = std::fs::File::open(&source)
            .map_err(|e| anyhow!("Cannot read {}: {e}", source.display()))?;
        let mut buffer = vec![0u8; conclave_common::server::DM_FILE_CHUNK_BYTES];
        let mut sent = 0u64;
        loop {
            // The transfer can end under us: the peer may cancel, or disconnect.
            if self
                .file_transfer(key)
                .is_none_or(|transfer| transfer.state != TransferState::Transferring)
            {
                return Ok(());
            }
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(e) => return Err(anyhow!("Cannot read {}: {e}", source.display())),
            };
            // Never send more than was offered: the server counts the bytes
            // against the offer and would drop the transfer.
            let read = read.min(usize::try_from(transfer.size - sent).unwrap_or(read));
            if read == 0 {
                break;
            }
            let data = dm::encrypt(&shared, &buffer[..read]);
            self.send_request(
                &ServerMessagesEncrypted::DirectFileChunk {
                    to: transfer.peer,
                    transfer: transfer.wire_id(),
                    data,
                }
                .to_vec(),
            )
            .await?;
            sent += read as u64;
            self.update_transfer(key, |transfer| transfer.progress = sent);
        }

        if sent != transfer.size {
            return Err(anyhow!("{} changed while it was being sent", transfer.name));
        }
        self.send_request(
            &ServerMessagesEncrypted::DirectFileEnd {
                to: transfer.peer,
                transfer: transfer.wire_id(),
            }
            .to_vec(),
        )
        .await?;
        self.update_transfer(key, |transfer| transfer.state = TransferState::Complete);
        Ok(())
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

    /// Set (or, with empty text, clear) a chatroom's topic.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn chat_set_topic(&self, room: u16, topic: String) -> Result<()> {
        self.send_request(&ServerMessagesEncrypted::ChatSetTopic { room, topic }.to_vec())
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

    /// The poll attached to an open thread, as this user may see it. `None`
    /// when the thread has no poll or has not been opened yet.
    ///
    /// A poll whose creator kept the results private arrives with no counts at
    /// all until it closes, so there is nothing here for a client to hide, and
    /// no version of this carries who voted for what.
    #[must_use]
    pub fn forum_poll(&self, thread: u32) -> Option<Poll> {
        self.forum_polls
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
        self.forum_polls
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&thread);
        self.send_request(&ServerMessagesEncrypted::ForumThreadClose { thread }.to_vec())
            .await
    }

    /// Start a new thread, optionally with a poll attached. When `sign` is set,
    /// the body is signed with this client's identity key.
    ///
    /// A poll can only be attached here, as the thread is started, and its
    /// terms are fixed from that moment.
    ///
    /// # Errors
    ///
    /// Returns an error if a poll is given and it is not a poll the server
    /// would accept. Network errors are possible.
    pub async fn new_forum_thread(
        &self,
        topic: u32,
        subject: String,
        body: String,
        markdown: bool,
        sign: bool,
        poll: Option<NewPoll>,
    ) -> Result<()> {
        if let Some(poll) = &poll {
            poll.validate()?;
        }
        let signature = sign.then(|| ForumSignature::sign(&self.signing_key, &body));
        self.send_request(
            &ServerMessagesEncrypted::ForumNewThread(NewForumThread {
                topic,
                subject,
                body,
                markdown,
                signature,
                poll,
            })
            .to_vec(),
        )
        .await
    }

    /// Cast a ballot in a thread's poll: one option, or several when the poll
    /// is multiple-choice.
    ///
    /// A vote cannot be taken back or changed. Nothing records which option an
    /// identity chose — only that it voted — so there would be nothing to
    /// undo. The updated poll arrives as an ordinary poll update.
    ///
    /// # Errors
    ///
    /// Network errors are possible. The server reports a closed poll, a second
    /// ballot or a malformed one as an error message rather than here.
    pub async fn vote_forum_poll(&self, poll: u32, options: Vec<u32>) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::ForumPollVote(PollVote { poll, options }).to_vec(),
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

    /// The server's banner image (a PNG), as last reported by the server.
    #[inline]
    #[must_use]
    pub fn server_banner(&self) -> Option<Vec<u8>> {
        self.server_banner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// (Admin) Set or clear the server's banner image.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    #[inline]
    pub async fn admin_set_server_banner(&self, banner: Option<Vec<u8>>) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetServerBanner(banner),
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

    /// (Admin) Set whether anonymous (guest) users may connect to the server.
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn admin_set_allow_anonymous(&self, allow: bool) -> Result<()> {
        self.send_request(
            &ServerMessagesEncrypted::AdministrativeRequest(
                ServerAdminMessagesEncrypted::SetAllowAnonymous(allow),
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
