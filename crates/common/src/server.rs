// SPDX-License-Identifier: Apache-2.0

use crate::admin::server::{ClientAdminMessagesEncrypted, ServerAdminMessagesEncrypted};
use crate::files::FileEntry;

use chrono::{DateTime, Duration, Utc};
pub use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Response to protocol handshake
pub const RESPONSE: &[u8] = b"Server";

/// Protocol for getting the server's public key
pub mod unencrypted {
    use anyhow::{Result, anyhow};
    use ed25519_dalek::VerifyingKey;
    use semver::Version;
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Unencrypted messages to the server
    #[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
    pub enum ClientToServer {
        /// Request the server's public key
        KeyRequest,

        /// Request the server's version
        VersionRequest,

        /// Switch to encrypted connection
        GoCrypto,
    }

    impl ClientToServer {
        /// Send the message to the server
        ///
        /// # Errors
        ///
        /// Networking errors are possible
        #[inline]
        pub async fn send(&self, stream: &mut TcpStream) -> Result<()> {
            let bytes = postcard::to_stdvec(&self)?;
            stream.write_u32(u32::try_from(bytes.len())?).await?;
            stream.write_all(&bytes).await?;

            Ok(())
        }

        /// Receive a message from the server
        ///
        /// # Errors
        ///
        /// Networking errors are possible
        #[inline]
        pub async fn receive(stream: &mut TcpStream) -> Result<Self> {
            let len = stream.read_u32().await?;
            let mut bytes = vec![0u8; len as usize];
            stream.read_exact(&mut bytes).await?;

            postcard::from_bytes(&bytes).map_err(|e| anyhow!("Failed to deserialize message: {e}"))
        }
    }

    /// Unencrypted messages from the server
    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
    pub enum ServerToClient {
        /// Server's public key
        PublicKey(VerifyingKey),

        /// Server's version
        Version(Version),
    }

    impl ServerToClient {
        /// Send the message to the client
        ///
        /// # Errors
        ///
        /// Networking errors are possible
        #[inline]
        pub async fn send(&self, stream: &mut TcpStream) -> Result<()> {
            let bytes = postcard::to_stdvec(&self)?;
            stream.write_u32(u32::try_from(bytes.len())?).await?;
            stream.write_all(&bytes).await?;

            Ok(())
        }

        /// Receive a message from the client
        ///
        /// # Errors
        ///
        /// Networking errors are possible
        #[inline]
        pub async fn receive(stream: &mut TcpStream) -> Result<Self> {
            let len = stream.read_u32().await?;
            let mut bytes = vec![0u8; len as usize];
            stream.read_exact(&mut bytes).await?;

            postcard::from_bytes(&bytes).map_err(|e| anyhow!("Failed to deserialize message: {e}"))
        }
    }
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

    /// Whether chat is enabled on the server
    pub chat_enabled: bool,

    /// Whether the server exposes a shared file directory
    pub sharing_enabled: bool,
}

/// A chatroom the user is allowed to see and join.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChatroomInfo {
    /// Database id of the chatroom
    pub id: u16,

    /// Chatroom name
    pub name: String,
}

/// Activity within a chatroom, pushed to its members. History is not preserved,
/// so these are only delivered live to members present at the time.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ChatEvent {
    /// A user joined the room.
    Joined {
        /// Chatroom id
        room: u16,
        /// Joining user's display name
        display_name: String,
    },

    /// A user left the room.
    Left {
        /// Chatroom id
        room: u16,
        /// Leaving user's display name
        display_name: String,
    },

    /// A user posted a message.
    Message {
        /// Chatroom id
        room: u16,
        /// Author's display name
        display_name: String,
        /// Message text
        message: String,
        /// When the server received the message (UTC)
        at: DateTime<Utc>,
    },
}

/// User authentication
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct UserAuthentication {
    /// User name
    pub username: String,

    /// Password
    pub password: String,
}

impl std::fmt::Debug for UserAuthentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserAuthentication({})", self.username)
    }
}

impl From<(String, String)> for UserAuthentication {
    fn from((username, password): (String, String)) -> Self {
        Self { username, password }
    }
}

impl From<(&str, &str)> for UserAuthentication {
    fn from((username, password): (&str, &str)) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

/// Minutes of inactivity after which a user is considered idle (and their name
/// is greyed out in the clients).
pub const IDLE_TIMEOUT_MINUTES: Duration = Duration::minutes(30);

/// Information about a connected user
#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct ConnectedUser {
    /// Opaque handle for this connection, used to request more details about the
    /// user or (for administrators) to kick them.
    pub id: u16,

    /// Display name of the user which might be different from their username
    pub display_name: String,

    /// Whether the user is an administrator
    pub admin: bool,

    /// Time since the user connected
    pub connected_since: Duration,

    /// Time since the user was last active (sent anything but a keep-alive).
    pub idle: Duration,

    /// Name colour, mixed from the user's groups' colours (`None` if the user
    /// belongs to no coloured groups).
    pub color: Option<[u8; 3]>,

    /// User's ID, if authenticated.
    pub user_id: Option<u32>,

    /// The user's ed25519 identity public key (compressed), if they connected
    /// with one. Lets other users end-to-end encrypt direct messages to them.
    pub public_key: Option<[u8; 32]>,

    /// The user's timezone as whole hours relative to GMT (e.g. `-5`, `2`), if
    /// shared. Other users compute the difference against their own.
    pub timezone: Option<i16>,
}

/// Extra, on-demand information about a connected user. The base fields (display
/// name, connection duration, timezone) are already carried by [`ConnectedUser`];
/// this holds what requires a lookup or elevated privileges.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserDetails {
    /// Connection handle this refers to (matches [`ConnectedUser::connection_id`]).
    pub connection_id: u16,

    /// Groups the user belongs to (empty for unauthenticated guests).
    pub groups: Vec<String>,

    /// The user's login name. Only populated for administrators viewing an
    /// authenticated user.
    pub username: Option<String>,

    /// The user's IP address. Only populated for administrators.
    pub ip: Option<String>,
}

/// Client to Server messages for encrypted connections
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ServerMessagesEncrypted {
    /// Ask the server for information about itself
    ServerInformationRequest,

    /// User tries to authenticate
    /// Send the display name and the optional timezone offset and authentication message
    /// Server responds with Server Information if successful
    ServerAuthenticationRequest((String, Option<i16>, Option<UserAuthentication>)),

    /// Ask the server for a list of connected users
    ListConnectedUsersRequest,

    /// Ask the server for extra details about a connected user, by connection id.
    UserDetailsRequest(u16),

    /// Ask the server for the chatrooms this user may access.
    ChatRoomsRequest,

    /// Join a chatroom by id (the server replies with the current member list).
    ChatJoin(u16),

    /// Leave a chatroom by id.
    ChatLeave(u16),

    /// Post a message to a chatroom.
    ChatSend {
        /// Chatroom id
        room: u16,
        /// Message text
        message: String,
    },

    /// List a shared directory. `path` is relative to the share root, using `/`
    /// separators; an empty string is the root.
    FileListRequest {
        /// Directory path relative to the share root
        path: String,
    },

    /// Download a shared file. `path` is relative to the share root.
    FileDownloadRequest {
        /// File path relative to the share root
        path: String,
    },

    /// Begin uploading a file to `path` (relative to the share root). The server
    /// replies with [`ClientMessagesEncrypted::FileUploadReady`] or an error;
    /// chunks and [`ServerMessagesEncrypted::FileUploadEnd`] follow.
    FileUploadRequest {
        /// Destination path relative to the share root
        path: String,
        /// Total size of the upload in bytes
        size: u64,
    },

    /// A chunk of the file currently uploading, in order.
    FileUploadChunk {
        /// Raw file bytes
        data: Vec<u8>,
    },

    /// Marks the end of the current upload; the server finalizes the file.
    FileUploadEnd,

    /// Delete a shared file or empty directory (relative to the share root).
    FileDeleteRequest {
        /// Path relative to the share root
        path: String,
    },

    /// Send a direct message to another connected user, by connection id. The
    /// server relays `payload` verbatim without inspecting it; when `encrypted`
    /// is set it is end-to-end ciphertext the server cannot read.
    DirectMessage {
        /// Recipient's connection id
        to: u16,
        /// Whether `payload` is end-to-end encrypted
        encrypted: bool,
        /// Message bytes (UTF-8 plaintext, or [`crate::dm`] ciphertext)
        payload: Vec<u8>,
    },

    /// Do nothing message to keep the connection alive.
    KeepAlive,

    /// Drop the connection.
    Disconnect,

    /// Container for administrative requests.
    AdministrativeRequest(ServerAdminMessagesEncrypted),
}

impl ServerMessagesEncrypted {
    /// Serialize with Postcard.
    ///
    /// # Panics
    ///
    /// A panic should be impossible.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn to_vec(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("`ServerMessagesEncrypted` failed to serialize")
    }

    /// Deserialize with Postcard.
    ///
    /// # Errors
    ///
    /// Postcard error is the data isn't valid or complete.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

/// Server to Client messages for encrypted connections
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ClientMessagesEncrypted {
    /// Server's response with information about itself
    ServerInformationResponse(ServerInformation),

    /// Receive a list of connected users
    ListConnectedUsersResponse(Vec<ConnectedUser>),

    /// Extra details about a connected user, or `None` if that user is no longer
    /// connected.
    UserDetailsResponse(Option<UserDetails>),

    /// Server error response
    Error(ServerError),

    /// Do nothing message to keep the connection alive.
    KeepAlive,

    /// Drop the connection.
    Disconnect,

    /// Sent right after a successful authentication so the client knows who it
    /// is connected as and whether it holds administrator rights.
    SessionInfo {
        /// Authenticated user id, or `None` for an anonymous guest
        user_id: Option<u32>,
        /// Whether the authenticated user is an administrator
        admin: bool,
    },

    /// The chatrooms this user may access (or empty if chat is disabled).
    ChatRoomsResponse(Vec<ChatroomInfo>),

    /// Sent to a user who joined a chatroom: the room id and the display names of
    /// the members currently present.
    ChatJoined {
        /// Chatroom id
        room: u16,
        /// Display names of the members currently in the room
        users: Vec<String>,
    },

    /// Live activity within a chatroom the user is a member of.
    ChatActivity(ChatEvent),

    /// A shared-directory listing.
    FileListResponse {
        /// Directory path relative to the share root that was listed
        path: String,
        /// The directory's entries (excluding hidden ACL files)
        entries: Vec<FileEntry>,
    },

    /// Marks the start of a file download; chunks follow in order, then
    /// [`ClientMessagesEncrypted::FileDownloadEnd`].
    FileDownloadBegin {
        /// File path relative to the share root
        path: String,
        /// Total size of the file in bytes
        size: u64,
    },

    /// A chunk of the file currently downloading, delivered in order.
    FileDownloadChunk {
        /// Raw file bytes
        data: Vec<u8>,
    },

    /// Marks the end of the current file download.
    FileDownloadEnd,

    /// The server accepted an upload request; the client may stream chunks.
    FileUploadReady,

    /// The server finalized an upload successfully.
    FileUploadComplete,

    /// A direct message relayed from another connected user.
    DirectMessageReceived {
        /// Sender's connection id
        from: u16,
        /// Sender's display name
        from_display_name: String,
        /// Whether `payload` is end-to-end encrypted
        encrypted: bool,
        /// Message bytes (UTF-8 plaintext, or [`crate::dm`] ciphertext)
        payload: Vec<u8>,
    },

    /// Container for administrative responses.
    AdministrativeResponse(ClientAdminMessagesEncrypted),
}

impl ClientMessagesEncrypted {
    /// Serialize with Postcard.
    ///
    /// # Panics
    ///
    /// A panic should be impossible.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn to_vec(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("`ClientMessagesEncrypted` failed to serialize")
    }

    /// Deserialize with Postcard.
    ///
    /// # Errors
    ///
    /// Postcard error is the data isn't valid or complete.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

/// Server error responses
#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub enum ServerError {
    /// Authentication was incorrect
    AuthenticationFailed,

    /// No authentication provided when this is required
    AuthenticationRequired,

    /// The action requires administrator privileges
    NotAuthorized,

    /// The maximum number of clients has been reached
    AtCapacity,

    /// An administrative action failed; the string carries a human-readable reason
    ActionFailed(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::AuthenticationFailed => write!(f, "Authentication failed"),
            ServerError::AuthenticationRequired => write!(f, "Authentication required"),
            ServerError::NotAuthorized => write!(f, "Administrator privileges required"),
            ServerError::AtCapacity => write!(f, "Server at capacity"),
            ServerError::ActionFailed(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for ServerError {}
