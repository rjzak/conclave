// SPDX-License-Identifier: Apache-2.0

use conclave_common::net::{DefaultEncryptedStream, EncryptedWrite};
use conclave_common::server::{
    AdminUser, ClientMessagesEncrypted, ConnectedUser, ServerInformation, ServerMessagesEncrypted,
};
use std::ops::Not;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration, Local};
use conclave_common::admin::server::{CreateUser, ServerAdminMessagesEncrypted, Tracker};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Maximum time to wait for a request to be written to the server. A stalled or
/// half-open socket would otherwise hold the connection's write lock forever.
const SEND_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);

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

    /// Display name shown for the user on this server
    pub(crate) display_name: Arc<RwLock<String>>,

    /// Whether the authenticated user is an administrator (from `SessionInfo`).
    pub(crate) is_admin: Arc<AtomicBool>,

    /// Latest administrative user list (populated for admins on request).
    pub(crate) admin_users: Arc<std::sync::RwLock<Vec<AdminUser>>>,

    /// Latest administrative tracker list (populated for admins on request).
    pub(crate) admin_trackers: Arc<std::sync::RwLock<Vec<(String, u16)>>>,

    /// Most recent administrative action error, if any.
    pub(crate) admin_error: Arc<std::sync::RwLock<Option<String>>>,

    /// Join handle for the task which listens for messages from the server
    pub(crate) listen_handle: Arc<JoinHandle<()>>,

    /// When the connection was established
    pub(crate) connection_time: DateTime<Local>,
}

impl ConclaveConnection {
    /// Create a connection object
    pub fn new(conn: DefaultEncryptedStream, info: ServerInformation, display_name: &str) -> Self {
        let (mut read, write) = conn.into_split();
        let server_info = Arc::new(std::sync::RwLock::new(info));
        let connected_users = Arc::new(std::sync::RwLock::new(Vec::new()));

        let mut conn = ConclaveConnection {
            connection: Arc::new(RwLock::new(write)),
            server_info: server_info.clone(),
            connected_users: connected_users.clone(),
            display_name: Arc::new(RwLock::new(display_name.to_string())),
            is_admin: Arc::new(AtomicBool::new(false)),
            admin_users: Arc::new(std::sync::RwLock::new(Vec::new())),
            admin_trackers: Arc::new(std::sync::RwLock::new(Vec::new())),
            admin_error: Arc::new(std::sync::RwLock::new(None)),
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
                    ClientMessagesEncrypted::SessionInfo { admin, .. } => {
                        conn_clone.is_admin.store(admin, Ordering::SeqCst);
                    }
                    ClientMessagesEncrypted::AdminUsersResponse(users) => {
                        *conn_clone
                            .admin_users
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = users;
                    }
                    ClientMessagesEncrypted::AdminTrackersResponse(trackers) => {
                        *conn_clone
                            .admin_trackers
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = trackers;
                    }
                    ClientMessagesEncrypted::AdminActionOk => {
                        *conn_clone
                            .admin_error
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                    }
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

    /// Update server information
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn update_server_info(&self) -> Result<()> {
        let request = ServerMessagesEncrypted::ServerInformationRequest.to_vec();
        self.send_request(&request).await
    }

    /// Get a copy of the server information. Synchronous: callable directly from
    /// the GUI render thread without blocking on the async runtime.
    #[must_use]
    pub fn server_info(&self) -> ServerInformation {
        self.server_info
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Get users connected to the server
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn update_connected_users(&self) -> Result<()> {
        let request = ServerMessagesEncrypted::ListConnectedUsersRequest.to_vec();
        self.send_request(&request).await
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

    /// The most recently received administrative tracker list.
    #[must_use]
    pub fn admin_trackers(&self) -> Vec<(String, u16)> {
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

    /// (Admin) Create a user account, optionally granting administrator rights.
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
