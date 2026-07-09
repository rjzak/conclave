// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

mod files;

use conclave_common::URL_PROTOCOL;
use conclave_common::admin::server::{
    AdminUser, Chatroom, ClientAdminMessagesEncrypted, CreateGroup, Group,
    ServerAdminMessagesEncrypted, is_reserved_red,
};
use conclave_common::net::{
    DEFAULT_REKEY_INTERVAL, DefaultEncryptedStream, EncryptedRead, EncryptedWrite, random_keypair,
};
use conclave_common::server::{
    ChatEvent, ChatroomInfo, ClientMessagesEncrypted, ConnectedUser, IDLE_TIMEOUT_MINUTES,
    ServerError, ServerInformation, ServerMessagesEncrypted, UserAuthentication, UserDetails,
    unencrypted,
};
use conclave_common::tracker::TrackerProtocol::AdvertiseServer;
use conclave_common::tracker::{Advertise, Tracker, TrackerWithKey};

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow, ensure};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_sqlite::rusqlite::fallible_iterator::FallibleIterator;
use async_sqlite::rusqlite::{Batch, Connection, OptionalExtension, params};
use async_sqlite::{Client, ClientBuilder, JournalMode};
use chrono::{DateTime, Duration, Local, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use semver::Version;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, RwLock};
use tracing::{error, info, trace, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Default config file name.
pub const DEFAULT_DATABASE: &str = "server.db";

const SCHEMA: &str = include_str!("schema.sql");

/// Conclave version
pub static VERSION: LazyLock<Version> =
    LazyLock::new(|| Version::parse(env!("CONCLAVE_VERSION")).unwrap());

/// Client connection
struct ClientConnection {
    /// Opaque, server-assigned handle for this connection.
    connection_id: u16,

    /// Write half of the encrypted connection to the client. The read half is
    /// owned by the per-client task spawned in [`State::serve`].
    conn: Arc<RwLock<EncryptedWrite<DEFAULT_REKEY_INTERVAL>>>,

    /// User information
    user: Arc<ConnectedUser>,

    /// Client's address
    addr: Arc<SocketAddr>,

    /// When the connection was established, for computing its duration.
    connected_at: DateTime<Utc>,

    /// Unix timestamp (seconds) of the user's last activity, for computing idle
    /// time. Shared so the per-client task can update it as messages arrive.
    last_active: Arc<AtomicI64>,

    /// Fired to kick this connection: the per-client task stops reading and the
    /// connection is torn down.
    cancel: Arc<Notify>,
}

impl Clone for ClientConnection {
    fn clone(&self) -> Self {
        Self {
            connection_id: self.connection_id,
            conn: self.conn.clone(),
            user: self.user.clone(),
            addr: self.addr.clone(),
            connected_at: self.connected_at,
            last_active: self.last_active.clone(),
            cancel: self.cancel.clone(),
        }
    }
}

impl std::fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let user = (*self.user).clone().display_name;
        write!(f, "ClientConnection: {user}@{:?}", self.addr)
    }
}

/// Server state
#[derive(Clone)]
pub struct State {
    /// Server name (admin-editable at runtime; `std` lock so it can be read from
    /// both sync and async contexts without blocking the runtime)
    name: Arc<std::sync::RwLock<String>>,

    /// Server description (admin-editable at runtime)
    description: Arc<std::sync::RwLock<String>>,

    /// Advertised URL
    url: String,

    /// Listening IP
    ip: IpAddr,

    /// Server port
    port: u16,

    /// When the server started
    started: DateTime<Utc>,

    /// Public key for verification
    public_key: VerifyingKey,

    /// Private key for signing
    private_key: SigningKey,

    /// SQL Lite client
    sqlite: Client,

    /// Trackers
    trackers: Arc<RwLock<Vec<TrackerWithKey>>>,

    /// Trackers we currently hold a persistent advertising connection to, so we
    /// don't start a second task for the same tracker.
    advertising: Arc<RwLock<std::collections::HashSet<TrackerWithKey>>>,

    /// Bumped whenever advertised information changes (name, description, guest
    /// policy, connected-user count) so the advertising tasks re-send at once.
    tracker_update: Arc<tokio::sync::watch::Sender<u64>>,

    /// Active connections
    connections: Arc<RwLock<Vec<ClientConnection>>>,

    /// Total visitors
    total_visits: Arc<AtomicU32>,

    /// Source of unique per-connection ids.
    next_connection_id: Arc<AtomicU16>,

    /// Whether anonymous connections are allowed
    allow_anonymous: Arc<AtomicBool>,

    /// Whether chat is enabled on the server
    chat_enabled: Arc<AtomicBool>,

    /// Chatroom membership: room id -> the connection ids currently present.
    chat_members: Arc<RwLock<HashMap<u16, HashSet<u16>>>>,

    /// Whether the server is currently serving requests
    serving: Arc<AtomicBool>,

    /// Advertising via Multicast DNS
    mdns: Option<ServiceDaemon>,

    /// Root of the optional shared file directory, canonicalized; `None` when
    /// the server is not sharing files.
    share_directory: Option<PathBuf>,

    /// Optional maximum accepted upload size, in bytes. `-1` means uncapped;
    /// stored as an atomic so admins can change it at runtime.
    max_upload_size: Arc<AtomicU64>,

    /// Optional maximum number of concurrent connections. `-1` means unlimited;
    /// stored as an atomic so admins can change it at runtime.
    max_connections: Arc<AtomicU16>,

    /// Show the log window
    #[cfg(feature = "gui")]
    log: bool,

    /// Initial password
    #[cfg(feature = "gui")]
    password: Option<Arc<RwLock<Zeroizing<String>>>>,

    /// Whether the password has been acknowledged
    #[cfg(feature = "gui")]
    password_acknowledged: Arc<AtomicBool>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conclave Server: {}", self.server_name())
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let connections = futures::executor::block_on(self.connections.read()).len();
        write!(
            f,
            "Conclave Server {} with {connections} connections",
            self.server_name()
        )
    }
}

impl State {
    /// Create a new server state and also return the new admin password.
    ///
    /// # Errors
    ///
    /// An error results if the database creation fails, including inability to write to the provided file path.
    ///
    /// # Panics
    ///
    /// Panics if Multicast DNS is requested and fails to start
    pub fn new<P: AsRef<Path>>(
        name: String,
        description: String,
        ip: IpAddr,
        advertised_domain: Option<String>,
        port: u16,
        mdns: bool,
        sqlite_path: P,
    ) -> Result<(Self, Zeroizing<String>)> {
        ensure!(
            !sqlite_path.as_ref().exists(),
            "Database path already exists"
        );
        let (private_key, public_key) = random_keypair();
        let new_admin_password = Zeroizing::new(Uuid::new_v4().to_string());

        {
            let conn = Connection::open(&sqlite_path)?;
            let mut batch = Batch::new(&conn, SCHEMA);
            while let Some(mut stmt) = batch.next()? {
                stmt.execute([])?;
            }

            let private_key_string = hex::encode(private_key.to_bytes());
            let public_key_string = hex::encode(public_key.to_bytes());
            let combined_key = format!("{private_key_string}{public_key_string}");

            conn.execute(
                "INSERT INTO SERVER_CONFIG(name, description, key, version) VALUES(?1, ?2, ?3, ?4)",
                [
                    &name,
                    &description,
                    &combined_key,
                    env!("CARGO_PKG_VERSION"),
                ],
            )?;

            if let Some(advertised_domain) = &advertised_domain {
                conn.execute(
                    "UPDATE SERVER_CONFIG SET advertised_domain = ?1;",
                    [advertised_domain],
                )?;
            }

            let hashed = hash_password(&new_admin_password);
            conn.execute(
                "UPDATE USER SET password = ?1 WHERE username = 'admin'",
                [hashed],
            )?;

            #[cfg(target_family = "unix")]
            {
                use std::os::unix::fs::PermissionsExt;

                let mut perms = sqlite_path.as_ref().metadata()?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&sqlite_path, perms)?;
            }
        }

        let url = if let Some(advertised_domain) = advertised_domain {
            format!("{URL_PROTOCOL}{advertised_domain}:{port}")
        } else {
            format!("{URL_PROTOCOL}{ip}:{port}")
        };

        let sqlite = ClientBuilder::new()
            .journal_mode(JournalMode::Wal)
            .path(sqlite_path)
            .open_blocking()?;

        Ok((
            Self {
                name: Arc::new(std::sync::RwLock::new(name)),
                description: Arc::new(std::sync::RwLock::new(description)),
                url,
                ip,
                port,
                started: Local::now().to_utc(),
                public_key,
                private_key,
                sqlite,
                trackers: Arc::new(RwLock::new(Vec::new())),
                advertising: Arc::new(RwLock::new(std::collections::HashSet::new())),
                tracker_update: Arc::new(tokio::sync::watch::channel(0u64).0),
                connections: Arc::new(RwLock::new(Vec::new())),
                total_visits: Arc::new(AtomicU32::new(0)),
                next_connection_id: Arc::new(AtomicU16::new(0)),
                allow_anonymous: Arc::new(AtomicBool::new(true)), // Database default
                chat_enabled: Arc::new(AtomicBool::new(false)),   // Database default
                chat_members: Arc::new(RwLock::new(HashMap::new())),
                serving: Arc::new(AtomicBool::new(false)),
                mdns: mdns.then(|| ServiceDaemon::new().expect("Failed to start Multicast DNS")),
                share_directory: None,
                max_upload_size: Arc::new(AtomicU64::new(u64::MAX)),
                max_connections: Arc::new(AtomicU16::new(u16::MAX)),
                #[cfg(feature = "gui")]
                log: false,
                #[cfg(feature = "gui")]
                password: Some(Arc::new(RwLock::new(new_admin_password.clone()))),
                #[cfg(feature = "gui")]
                password_acknowledged: Arc::new(AtomicBool::new(false)),
            },
            new_admin_password,
        ))
    }

    /// Load a server from an existing database
    ///
    /// # Errors
    ///
    /// An error results if the database can't be read.
    ///
    /// # Panics
    ///
    /// Panics if Multicast DNS is requested and fails to start
    #[allow(clippy::too_many_lines)]
    pub fn load<P: AsRef<Path>>(ip: IpAddr, port: u16, mdns: bool, sqlite_path: P) -> Result<Self> {
        ensure!(
            sqlite_path.as_ref().exists(),
            "Database file does not exist"
        );
        ensure!(
            sqlite_path.as_ref().is_file(),
            "Database path is not a file"
        );

        let (
            name,
            description,
            private_key,
            public_key,
            url,
            trackers,
            allow_anonymous,
            chat_enabled,
            max_upload_size,
            max_connections,
        ) = {
            let conn = Connection::open(&sqlite_path)?;
            let mut stmt = conn
                .prepare("SELECT name, description, key, version, advertised_domain, allow_anonymous_clients, chat_enabled, max_upload_size, max_connections FROM SERVER_CONFIG")?;
            let (
                name,
                description,
                keypair,
                version,
                advertised_domain,
                allow_anonymous,
                chat_enabled,
                max_upload_size,
                max_connections,
            ) = stmt.query_row([], |row| {
                let name: String = row.get(0)?;
                let description: String = row.get(1)?;
                let key_string: String = row.get(2)?;
                let version: String = row.get(3)?;
                let advertised_domain: Option<String> = row.get(4)?;
                let allow_anonymous: bool = row.get(5)?;
                let chat_enabled: bool = row.get(6)?;
                let max_upload_size: Option<u64> = row.get(7)?;
                let max_connections: Option<u16> = row.get(8)?;
                Ok((
                    name,
                    description,
                    key_string,
                    version,
                    advertised_domain,
                    allow_anonymous,
                    chat_enabled,
                    max_upload_size,
                    max_connections,
                ))
            })?;

            let keypair = hex::decode(keypair)?;
            let keypair: [u8; 64] = keypair
                .try_into()
                .map_err(|_| anyhow!("Invalid keypair length"))?;

            let private_key = SigningKey::from_keypair_bytes(&keypair)
                .map_err(|_| anyhow!("Invalid private key"))?;
            let public_key = private_key.verifying_key();

            let trackers = {
                let mut stmt =
                    conn.prepare("SELECT host, port, key FROM TRACKER WHERE enabled = true;")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, u16>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<async_sqlite::rusqlite::Result<Vec<(String, u16, String)>>>()?;
                rows.into_iter()
                    .map(TrackerWithKey::from)
                    .collect::<Vec<TrackerWithKey>>()
            };

            let database_version = Version::parse(&version)?;
            let binary_version = Version::parse(env!("CARGO_PKG_VERSION"))?;
            if binary_version > database_version {
                warn!(
                    "Binary version {binary_version} is newer than database version {database_version}"
                );
            }

            if database_version > binary_version {
                warn!(
                    "Database version {database_version} is newer than binary version {binary_version}"
                );
            }

            let url = if let Some(advertised_domain) = advertised_domain {
                format!("{URL_PROTOCOL}{advertised_domain}:{port}")
            } else {
                format!("{URL_PROTOCOL}{ip}:{port}")
            };

            (
                name,
                description,
                private_key,
                public_key,
                url,
                trackers,
                allow_anonymous,
                chat_enabled,
                max_upload_size,
                max_connections,
            )
        };

        let sqlite = ClientBuilder::new()
            .journal_mode(JournalMode::Wal)
            .path(sqlite_path)
            .open_blocking()?;

        Ok(Self {
            name: Arc::new(std::sync::RwLock::new(name)),
            description: Arc::new(std::sync::RwLock::new(description)),
            url,
            ip,
            port,
            started: Local::now().to_utc(),
            public_key,
            private_key,
            sqlite,
            trackers: Arc::new(RwLock::new(trackers)),
            advertising: Arc::new(RwLock::new(std::collections::HashSet::new())),
            tracker_update: Arc::new(tokio::sync::watch::channel(0u64).0),
            connections: Arc::new(RwLock::new(Vec::new())),
            total_visits: Arc::new(AtomicU32::new(0)),
            next_connection_id: Arc::new(AtomicU16::new(0)),
            allow_anonymous: Arc::new(AtomicBool::new(allow_anonymous)),
            chat_enabled: Arc::new(AtomicBool::new(chat_enabled)),
            chat_members: Arc::new(RwLock::new(HashMap::new())),
            serving: Arc::new(AtomicBool::new(false)),
            mdns: mdns.then(|| ServiceDaemon::new().expect("Failed to start Multicast DNS")),
            share_directory: None,
            max_upload_size: Arc::new(AtomicU64::new(max_upload_size.unwrap_or(u64::MAX))),
            max_connections: Arc::new(AtomicU16::new(max_connections.unwrap_or(u16::MAX))),
            #[cfg(feature = "gui")]
            log: false,
            #[cfg(feature = "gui")]
            password: None,
            #[cfg(feature = "gui")]
            password_acknowledged: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Set the shared file directory (builder-style). The path is canonicalized;
    /// if it does not resolve to an existing directory, file sharing stays off
    /// and a warning is logged. Call before the state is cloned/served.
    #[must_use]
    pub fn with_share_directory(mut self, dir: Option<PathBuf>) -> Self {
        self.share_directory = match dir {
            Some(dir) => match std::fs::canonicalize(&dir) {
                Ok(canonical) if canonical.is_dir() => {
                    info!("Sharing files from {}", canonical.display());
                    Some(canonical)
                }
                Ok(_) => {
                    warn!(
                        "Share path {} is not a directory; file sharing disabled",
                        dir.display()
                    );
                    None
                }
                Err(e) => {
                    warn!(
                        "Cannot use share path {}: {e}; file sharing disabled",
                        dir.display()
                    );
                    None
                }
            },
            None => None,
        };
        self
    }

    /// The current maximum accepted upload size in bytes, or `None` if uncapped.
    fn max_upload_size(&self) -> Option<u64> {
        let value = self.max_upload_size.load(Ordering::Relaxed);
        if value == u64::MAX { None } else { Some(value) }
    }

    /// The current maximum number of concurrent connections, or `None` if
    /// unlimited.
    fn max_connections(&self) -> Option<u16> {
        let value = self.max_connections.load(Ordering::Relaxed);
        if value == u16::MAX { None } else { Some(value) }
    }

    /// Set the maximum accepted upload size in bytes, persisting it to the
    /// database. `None` removes the cap (stores SQL NULL).
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn set_max_upload_size(&self, max: Option<u64>) -> Result<()> {
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "UPDATE SERVER_CONFIG SET max_upload_size = ?1;",
                    params![max],
                )
            })
            .await?;
        self.max_upload_size
            .store(max.unwrap_or(u64::MAX), Ordering::Relaxed);
        Ok(())
    }

    /// Set the maximum number of concurrent connections, persisting it to the
    /// database. `None` removes the limit (stores SQL NULL).
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn set_max_connections(&self, max: Option<u16>) -> Result<()> {
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "UPDATE SERVER_CONFIG SET max_connections = ?1;",
                    params![max],
                )
            })
            .await?;
        self.max_connections
            .store(max.unwrap_or(u16::MAX), Ordering::Relaxed);
        Ok(())
    }

    /// Returns the number of total visitors
    #[inline]
    #[must_use]
    pub fn visitors(&self) -> u32 {
        self.total_visits.load(Ordering::Relaxed)
    }

    /// Returns duration since the server started
    #[inline]
    #[must_use]
    pub fn since(&self) -> Duration {
        Local::now().to_utc() - self.started
    }

    /// Reset the admin password
    ///
    /// # Errors
    ///
    /// Might return an SQL error if the database update fails.
    pub async fn reset_admin_password(&self, new_password: &str) -> Result<()> {
        let hashed = hash_password(new_password);
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "UPDATE USER SET password = ?1 WHERE username = 'admin'",
                    [hashed],
                )
            })
            .await?;
        Ok(())
    }

    /// Whether anonymous clients are allowed to connect to the server.
    ///
    /// # Errors
    ///
    /// Database errors can occur if the query fails.
    #[inline]
    #[must_use]
    pub fn anonymous_clients_allowed(&self) -> bool {
        self.allow_anonymous.load(Ordering::Relaxed)
    }

    /// Enable or disable anonymous client connections
    ///
    /// # Errors
    ///
    /// Database errors can occur if the query fails.
    pub async fn anonymous_clients_enabled(&self, anon: bool) -> Result<()> {
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "UPDATE SERVER_CONFIG SET allow_anonymous_clients = ?1;",
                    [anon],
                )
            })
            .await?;
        self.allow_anonymous.store(anon, Ordering::Relaxed);
        self.notify_trackers();
        Ok(())
    }

    /// Authenticate a user, returns the user's ID and whether they belong to the
    /// administrators group if authenticated.
    ///
    /// # Errors
    ///
    /// Errors result if the password is incorrect, of the user doesn't have a password or doesn't exist,
    /// or if there's a database error.
    pub async fn authenticate_user(&self, auth: UserAuthentication) -> Result<(u32, bool)> {
        let auth_clone = auth.clone();
        let (id, db_password, admin) = self
            .sqlite
            .conn(move |conn| {
                conn.query_one(
                    "SELECT u.id, u.password, \
                     EXISTS(SELECT 1 FROM USERGROUP ug JOIN GRP g ON ug.gid = g.id \
                            WHERE ug.uid = u.id AND g.name = 'admin') AS admin \
                     FROM USER u WHERE u.username = ?1;",
                    [&auth_clone.username],
                    |row| {
                        let id: i32 = row.get(0)?;
                        let password: String = row.get(1)?;
                        let admin: bool = row.get(2)?;
                        Ok((id, password, admin))
                    },
                )
            })
            .await?;

        let password_hashed = PasswordHash::new(&db_password)?;
        Argon2::default().verify_password(auth.password.as_ref(), &password_hashed)?;

        Ok((u32::try_from(id)?, admin || id == 0))
    }

    /// The server's current display name.
    #[must_use]
    pub fn server_name(&self) -> String {
        self.name
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The server's current description.
    #[must_use]
    pub fn server_description(&self) -> String {
        self.description
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// (Admin) Set the server's display name and persist it.
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn set_server_name(&self, name: String) -> Result<()> {
        name.clone_into(
            &mut self
                .name
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        self.sqlite
            .conn(move |conn| conn.execute("UPDATE SERVER_CONFIG SET name = ?1", [name]))
            .await?;
        self.broadcast_server_info().await;
        self.notify_trackers();
        Ok(())
    }

    /// (Admin) Set the server's description and persist it.
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn set_server_description(&self, description: String) -> Result<()> {
        description.clone_into(
            &mut self
                .description
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        self.sqlite
            .conn(move |conn| {
                conn.execute("UPDATE SERVER_CONFIG SET description = ?1", [description])
            })
            .await?;
        self.broadcast_server_info().await;
        self.notify_trackers();
        Ok(())
    }

    /// (Admin) List all user accounts.
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    ///
    /// # Panics
    ///
    /// Despite the call to `unwrap()`, a panic is not possible as the same variable used for
    /// insertion is then used for retrieval.
    pub async fn admin_list_users(&self) -> Result<Vec<AdminUser>> {
        let rows = self
            .sqlite
            .conn(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, username, (password IS NOT NULL) AS enabled, readonly, created \
                    FROM USER ORDER BY id;",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, u32>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, bool>(2)?,
                            row.get::<_, bool>(3)?,
                            row.get::<_, DateTime<Utc>>(4)?,
                        ))
                    })?
                    .collect::<async_sqlite::rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await?;

        let mut groups_map = HashMap::new();
        for row in &rows {
            let id = row.0;
            let groups = self.user_groups(id).await?;
            groups_map.insert(id, groups);
        }

        Ok(rows
            .into_iter()
            .map(|(id, username, enabled, readonly, created)| {
                let groups = groups_map.get(&id).unwrap().to_owned();
                let admin = groups.contains(&"admin".to_string());
                AdminUser {
                    id,
                    username,
                    admin,
                    enabled,
                    readonly,
                    created,
                    groups,
                }
            })
            .collect())
    }

    /// (Admin) Create a user account and grant its initial group memberships.
    ///
    /// # Errors
    ///
    /// Returns an error if the username already exists, a named group does not
    /// exist, or on a database failure.
    pub async fn create_user_admin(
        &self,
        username: String,
        password: &str,
        groups: Vec<String>,
    ) -> Result<()> {
        let uid = self.create_user(username.clone(), password).await?;
        for group in groups {
            let gid = self.group_id(&group).await?;
            self.add_user_to_group(uid, gid).await?;
        }
        Ok(())
    }

    /// (Admin) The groups a user account may belong to.
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn admin_list_groups(&self) -> Result<Vec<Group>> {
        let groups = self
            .sqlite
            .conn(move |conn| {
                let mut statement =
                    conn.prepare("SELECT id, name, description, color FROM GRP ORDER BY name;")?;
                statement
                    .query_map([], |row| {
                        Ok(Group {
                            id: row.get::<_, u32>(0)?,
                            name: row.get::<_, String>(1)?,
                            description: row.get::<_, Option<String>>(2)?,
                            color: row.get::<_, Option<i64>>(3)?.map(color_from_db),
                        })
                    })?
                    .collect::<async_sqlite::rusqlite::Result<Vec<_>>>()
            })
            .await?;
        Ok(groups)
    }

    /// (Admin) Create a group. Red is reserved for the built-in admin group, so
    /// a red colour is rejected here.
    ///
    /// # Errors
    ///
    /// Returns an error on an empty/duplicate name, a reserved-red colour, or a
    /// database failure.
    pub async fn create_group(
        &self,
        name: String,
        description: Option<String>,
        color: Option<[u8; 3]>,
    ) -> Result<()> {
        ensure!(!name.trim().is_empty(), "Group name cannot be empty");
        ensure!(
            !color.is_some_and(is_reserved_red),
            "Red is reserved for the admin group"
        );
        let color_db = color.map(color_to_db);
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "INSERT INTO GRP(name, description, color) VALUES(?1, ?2, ?3);",
                    params![name, description, color_db],
                )
            })
            .await?;
        Ok(())
    }

    /// (Admin) Rename a group and set its description and colour. The built-in
    /// admin group (id 0) keeps its name; only it may be red.
    ///
    /// # Errors
    ///
    /// Returns an error on an empty name, a reserved-red colour on a non-admin
    /// group, or a database failure.
    pub async fn edit_group(
        &self,
        id: u32,
        name: String,
        description: Option<String>,
        color: Option<[u8; 3]>,
    ) -> Result<()> {
        ensure!(!name.trim().is_empty(), "Group name cannot be empty");
        // Only the admin group (id 0) may be red.
        ensure!(
            id == 0 || !color.is_some_and(is_reserved_red),
            "Red is reserved for the admin group"
        );
        // Don't let the admin group be renamed; admin detection relies on it.
        let name = if id == 0 { "admin".to_string() } else { name };
        let color_db = color.map(color_to_db);
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "UPDATE GRP SET name = ?1, description = ?2, color = ?3 WHERE id = ?4;",
                    params![name, description, color_db, id],
                )
            })
            .await?;
        self.refresh_user_colors().await;
        Ok(())
    }

    /// (Admin) Delete a group by id. The built-in admin group (id 0) cannot be
    /// deleted. Removes the group's memberships and chatroom restrictions too.
    ///
    /// # Errors
    ///
    /// Returns an error when deleting the admin group or on a database failure.
    pub async fn delete_group(&self, id: u32) -> Result<()> {
        ensure!(id != 0, "The admin group cannot be deleted");
        self.sqlite
            .conn(move |conn| {
                conn.execute("DELETE FROM USERGROUP WHERE gid = ?1;", [id])?;
                conn.execute("DELETE FROM CHATROOM_GROUP WHERE gid = ?1;", [id])?;
                conn.execute("DELETE FROM GRP WHERE id = ?1;", [id])
            })
            .await?;
        self.refresh_user_colors().await;
        Ok(())
    }

    /// The mixed name colour for a user: the component-wise average of the
    /// colours of the coloured groups they belong to, or `None` if none.
    async fn user_color(&self, uid: u32) -> Option<[u8; 3]> {
        let colors: Vec<i64> = self
            .sqlite
            .conn(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT g.color FROM GRP g JOIN USERGROUP ug ON ug.gid = g.id \
                     WHERE ug.uid = ?1 AND g.color IS NOT NULL;",
                )?;
                statement
                    .query_map([uid], |row| row.get::<_, i64>(0))?
                    .collect::<async_sqlite::rusqlite::Result<Vec<_>>>()
            })
            .await
            .unwrap_or_default();

        if colors.is_empty() {
            return None;
        }
        let count = i64::try_from(colors.len()).unwrap_or(1).max(1);
        let (mut r, mut g, mut b) = (0_i64, 0_i64, 0_i64);
        for color in colors {
            let [cr, cg, cb] = color_from_db(color);
            r += i64::from(cr);
            g += i64::from(cg);
            b += i64::from(cb);
        }
        let avg = |sum: i64| u8::try_from(sum / count).unwrap_or(u8::MAX);
        Some([avg(r), avg(g), avg(b)])
    }

    /// Recompute the mixed colour of every connected authenticated user and, if
    /// any changed, re-broadcast the roster. Called after group or membership
    /// changes so tinting stays current.
    async fn refresh_user_colors(&self) {
        let targets: Vec<(u16, u32)> = self
            .connections
            .read()
            .await
            .iter()
            .filter_map(|c| c.user.user_id.map(|uid| (c.connection_id, uid)))
            .collect();

        let mut new_colors: HashMap<u16, Option<[u8; 3]>> = HashMap::new();
        for (connection_id, uid) in targets {
            new_colors.insert(connection_id, self.user_color(uid).await);
        }

        let mut changed = false;
        {
            let mut connections = self.connections.write().await;
            for conn in connections.iter_mut() {
                if let Some(color) = new_colors.get(&conn.connection_id)
                    && conn.user.color != *color
                {
                    let mut updated = (*conn.user).clone();
                    updated.color = *color;
                    conn.user = Arc::new(updated);
                    changed = true;
                }
            }
        }
        if changed {
            self.broadcast_user_list().await;
        }
    }

    /// Resolve a group name to its id, erroring if no such group exists.
    async fn group_id(&self, group: &str) -> Result<u32> {
        let group_owned = group.to_string();
        let id = self
            .sqlite
            .conn(move |conn| {
                conn.query_one(
                    "SELECT id FROM GRP WHERE name = ?1;",
                    [group_owned],
                    |row| row.get::<_, u32>(0),
                )
                .optional()
            })
            .await?;
        id.ok_or_else(|| anyhow!("No such group: {group}"))
    }

    /// (Admin) Add a user account to a group by id. Adding a membership the user
    /// already has is a no-op, and an unknown group id is also a no-op (the
    /// `SELECT` yields no row to insert).
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn add_user_to_group(&self, uid: u32, gid: u32) -> Result<()> {
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO USERGROUP(uid, gid) VALUES(?1, ?2);",
                    params![uid, gid],
                )
            })
            .await?;
        self.refresh_user_colors().await;
        Ok(())
    }

    /// (Admin) Remove a user account from a group by id. The built-in `admin`
    /// account (id 0) cannot be removed from the built-in `admin` group (id 0),
    /// so the server can't be locked out of its own administration.
    ///
    /// # Errors
    ///
    /// Returns an error when removing the built-in admin from the admin group or
    /// on a database failure.
    pub async fn remove_user_from_group(&self, uid: u32, gid: u32) -> Result<()> {
        // The schema seeds both the admin user and admin group with id 0.
        ensure!(
            !(uid == 0 && gid == 0),
            "The built-in admin account cannot be removed from the admin group"
        );
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "DELETE FROM USERGROUP WHERE uid = ?1 AND gid = ?2;",
                    params![uid, gid],
                )
            })
            .await?;
        self.refresh_user_colors().await;
        Ok(())
    }

    async fn user_groups(&self, uid: u32) -> Result<Vec<String>> {
        self.sqlite
            .conn(move |conn| {
                let mut statement = conn
                    .prepare("SELECT g.name FROM GRP g JOIN USERGROUP ug ON (ug.gid = g.id) WHERE ug.uid = ?1;")?;
                statement
                    .query_map([uid], |row| row.get::<_, String>(0))?
                    .collect::<async_sqlite::rusqlite::Result<Vec<_>>>()
            })
            .await
            .map_err(Into::into)
    }

    /// Group names for a connection's requester (empty for a guest).
    async fn requester_groups(&self, user: &ConnectedUser) -> Vec<String> {
        match user.user_id {
            Some(uid) => self.user_groups(uid).await.unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Handle a shared-directory listing request, producing the reply to send.
    async fn file_list(&self, path: &str, user: &ConnectedUser) -> ClientMessagesEncrypted {
        use conclave_common::files::FilePermission;
        let Some(root) = self.share_directory.clone() else {
            return file_error("File sharing is not enabled");
        };
        let dir = match files::resolve(&root, path) {
            Ok(dir) if dir.is_dir() => dir,
            Ok(_) => return file_error("Not a directory"),
            Err(e) => return file_error(e.to_string()),
        };
        let groups = self.requester_groups(user).await;
        let allowed = user.admin
            || files::has_permission(
                &root,
                &dir,
                &groups,
                user.user_id.is_none(),
                FilePermission::List,
            );
        if !allowed {
            return ClientMessagesEncrypted::Error(ServerError::NotAuthorized);
        }
        match files::list_dir(&dir) {
            Ok(entries) => ClientMessagesEncrypted::FileListResponse {
                path: path.to_string(),
                entries,
            },
            Err(e) => file_error(e.to_string()),
        }
    }

    /// Handle a file-download request by streaming the file to the client.
    async fn file_download(
        &self,
        path: &str,
        user: &ConnectedUser,
        write: &Arc<RwLock<EncryptedWrite<DEFAULT_REKEY_INTERVAL>>>,
        addr: &SocketAddr,
    ) {
        use conclave_common::files::FilePermission;
        let Some(root) = self.share_directory.clone() else {
            reply(write, addr, &file_error("File sharing is not enabled")).await;
            return;
        };
        let file = match files::resolve(&root, path) {
            Ok(file) if file.is_file() => file,
            Ok(_) => {
                reply(write, addr, &file_error("Not a file")).await;
                return;
            }
            Err(e) => {
                reply(write, addr, &file_error(e.to_string())).await;
                return;
            }
        };
        // Read permission is checked on the file's containing directory.
        let dir = file.parent().unwrap_or(&root).to_path_buf();
        let groups = self.requester_groups(user).await;
        let allowed = user.admin
            || files::has_permission(
                &root,
                &dir,
                &groups,
                user.user_id.is_none(),
                FilePermission::Read,
            );
        if !allowed {
            reply(
                write,
                addr,
                &ClientMessagesEncrypted::Error(ServerError::NotAuthorized),
            )
            .await;
            return;
        }

        let mut handle = match std::fs::File::open(&file) {
            Ok(handle) => handle,
            Err(e) => {
                reply(write, addr, &file_error(e.to_string())).await;
                return;
            }
        };
        let size = handle.metadata().map_or(0, |m| m.len());
        let begin = ClientMessagesEncrypted::FileDownloadBegin {
            path: path.to_string(),
            size,
        };
        if write.write().await.send(&begin.to_vec()).await.is_err() {
            return;
        }
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = match std::io::Read::read(&mut handle, &mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(e) => {
                    error!("Error reading {}: {e}", file.display());
                    break;
                }
            };
            let chunk = ClientMessagesEncrypted::FileDownloadChunk {
                data: buffer[..read].to_vec(),
            };
            if write.write().await.send(&chunk.to_vec()).await.is_err() {
                return;
            }
        }
        let _ = write
            .write()
            .await
            .send(&ClientMessagesEncrypted::FileDownloadEnd.to_vec())
            .await;
    }

    /// Validate an upload request and open the temp file to receive it.
    async fn file_upload_begin(
        &self,
        path: &str,
        size: u64,
        user: &ConnectedUser,
        connection_id: u16,
    ) -> Result<Upload> {
        use conclave_common::files::FilePermission;
        let root = self
            .share_directory
            .clone()
            .ok_or_else(|| anyhow!("File sharing is not enabled"))?;
        if let Some(max) = self.max_upload_size() {
            ensure!(size <= max, "Upload exceeds the size limit of {max} bytes");
        }
        let final_path = files::resolve_target(&root, path)?;
        ensure!(
            std::fs::symlink_metadata(&final_path).is_err(),
            "A file with that name already exists"
        );
        let parent = final_path.parent().unwrap_or(&root).to_path_buf();
        let groups = self.requester_groups(user).await;
        let allowed = user.admin
            || files::has_permission(
                &root,
                &parent,
                &groups,
                user.user_id.is_none(),
                FilePermission::Write,
            );
        ensure!(allowed, "Permission denied");

        let temp_path = parent.join(format!(".conclave-upload-{connection_id}.tmp"));
        let _ = std::fs::remove_file(&temp_path);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        Ok(Upload {
            temp_path,
            final_path,
            file,
            written: 0,
            max: self.max_upload_size(),
        })
    }

    /// Delete a shared file or empty directory, returning an error reply on
    /// failure and `None` on success.
    async fn file_delete(
        &self,
        path: &str,
        user: &ConnectedUser,
    ) -> Option<ClientMessagesEncrypted> {
        use conclave_common::files::FilePermission;
        let root = self.share_directory.clone()?;
        let target = match files::resolve(&root, path) {
            Ok(target) => target,
            Err(e) => return Some(file_error(e.to_string())),
        };
        let parent = target.parent().unwrap_or(&root).to_path_buf();
        let groups = self.requester_groups(user).await;
        let allowed = user.admin
            || files::has_permission(
                &root,
                &parent,
                &groups,
                user.user_id.is_none(),
                FilePermission::Delete,
            );
        if !allowed {
            return Some(ClientMessagesEncrypted::Error(ServerError::NotAuthorized));
        }
        match files::delete(&target) {
            Ok(()) => None,
            Err(e) => Some(file_error(e.to_string())),
        }
    }

    /// (Admin) The current server-wide limits.
    #[inline]
    fn server_limits(&self) -> conclave_common::admin::server::ServerLimits {
        conclave_common::admin::server::ServerLimits {
            max_upload_size: self.max_upload_size(),
            max_connections: self.max_connections(),
        }
    }

    /// (Admin) Read-only information about the shared directory: its path and
    /// the total/available space on its filesystem.
    #[inline]
    fn share_info(&self) -> Option<conclave_common::files::ShareInfo> {
        let root = self.share_directory.as_ref()?;
        // The filesystem holding the share is the disk whose mount point is the
        // deepest prefix of the share path.
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk = disks
            .list()
            .iter()
            .filter(|disk| root.starts_with(disk.mount_point()))
            .max_by_key(|disk| disk.mount_point().as_os_str().len())?;
        Some(conclave_common::files::ShareInfo {
            path: root.display().to_string(),
            total_bytes: disk.total_space(),
            available_bytes: disk.available_space(),
        })
    }

    /// (Admin) Read a shared directory's ACL.
    #[inline]
    fn get_file_acl(&self, path: &str) -> Result<files::DirAcl> {
        let root = self
            .share_directory
            .clone()
            .ok_or_else(|| anyhow!("File sharing is not enabled"))?;
        let dir = files::resolve(&root, path)?;
        ensure!(dir.is_dir(), "Not a directory");
        Ok(files::read_acl(&dir))
    }

    /// (Admin) Replace a shared directory's ACL.
    fn set_file_acl(&self, path: &str, acl: &files::DirAcl) -> Result<()> {
        let root = self
            .share_directory
            .clone()
            .ok_or_else(|| anyhow!("File sharing is not enabled"))?;
        let dir = files::resolve(&root, path)?;
        ensure!(dir.is_dir(), "Not a directory");
        files::write_acl(&dir, acl)
    }

    /// (Admin) Delete a user account by login name. The built-in `admin`
    /// account cannot be deleted.
    ///
    /// # Errors
    ///
    /// Returns an error when deleting the built-in admin or on a database failure.
    pub async fn delete_user(&self, uid: u32) -> Result<()> {
        ensure!(uid != 0, "The built-in admin account cannot be deleted");
        self.sqlite
            .conn(move |conn| {
                conn.execute("DELETE FROM USERGROUP WHERE uid = ?1;", [&uid])?;
                conn.execute("DELETE FROM USER WHERE id = ?1;", [&uid])
            })
            .await?;
        Ok(())
    }

    /// (Admin) The configured trackers as `(host, port)` pairs.
    pub async fn list_trackers(&self) -> Vec<TrackerWithKey> {
        self.trackers.read().await.clone()
    }

    /// (Admin) Add a tracker by host and port, then persist the tracker list.
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn add_tracker_host(&self, host: String, port: u16) -> Result<()> {
        let tracker: Tracker = (host, port).into();
        if self.trackers.read().await.iter().any(|t| t == &tracker) {
            return Ok(());
        }
        // Fetch the tracker's key without holding the trackers lock.
        let tracker = tracker.as_with_key().await?;
        self.trackers.write().await.push(tracker.clone());
        // Start advertising to the new tracker right away if we're running.
        if self.serving.load(Ordering::Relaxed) {
            self.spawn_advertiser(tracker);
        }
        self.persist_trackers().await
    }

    /// (Admin) Remove a tracker by host and port, then persist the tracker list.
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn remove_tracker_host(&self, host: &str, port: u16) -> Result<()> {
        {
            let tracker: Tracker = (host, port).into();
            let mut trackers = self.trackers.write().await;
            trackers.retain(|t| t != &tracker);
        }
        self.persist_trackers().await
    }

    /// Persist the current in-memory tracker list to the database, replacing any
    /// previously stored trackers so removals are reflected.
    async fn persist_trackers(&self) -> Result<()> {
        // Snapshot the trackers first: the `conn` closure is synchronous and
        // can't await the `RwLock`.
        let rows: Vec<(String, u16, String)> = self
            .trackers
            .read()
            .await
            .iter()
            .map(|tracker| (tracker.host.clone(), tracker.port, tracker.key_as_str()))
            .collect();

        self.sqlite
            .conn(move |conn| {
                conn.execute("DELETE FROM TRACKER", [])?;
                for (host, port, key) in &rows {
                    conn.execute(
                        "INSERT OR REPLACE INTO TRACKER (host, port, key) VALUES (?1, ?2, ?3)",
                        params![host, port, key],
                    )?;
                }
                Ok(())
            })
            .await?;

        Ok(())
    }

    /// Create a new user
    ///
    /// # Errors
    ///
    /// Returns an error if the username already exists or if there's a database error.
    pub async fn create_user(&self, username: String, password: &str) -> Result<u32> {
        let username_clone = username.clone();
        let user_id = self
            .sqlite
            .conn(move |conn| {
                conn.query_one(
                    "SELECT id from USER where username = ?1;",
                    [username_clone],
                    |row| {
                        let id: Option<u32> = row.get(0)?;
                        Ok(id)
                    },
                )
                .optional()
            })
            .await?;

        ensure!(user_id.is_none(), "User already exists");

        let username_clone = username.clone();
        let hashed_password = hash_password(password);
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "INSERT INTO USER(username, password) VALUES(?1, ?2);",
                    [username_clone, hashed_password],
                )
            })
            .await?;

        let user_id = self
            .sqlite
            .conn(move |conn| {
                conn.query_one(
                    "SELECT id from USER where username = ?1;",
                    [username],
                    |row| {
                        let id: u32 = row.get(0)?;
                        Ok(id)
                    },
                )
            })
            .await?;

        Ok(user_id)
    }

    /// Disable a user's account. Re-enabling requires a password reset.
    ///
    /// # Errors
    ///
    /// Invalid username results in an error.
    pub async fn disable_user(&self, username: String) -> Result<()> {
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "UPDATE USER SET PASSWORD = NULL WHERE username = ?1;",
                    [username],
                )
            })
            .await?;
        Ok(())
    }

    /// Add a tracker to the server configuration, fetching its key.
    ///
    /// # Errors
    ///
    /// An error might occur if the tracker is unreachable or on a database
    /// update problem.
    pub async fn add_tracker(&self, ip: IpAddr, port: u16) -> Result<()> {
        self.add_tracker_host(ip.to_string(), port).await
    }

    /// The server's current advertisement for trackers.
    async fn advertisement(&self) -> Advertise {
        Advertise {
            name: self.server_name(),
            description: self.server_description(),
            version: VERSION.clone(),
            anonymous: self.allow_anonymous.load(Ordering::Relaxed),
            users_connected: u32::try_from(self.connections.read().await.len()).unwrap_or_default(),
            uptime: self.since(),
            url: self.url.clone(),
            key: self.public_key,
        }
    }

    /// Whether a tracker is currently configured.
    async fn has_tracker(&self, tracker: &TrackerWithKey) -> bool {
        self.trackers.read().await.iter().any(|t| t == tracker)
    }

    /// Wake the advertising tasks so they re-send the current advertisement to
    /// their trackers immediately.
    fn notify_trackers(&self) {
        self.tracker_update.send_modify(|version| {
            *version = version.wrapping_add(1);
        });
    }

    /// Ensure a persistent advertising task is running for every configured
    /// tracker.
    async fn start_tracker_advertising(&self) {
        for tracker in self.trackers.read().await.clone() {
            self.spawn_advertiser(tracker);
        }
    }

    /// Spawn a persistent advertising task for a tracker, unless one is already
    /// running for it.
    fn spawn_advertiser(&self, tracker: TrackerWithKey) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            // Claim the tracker so a concurrent add can't start a second task.
            if !self_clone.advertising.write().await.insert(tracker.clone()) {
                return;
            }
            self_clone.advertise_to_tracker(&tracker).await;
            self_clone.advertising.write().await.remove(&tracker);
        });
    }

    /// Maintain a persistent advertising connection to a single tracker: connect,
    /// send the advertisement, and re-send it whenever our information changes.
    /// Dropping the connection (on shutdown or when the tracker is removed) tells
    /// the tracker we are gone. Reconnects with a short delay after any failure.
    async fn advertise_to_tracker(&self, tracker: &TrackerWithKey) {
        /// Delay before reconnecting after a connection failure.
        const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
        /// How often to re-check that this tracker is still configured.
        const LIVENESS_CHECK: std::time::Duration = std::time::Duration::from_secs(10);

        let mut updates = self.tracker_update.subscribe();

        while self.serving.load(Ordering::Relaxed) && self.has_tracker(tracker).await {
            let mut stream = match TcpStream::connect(tracker.as_string()).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("Failed to connect to tracker {}: {e}", tracker.as_string());
                    tokio::time::sleep(RECONNECT_DELAY).await;
                    continue;
                }
            };

            let advert = AdvertiseServer(self.advertisement().await);
            if let Err(e) = advert.send(&mut stream).await {
                error!(
                    "Failed to advertise to tracker {}: {e}",
                    tracker.as_string()
                );
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }

            // Hold the connection open, re-advertising on every change, until we
            // stop serving, the tracker is removed, or the connection breaks.
            loop {
                tokio::select! {
                    changed = updates.changed() => {
                        if changed.is_err() {
                            return; // state dropped: shutting down
                        }
                        let advert = AdvertiseServer(self.advertisement().await);
                        if advert.send(&mut stream).await.is_err() {
                            break; // reconnect
                        }
                    }
                    () = tokio::time::sleep(LIVENESS_CHECK) => {
                        if !self.serving.load(Ordering::Relaxed)
                            || !self.has_tracker(tracker).await
                        {
                            return;
                        }
                    }
                }
            }

            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }

    /// Run the server logic, does not return.
    ///
    /// # Errors
    ///
    /// An error returns if there's a network or database problem.
    #[allow(clippy::too_many_lines)]
    #[tracing::instrument]
    pub async fn serve(&self) -> Result<()> {
        // Mark ourselves serving before starting the advertising tasks, which
        // check this flag to decide whether to keep running.
        self.serving.store(true, Ordering::Relaxed);
        self.start_tracker_advertising().await;

        // Periodically re-broadcast the roster so idle times (and idle-based
        // greying) stay current even when nobody is sending anything.
        let sweeper = self.clone();
        tokio::spawn(async move {
            while sweeper.serving.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_mins(1)).await;
                if !sweeper.connections.read().await.is_empty() {
                    sweeper.broadcast_user_list().await;
                }
            }
        });

        let self_clone = self.clone();

        if let Some(mdns) = &self_clone.mdns {
            let service = self_clone.mdns_service_info()?;
            trace!("Registering MDNS service...");
            mdns.register(service)?;
        }

        let disconnect_bytes = ServerMessagesEncrypted::Disconnect.to_vec();
        let listener = TcpListener::bind((self.ip, self.port)).await?;
        let accept_handle = tokio::spawn(async move {
            while self_clone.serving.load(Ordering::Relaxed) {
                match listener.accept().await {
                    Ok((mut socket, client)) => {
                        let message = match unencrypted::ClientToServer::receive(&mut socket).await
                        {
                            Ok(message) => message,
                            Err(e) => {
                                error!("Failed to receive message: {e}");
                                continue;
                            }
                        };
                        match message {
                            unencrypted::ClientToServer::KeyRequest => {
                                let response =
                                    unencrypted::ServerToClient::PublicKey(self_clone.public_key);
                                if let Err(e) = response.send(&mut socket).await {
                                    error!("Failed to send key response: {e}");
                                }
                            }
                            unencrypted::ClientToServer::VersionRequest => {
                                let response =
                                    unencrypted::ServerToClient::Version(VERSION.clone());
                                if let Err(e) = response.send(&mut socket).await {
                                    error!("Failed to send version response: {e}");
                                }
                            }
                            unencrypted::ClientToServer::GoCrypto => {
                                let mut stream = match DefaultEncryptedStream::accept(
                                    socket,
                                    &self_clone.private_key,
                                )
                                .await
                                {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to start encrypted connection: {e}");
                                        continue;
                                    }
                                };
                                match stream.recv().await {
                                    Ok(bytes) => match ServerMessagesEncrypted::from_bytes(&bytes) {
                                        Ok(
                                            ServerMessagesEncrypted::ServerAuthenticationRequest((
                                                display_name,
                                                user_local_time,
                                                auth,
                                            )),
                                        ) => {
                                            let (user_id, admin) = if let Some(inner_auth) = auth {
                                                let uname = inner_auth.username.clone();
                                                if let Ok((user_id, admin)) =
                                                    self_clone.authenticate_user(inner_auth).await
                                                {
                                                    info!(
                                                        "User {display_name} authenticated: uname: {uname}, uid: {user_id}"
                                                    );
                                                    (Some(user_id), admin)
                                                } else {
                                                    let error_message =
                                                        ClientMessagesEncrypted::Error(
                                                            ServerError::AuthenticationFailed,
                                                        )
                                                        .to_vec();
                                                    warn!(
                                                        "Authentication failed for: username {uname} from {client}"
                                                    );
                                                    if let Err(e) =
                                                        stream.send(&error_message).await
                                                    {
                                                        error!(
                                                            "Failed to send server auth error to {client}: {e}"
                                                        );
                                                    }
                                                    continue;
                                                }
                                            } else if self_clone
                                                .allow_anonymous
                                                .load(Ordering::Relaxed)
                                            {
                                                (None, false)
                                            } else {
                                                warn!(
                                                    "Attempted anonymous connection from {client} for display name {display_name}"
                                                );
                                                let error_message = ClientMessagesEncrypted::Error(
                                                    ServerError::AuthenticationRequired,
                                                )
                                                .to_vec();
                                                if let Err(e) = stream.send(&error_message).await {
                                                    error!(
                                                        "Failed to send server auth error to {client}: {e}"
                                                    );
                                                }
                                                continue;
                                            };

                                            // Enforce the optional concurrent-connection
                                            // limit. Administrators are exempt so a full
                                            // server can still be managed.
                                            if !admin
                                                && let Some(max) = self_clone.max_connections()
                                                && self_clone.connections.read().await.len()
                                                    >= usize::from(max)
                                            {
                                                warn!(
                                                    "Rejecting {client}: server at capacity ({max} connections)"
                                                );
                                                let full = ClientMessagesEncrypted::Error(
                                                    ServerError::AtCapacity,
                                                )
                                                .to_vec();
                                                if let Err(e) = stream.send(&full).await {
                                                    error!(
                                                        "Failed to send capacity rejection to {client}: {e}"
                                                    );
                                                }
                                                continue;
                                            }

                                            // Register the connection BEFORE replying, so any
                                            // client that has received its response is already
                                            // present in the roster (closes a connect race).
                                            let (read_half, write_half) = stream.into_split();
                                            let write = Arc::new(RwLock::new(write_half));
                                            let addr = Arc::new(client);
                                            let id = self_clone
                                                .next_connection_id
                                                .fetch_add(1, Ordering::Relaxed);
                                            let cancel = Arc::new(Notify::new());
                                            let now = Local::now().to_utc();
                                            let last_active =
                                                Arc::new(AtomicI64::new(now.timestamp()));
                                            let color = match user_id {
                                                Some(uid) => self_clone.user_color(uid).await,
                                                None => None,
                                            };
                                            // The client's verified identity key (if it
                                            // provided one), so peers can end-to-end
                                            // encrypt direct messages to this user.
                                            let public_key = write
                                                .read()
                                                .await
                                                .client_key()
                                                .map(VerifyingKey::to_bytes);
                                            let user = Arc::new(ConnectedUser {
                                                id,
                                                display_name,
                                                admin,
                                                connected_since: Duration::default(),
                                                idle: Duration::default(),
                                                color,
                                                user_id,
                                                public_key,
                                                timezone: user_local_time,
                                            });
                                            let connection = ClientConnection {
                                                connection_id: id,
                                                conn: write.clone(),
                                                user: user.clone(),
                                                addr: addr.clone(),
                                                connected_at: now,
                                                last_active: last_active.clone(),
                                                cancel: cancel.clone(),
                                            };
                                            if let Some(uid) = user_id {
                                                info!(
                                                    "{} (uid: {uid}) connected from {addr}",
                                                    user.display_name
                                                );
                                            } else {
                                                info!(
                                                    "{} connected from {addr}",
                                                    user.display_name
                                                );
                                            }
                                            self_clone.connections.write().await.push(connection);
                                            self_clone.total_visits.fetch_add(1, Ordering::Relaxed);

                                            // Reply with the server information and session
                                            // details over the shared write half. On failure,
                                            // drop the just-registered connection.
                                            let server_bytes =
                                                ClientMessagesEncrypted::ServerInformationResponse(
                                                    self_clone.server_information().await,
                                                )
                                                .to_vec();
                                            let session_bytes =
                                                ClientMessagesEncrypted::SessionInfo {
                                                    user_id,
                                                    admin,
                                                }
                                                .to_vec();
                                            // Push the chatrooms this user may see
                                            // so chat is available immediately,
                                            // without the client having to ask.
                                            let chat_bytes =
                                                ClientMessagesEncrypted::ChatRoomsResponse(
                                                    self_clone
                                                        .chatrooms_for_user(user_id, admin)
                                                        .await,
                                                )
                                                .to_vec();
                                            let send_result = {
                                                let mut guard = write.write().await;
                                                let mut result = guard.send(&server_bytes).await;
                                                if result.is_ok() {
                                                    result = guard.send(&session_bytes).await;
                                                }
                                                if result.is_ok() {
                                                    result = guard.send(&chat_bytes).await;
                                                }
                                                result
                                            };
                                            if let Err(e) = send_result {
                                                error!("Failed to send handshake to {client}: {e}");
                                                self_clone
                                                    .connections
                                                    .write()
                                                    .await
                                                    .retain(|c| c.addr != addr);
                                                continue;
                                            }

                                            // Service this client on its own task so a slow
                                            // or idle client can't stall the others and a
                                            // disconnect is noticed as soon as it happens.
                                            let client_state = self_clone.clone();
                                            tokio::spawn(async move {
                                                client_state
                                                    .handle_client(
                                                        read_half,
                                                        write,
                                                        addr,
                                                        user,
                                                        cancel,
                                                        last_active,
                                                    )
                                                    .await;
                                            });

                                            // Push the updated roster to every client,
                                            // off the accept path so a slow client can't
                                            // hold up new connections, and refresh the
                                            // user count advertised to trackers.
                                            let broadcaster = self_clone.clone();
                                            tokio::spawn(async move {
                                                broadcaster.broadcast_user_list().await;
                                            });
                                            self_clone.notify_trackers();
                                        }
                                        Ok(_) => {
                                            warn!(
                                                "Unexpected protocol message received when expecting to switch to encrypted communications from {client}"
                                            );
                                            if let Err(e) = stream.send(&disconnect_bytes).await {
                                                error!(
                                                    "Failed to disconnect message to {client}: {e}"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "Error decoding encrypted message from {client}: {e}"
                                            );
                                        }
                                    },
                                    Err(e) => {
                                        error!(
                                            "Error decoding unencrypted message from {client}: {e}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {e}");
                        break;
                    }
                }
            }
        });

        accept_handle.await?;

        Ok(())
    }

    /// Service a single client on its own task: read messages and respond until
    /// the client disconnects or the socket errors, then drop it from the roster
    /// and notify the remaining clients. The read half is owned here; the write
    /// half is shared so the server can also push roster updates to this client.
    #[allow(clippy::too_many_lines)]
    async fn handle_client(
        &self,
        mut read: EncryptedRead<DEFAULT_REKEY_INTERVAL>,
        write: Arc<RwLock<EncryptedWrite<DEFAULT_REKEY_INTERVAL>>>,
        addr: Arc<SocketAddr>,
        user: Arc<ConnectedUser>,
        cancel: Arc<Notify>,
        last_active: Arc<AtomicI64>,
    ) {
        let keep_alive_bytes = ServerMessagesEncrypted::KeepAlive.to_vec();

        // In-progress upload for this connection, if any.
        let mut upload: Option<Upload> = None;

        loop {
            let message = tokio::select! {
                result = read.recv() => match result {
                    Ok(message) => message,
                    // EOF here is the normal path for a client that drops without
                    // sending `Disconnect`; treat it as an ordinary disconnect.
                    Err(e) => {
                        info!("Connection {addr:?} closed: {e}");
                        break;
                    }
                },
                // An administrator kicked this connection.
                () = cancel.notified() => {
                    info!("Connection {addr:?} kicked");
                    break;
                }
            };

            // Treat anything but the keep-alive heartbeat as user activity, so an
            // idle user's name un-greys as soon as they do something.
            match ServerMessagesEncrypted::from_bytes(&message) {
                Ok(ServerMessagesEncrypted::KeepAlive) | Err(_) => {}
                Ok(_) => self.mark_active(&last_active).await,
            }

            match ServerMessagesEncrypted::from_bytes(&message) {
                Ok(ServerMessagesEncrypted::KeepAlive) => {
                    if let Err(e) = write.write().await.send(&keep_alive_bytes).await {
                        error!("Failed to send keep alive to {addr:?}: {e}");
                    }
                }

                Ok(ServerMessagesEncrypted::ServerInformationRequest) => {
                    let info = ClientMessagesEncrypted::ServerInformationResponse(
                        self.server_information().await,
                    )
                    .to_vec();
                    if let Err(e) = write.write().await.send(&info).await {
                        error!("Failed to send server info to {addr:?}: {e}");
                    }
                }

                Ok(ServerMessagesEncrypted::ListConnectedUsersRequest) => {
                    let response = ClientMessagesEncrypted::ListConnectedUsersResponse(
                        self.connected_users().await,
                    )
                    .to_vec();
                    if let Err(e) = write.write().await.send(&response).await {
                        error!("Failed to send connected users to {addr:?}: {e}");
                    }
                }

                Ok(ServerMessagesEncrypted::UserDetailsRequest(id)) => {
                    // Privileged fields (username, IP) are only filled in for an
                    // administrator connection.
                    let details = self.user_details(id, user.admin).await;
                    let response = ClientMessagesEncrypted::UserDetailsResponse(details).to_vec();
                    if let Err(e) = write.write().await.send(&response).await {
                        error!("Failed to send user details to {addr:?}: {e}");
                    }
                }

                Ok(ServerMessagesEncrypted::ChatRoomsRequest) => {
                    let rooms = self.chatrooms_for_user(user.user_id, user.admin).await;
                    let response = ClientMessagesEncrypted::ChatRoomsResponse(rooms).to_vec();
                    if let Err(e) = write.write().await.send(&response).await {
                        error!("Failed to send chatroom list to {addr:?}: {e}");
                    }
                }

                Ok(ServerMessagesEncrypted::ChatJoin(room)) => {
                    self.chat_join(user.id, room, &user).await;
                }

                Ok(ServerMessagesEncrypted::ChatLeave(room)) => {
                    self.chat_leave(user.id, room, &user.display_name).await;
                }

                Ok(ServerMessagesEncrypted::ChatSend { room, message }) => {
                    self.chat_send(user.id, room, message, &user).await;
                }

                Ok(ServerMessagesEncrypted::FileListRequest { path }) => {
                    let response = self.file_list(&path, &user).await;
                    reply(&write, &addr, &response).await;
                }

                Ok(ServerMessagesEncrypted::FileDownloadRequest { path }) => {
                    self.file_download(&path, &user, &write, &addr).await;
                }

                Ok(ServerMessagesEncrypted::FileUploadRequest { path, size }) => {
                    // Discard any half-finished prior upload.
                    if let Some(previous) = upload.take() {
                        let _ = std::fs::remove_file(&previous.temp_path);
                    }
                    match self.file_upload_begin(&path, size, &user, user.id).await {
                        Ok(started) => {
                            upload = Some(started);
                            reply(&write, &addr, &ClientMessagesEncrypted::FileUploadReady).await;
                        }
                        Err(e) => reply(&write, &addr, &file_error(e.to_string())).await,
                    }
                }

                Ok(ServerMessagesEncrypted::FileUploadChunk { data }) => {
                    if let Some(active) = upload.as_mut() {
                        active.written += data.len() as u64;
                        let too_big = active.max.is_some_and(|max| active.written > max);
                        let write_failed =
                            !too_big && std::io::Write::write_all(&mut active.file, &data).is_err();
                        if too_big || write_failed {
                            if let Some(aborted) = upload.take() {
                                let _ = std::fs::remove_file(&aborted.temp_path);
                            }
                            let reason = if too_big {
                                "Upload exceeds the size limit"
                            } else {
                                "Failed to write upload"
                            };
                            reply(&write, &addr, &file_error(reason)).await;
                        }
                    }
                }

                Ok(ServerMessagesEncrypted::FileUploadEnd) => {
                    if let Some(finished) = upload.take() {
                        let response = match finalize_upload(finished) {
                            Ok(()) => ClientMessagesEncrypted::FileUploadComplete,
                            Err(e) => file_error(e.to_string()),
                        };
                        reply(&write, &addr, &response).await;
                    }
                }

                Ok(ServerMessagesEncrypted::FileDeleteRequest { path }) => {
                    if let Some(err) = self.file_delete(&path, &user).await {
                        reply(&write, &addr, &err).await;
                    }
                }

                Ok(ServerMessagesEncrypted::DirectMessage {
                    to,
                    encrypted,
                    payload,
                }) => {
                    // Relay to the recipient verbatim; when `encrypted` the
                    // payload is end-to-end ciphertext the server cannot read.
                    let delivery = ClientMessagesEncrypted::DirectMessageReceived {
                        from: user.id,
                        from_display_name: user.display_name.clone(),
                        encrypted,
                        payload,
                    };
                    self.send_to_connection(to, &delivery).await;
                }

                Ok(ServerMessagesEncrypted::Disconnect) => break,

                // Administrative requests: allowed only on an authenticated admin
                // connection. A single gate covers every admin message.
                Ok(ServerMessagesEncrypted::AdministrativeRequest(admin_request)) => {
                    if user.admin {
                        self.handle_admin(admin_request, &write, &addr).await;
                    } else {
                        warn!("Rejected admin request from non-admin {addr:?}");
                        reply(
                            &write,
                            &addr,
                            &ClientMessagesEncrypted::Error(ServerError::NotAuthorized),
                        )
                        .await;
                    }
                }

                Ok(x) => {
                    error!("Unexpected message from {addr:?}: {x:?}");
                    break;
                }
                Err(e) => {
                    error!("Error decoding message from {addr:?}: {e}");
                    break;
                }
            }
        }

        // The client is gone: discard any half-finished upload, then drop it
        // from any chatrooms and the roster, tell everyone else, and refresh the
        // user count advertised to trackers.
        if let Some(pending) = upload {
            let _ = std::fs::remove_file(&pending.temp_path);
        }
        self.chat_leave_all(user.id, &user.display_name).await;
        self.connections.write().await.retain(|c| c.addr != addr);
        self.broadcast_user_list().await;
        self.notify_trackers();
    }

    /// Perform an administrative request and reply to the requester. The caller
    /// (`handle_client`) has already confirmed the connection is an admin.
    #[inline]
    #[allow(clippy::too_many_lines)]
    async fn handle_admin(
        &self,
        msg: ServerAdminMessagesEncrypted,
        write: &Arc<RwLock<EncryptedWrite<DEFAULT_REKEY_INTERVAL>>>,
        addr: &SocketAddr,
    ) {
        let ok = ClientAdminMessagesEncrypted::ActionOk;
        let result: Result<ClientAdminMessagesEncrypted> = match msg {
            ServerAdminMessagesEncrypted::SetServerName(name) => {
                self.set_server_name(name).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::SetServerDescription(description) => {
                self.set_server_description(description).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::ListUsers => self
                .admin_list_users()
                .await
                .map(ClientAdminMessagesEncrypted::UsersResponse),
            ServerAdminMessagesEncrypted::ListGroups => self
                .admin_list_groups()
                .await
                .map(ClientAdminMessagesEncrypted::GroupsResponse),
            ServerAdminMessagesEncrypted::CreateGroup(CreateGroup {
                name,
                description,
                color,
            }) => self
                .create_group(name, description, color)
                .await
                .map(|()| ok),
            ServerAdminMessagesEncrypted::EditGroup(Group {
                id,
                name,
                description,
                color,
            }) => self
                .edit_group(id, name, description, color)
                .await
                .map(|()| ok),
            ServerAdminMessagesEncrypted::DeleteGroup(id) => {
                self.delete_group(id).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::CreateUser(user) => self
                .create_user_admin(user.username, &user.password, user.groups)
                .await
                .map(|()| ok),
            ServerAdminMessagesEncrypted::DeleteUser(uid) => {
                self.delete_user(uid).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::AddUserToGroup(m) => {
                self.add_user_to_group(m.uid, m.gid).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::RemoveUserFromGroup(m) => {
                self.remove_user_from_group(m.uid, m.gid).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::ListTrackers => Ok(
                ClientAdminMessagesEncrypted::TrackersResponse(self.list_trackers().await),
            ),
            ServerAdminMessagesEncrypted::AddTracker(tracker) => self
                .add_tracker_host(tracker.host, tracker.port)
                .await
                .map(|()| ok),
            ServerAdminMessagesEncrypted::RemoveTracker(tracker) => self
                .remove_tracker_host(&tracker.host, tracker.port)
                .await
                .map(|()| ok),
            ServerAdminMessagesEncrypted::KickUser(id) => self.kick_user(id).await.map(|()| ok),
            ServerAdminMessagesEncrypted::SetChatEnabled(enabled) => {
                self.set_chat_enabled(enabled).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::ListChatrooms => self
                .admin_list_chatrooms()
                .await
                .map(ClientAdminMessagesEncrypted::ChatroomsResponse),
            ServerAdminMessagesEncrypted::CreateChatroom { name, groups } => {
                self.create_chatroom(name, groups).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::EditChatroom { id, name, groups } => {
                self.edit_chatroom(id, name, groups).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::DeleteChatroom(id) => {
                self.delete_chatroom(id).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::GetServerLimits => Ok(
                ClientAdminMessagesEncrypted::ServerLimitsResponse(self.server_limits()),
            ),
            ServerAdminMessagesEncrypted::SetMaxUploadSize(max) => {
                self.set_max_upload_size(max).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::SetMaxConnections(max) => {
                self.set_max_connections(max).await.map(|()| ok)
            }
            ServerAdminMessagesEncrypted::GetShareInfo => Ok(
                ClientAdminMessagesEncrypted::ShareInfoResponse(self.share_info()),
            ),
            ServerAdminMessagesEncrypted::GetFileAcl(path) => self
                .get_file_acl(&path)
                .map(|acl| ClientAdminMessagesEncrypted::FileAclResponse { path, acl }),
            ServerAdminMessagesEncrypted::SetFileAcl { path, acl } => {
                self.set_file_acl(&path, &acl).map(|()| ok)
            }
            // Unreachable: the caller only dispatches admin variants here.
            _ => return,
        };

        let response = result.map_or_else(
            |e| {
                warn!("Admin action failed for {addr:?}: {e}");
                ClientMessagesEncrypted::Error(ServerError::ActionFailed(e.to_string()))
            },
            ClientMessagesEncrypted::AdministrativeResponse,
        );
        reply(write, addr, &response).await;
    }

    /// Snapshot of the server's public information for clients.
    #[inline]
    async fn server_information(&self) -> ServerInformation {
        ServerInformation {
            name: self.server_name(),
            description: self.server_description(),
            url: self.url.clone(),
            key: self.public_key,
            version: VERSION.clone(),
            anonymous: self.allow_anonymous.load(Ordering::Relaxed),
            users_connected: u32::try_from(self.connections.read().await.len()).unwrap_or_default(),
            chat_enabled: self.chat_enabled.load(Ordering::Relaxed),
            sharing_enabled: self.share_directory.is_some(),
        }
    }

    /// Send a message to every connected client.
    async fn broadcast(&self, message: &ClientMessagesEncrypted) {
        let bytes = message.to_vec();

        // Clone the write-half handles out from under the read lock, then send
        // without holding the connections lock.
        let writers: Vec<_> = self
            .connections
            .read()
            .await
            .iter()
            .map(|c| c.conn.clone())
            .collect();

        for writer in writers {
            if let Err(e) = writer.write().await.send(&bytes).await {
                error!("Failed to broadcast message: {e}");
            }
        }
    }

    /// Send the current connected-users list to every connected client so their
    /// rosters update automatically when someone joins or leaves.
    async fn broadcast_user_list(&self) {
        self.broadcast(&ClientMessagesEncrypted::ListConnectedUsersResponse(
            self.connected_users().await,
        ))
        .await;
    }

    /// Push the current server information to every connected client so their
    /// view updates when an admin changes the name or description.
    async fn broadcast_server_info(&self) {
        self.broadcast(&ClientMessagesEncrypted::ServerInformationResponse(
            self.server_information().await,
        ))
        .await;
    }

    // ── Chat ──────────────────────────────────────────────────────────────

    /// Whether chat is enabled on the server.
    #[inline]
    #[must_use]
    pub fn chat_enabled(&self) -> bool {
        self.chat_enabled.load(Ordering::Relaxed)
    }

    /// (Admin) Enable or disable chat. Disabling clears all room membership.
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn set_chat_enabled(&self, enabled: bool) -> Result<()> {
        self.sqlite
            .conn(move |conn| {
                conn.execute("UPDATE SERVER_CONFIG SET chat_enabled = ?1;", [enabled])
            })
            .await?;
        self.chat_enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.chat_members.write().await.clear();
        }
        // Tell clients chat is on/off and refresh their accessible-room lists.
        self.broadcast_server_info().await;
        self.broadcast_chatrooms().await;
        Ok(())
    }

    /// (Admin) All chatrooms with their group restrictions.
    ///
    /// # Errors
    ///
    /// Returns an error on a database failure.
    pub async fn admin_list_chatrooms(&self) -> Result<Vec<Chatroom>> {
        let rooms = self
            .sqlite
            .conn(move |conn| {
                let mut stmt = conn.prepare("SELECT id, name FROM CHATROOM ORDER BY id;")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, u16>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<async_sqlite::rusqlite::Result<Vec<(u16, String)>>>()?;

                let mut chatrooms = Vec::with_capacity(rows.len());
                for (id, name) in rows {
                    let mut gstmt = conn
                        .prepare("SELECT gid FROM CHATROOM_GROUP WHERE room = ?1 ORDER BY gid;")?;
                    let groups = gstmt
                        .query_map([id], |row| row.get::<_, u32>(0))?
                        .collect::<async_sqlite::rusqlite::Result<Vec<u32>>>()?;
                    chatrooms.push(Chatroom { id, name, groups });
                }
                Ok(chatrooms)
            })
            .await?;
        Ok(rooms)
    }

    /// (Admin) Create a chatroom, restricted to the given group ids (empty means
    /// open to everyone).
    ///
    /// # Errors
    ///
    /// Returns an error if the name is empty or already taken, or on a database
    /// failure.
    pub async fn create_chatroom(&self, name: String, groups: Vec<u32>) -> Result<()> {
        ensure!(!name.trim().is_empty(), "Chatroom name cannot be empty");
        self.sqlite
            .conn(move |conn| {
                conn.execute("INSERT INTO CHATROOM(name) VALUES(?1);", [&name])?;
                let id = conn.last_insert_rowid();
                for gid in &groups {
                    conn.execute(
                        "INSERT OR IGNORE INTO CHATROOM_GROUP(room, gid) VALUES(?1, ?2);",
                        params![id, gid],
                    )?;
                }
                Ok(())
            })
            .await?;
        self.broadcast_chatrooms().await;
        Ok(())
    }

    /// (Admin) Rename a chatroom and replace its group restrictions.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is empty, or on a database failure.
    pub async fn edit_chatroom(&self, id: u16, name: String, groups: Vec<u32>) -> Result<()> {
        ensure!(!name.trim().is_empty(), "Chatroom name cannot be empty");
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "UPDATE CHATROOM SET name = ?1 WHERE id = ?2;",
                    params![name, id],
                )?;
                conn.execute("DELETE FROM CHATROOM_GROUP WHERE room = ?1;", [id])?;
                for gid in &groups {
                    conn.execute(
                        "INSERT OR IGNORE INTO CHATROOM_GROUP(room, gid) VALUES(?1, ?2);",
                        params![id, gid],
                    )?;
                }
                Ok(())
            })
            .await?;
        self.broadcast_chatrooms().await;
        Ok(())
    }

    /// (Admin) Delete a chatroom by id. The default `Public` room (id 0) cannot
    /// be deleted.
    ///
    /// # Errors
    ///
    /// Returns an error when deleting the Public room or on a database failure.
    pub async fn delete_chatroom(&self, id: u16) -> Result<()> {
        ensure!(id != 0, "The Public chatroom cannot be deleted");
        self.sqlite
            .conn(move |conn| {
                conn.execute("DELETE FROM CHATROOM_GROUP WHERE room = ?1;", [id])?;
                conn.execute("DELETE FROM CHATROOM WHERE id = ?1;", [id])
            })
            .await?;
        self.chat_members.write().await.remove(&id);
        self.broadcast_chatrooms().await;
        Ok(())
    }

    /// The chatrooms a user may access. Empty when chat is disabled. A room with
    /// no group restriction is open to everyone; otherwise the user must be an
    /// admin or a member of one of the room's groups.
    async fn chatrooms_for_user(&self, user_id: Option<u32>, admin: bool) -> Vec<ChatroomInfo> {
        if !self.chat_enabled.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let uid = user_id.map_or(-1_i64, i64::from);
        self.sqlite
            .conn(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT c.id, c.name FROM CHATROOM c \
                     WHERE NOT EXISTS(SELECT 1 FROM CHATROOM_GROUP cg WHERE cg.room = c.id) \
                        OR ?1 \
                        OR EXISTS(SELECT 1 FROM CHATROOM_GROUP cg \
                                  JOIN USERGROUP ug ON ug.gid = cg.gid \
                                  WHERE cg.room = c.id AND ug.uid = ?2) \
                     ORDER BY c.id;",
                )?;
                stmt.query_map(params![admin, uid], |row| {
                    Ok(ChatroomInfo {
                        id: row.get(0)?,
                        name: row.get(1)?,
                    })
                })?
                .collect::<async_sqlite::rusqlite::Result<Vec<_>>>()
            })
            .await
            .unwrap_or_default()
    }

    /// Whether a user may access a specific chatroom.
    async fn can_access_room(&self, room: u16, user_id: Option<u32>, admin: bool) -> bool {
        if !self.chat_enabled.load(Ordering::Relaxed) {
            return false;
        }
        let uid = user_id.map_or(-1_i64, i64::from);
        let allowed = self
            .sqlite
            .conn(move |conn| {
                conn.query_row(
                    "SELECT (NOT EXISTS(SELECT 1 FROM CHATROOM_GROUP WHERE room = ?1)) \
                     OR ?2 \
                     OR EXISTS(SELECT 1 FROM CHATROOM_GROUP cg \
                               JOIN USERGROUP ug ON ug.gid = cg.gid \
                               WHERE cg.room = ?1 AND ug.uid = ?3) \
                     FROM CHATROOM WHERE id = ?1;",
                    params![room, admin, uid],
                    |row| row.get::<_, bool>(0),
                )
                .optional()
            })
            .await;
        matches!(allowed, Ok(Some(true)))
    }

    /// Send each connected client its own list of accessible chatrooms.
    async fn broadcast_chatrooms(&self) {
        let targets: Vec<_> = self
            .connections
            .read()
            .await
            .iter()
            .map(|c| (c.conn.clone(), c.user.user_id, c.user.admin))
            .collect();
        for (writer, user_id, admin) in targets {
            let rooms = self.chatrooms_for_user(user_id, admin).await;
            let bytes = ClientMessagesEncrypted::ChatRoomsResponse(rooms).to_vec();
            if let Err(e) = writer.write().await.send(&bytes).await {
                error!("Failed to send chatroom list: {e}");
            }
        }
    }

    /// Display names of the members currently in a room.
    async fn room_member_names(&self, room: u16) -> Vec<String> {
        let ids = self
            .chat_members
            .read()
            .await
            .get(&room)
            .cloned()
            .unwrap_or_default();
        self.connections
            .read()
            .await
            .iter()
            .filter(|c| ids.contains(&c.connection_id))
            .map(|c| c.user.display_name.clone())
            .collect()
    }

    /// Send a message to every member of a room, optionally excluding one
    /// connection (e.g. the sender of a join notice).
    async fn broadcast_to_room(
        &self,
        room: u16,
        message: &ClientMessagesEncrypted,
        exclude: Option<u16>,
    ) {
        let ids = self
            .chat_members
            .read()
            .await
            .get(&room)
            .cloned()
            .unwrap_or_default();
        let bytes = message.to_vec();
        let writers: Vec<_> = self
            .connections
            .read()
            .await
            .iter()
            .filter(|c| ids.contains(&c.connection_id) && Some(c.connection_id) != exclude)
            .map(|c| c.conn.clone())
            .collect();
        for writer in writers {
            if let Err(e) = writer.write().await.send(&bytes).await {
                error!("Failed to send chat message: {e}");
            }
        }
    }

    /// Send a single message to a specific connection by id.
    async fn send_to_connection(&self, connection_id: u16, message: &ClientMessagesEncrypted) {
        let writer = self
            .connections
            .read()
            .await
            .iter()
            .find(|c| c.connection_id == connection_id)
            .map(|c| c.conn.clone());
        if let Some(writer) = writer
            && let Err(e) = writer.write().await.send(&message.to_vec()).await
        {
            error!("Failed to send chat message: {e}");
        }
    }

    /// Handle a user joining a chatroom: register membership, send them the
    /// current member list, and tell the others someone arrived.
    async fn chat_join(&self, connection_id: u16, room: u16, user: &ConnectedUser) {
        if !self.can_access_room(room, user.user_id, user.admin).await {
            return;
        }
        self.chat_members
            .write()
            .await
            .entry(room)
            .or_default()
            .insert(connection_id);

        let users = self.room_member_names(room).await;
        self.send_to_connection(
            connection_id,
            &ClientMessagesEncrypted::ChatJoined { room, users },
        )
        .await;
        self.broadcast_to_room(
            room,
            &ClientMessagesEncrypted::ChatActivity(ChatEvent::Joined {
                room,
                display_name: user.display_name.clone(),
            }),
            Some(connection_id),
        )
        .await;
    }

    /// Handle a user leaving a chatroom, telling the remaining members.
    async fn chat_leave(&self, connection_id: u16, room: u16, display_name: &str) {
        let was_member = {
            let mut members = self.chat_members.write().await;
            if let Some(set) = members.get_mut(&room) {
                let removed = set.remove(&connection_id);
                if set.is_empty() {
                    members.remove(&room);
                }
                removed
            } else {
                false
            }
        };
        if was_member {
            self.broadcast_to_room(
                room,
                &ClientMessagesEncrypted::ChatActivity(ChatEvent::Left {
                    room,
                    display_name: display_name.to_string(),
                }),
                None,
            )
            .await;
        }
    }

    /// Remove a connection from every chatroom, telling each room's remaining
    /// members. Used when a connection drops.
    async fn chat_leave_all(&self, connection_id: u16, display_name: &str) {
        let left_rooms: Vec<u16> = {
            let mut members = self.chat_members.write().await;
            let mut left = Vec::new();
            members.retain(|room, set| {
                if set.remove(&connection_id) {
                    left.push(*room);
                }
                !set.is_empty()
            });
            left
        };
        for room in left_rooms {
            self.broadcast_to_room(
                room,
                &ClientMessagesEncrypted::ChatActivity(ChatEvent::Left {
                    room,
                    display_name: display_name.to_string(),
                }),
                None,
            )
            .await;
        }
    }

    /// Broadcast a chat message from a member to the whole room. Ignored if the
    /// sender isn't a member of the room or the message is blank.
    async fn chat_send(
        &self,
        connection_id: u16,
        room: u16,
        message: String,
        user: &ConnectedUser,
    ) {
        let is_member = self
            .chat_members
            .read()
            .await
            .get(&room)
            .is_some_and(|set| set.contains(&connection_id));
        if !is_member || message.trim().is_empty() {
            return;
        }
        self.broadcast_to_room(
            room,
            &ClientMessagesEncrypted::ChatActivity(ChatEvent::Message {
                room,
                display_name: user.display_name.clone(),
                message,
                at: Utc::now(),
            }),
            None,
        )
        .await;
    }

    /// Get a list of connected users
    pub async fn connected_users(&self) -> Vec<ConnectedUser> {
        let now = Local::now().to_utc();
        let now_ts = now.timestamp();
        self.connections
            .read()
            .await
            .iter()
            .map(|conn| {
                let mut user = (*conn.user).clone();
                user.connected_since = now - conn.connected_at;
                let idle_secs = (now_ts - conn.last_active.load(Ordering::Relaxed)).max(0);
                user.idle = Duration::seconds(idle_secs);
                user
            })
            .collect()
    }

    /// Record user activity on a connection. If the user had been idle past the
    /// timeout, refresh the roster so their name un-greys promptly.
    async fn mark_active(&self, last_active: &AtomicI64) {
        let now = Local::now().to_utc().timestamp();
        let previous = last_active.swap(now, Ordering::Relaxed);
        if now - previous >= IDLE_TIMEOUT_MINUTES.num_seconds() {
            self.broadcast_user_list().await;
        }
    }

    /// Extra, on-demand details about a connected user by connection id. The
    /// `requester_admin` flag decides whether the privileged fields (login name
    /// and IP address) are included.
    async fn user_details(&self, connection_id: u16, requester_admin: bool) -> Option<UserDetails> {
        let (user_id, ip) = {
            let connections = self.connections.read().await;
            let conn = connections
                .iter()
                .find(|c| c.connection_id == connection_id)?;
            (conn.user.user_id, conn.addr.ip())
        };

        // Group membership is visible to any connected user.
        let groups = match user_id {
            Some(uid) => self.user_groups(uid).await.unwrap_or_default(),
            None => Vec::new(),
        };

        let (username, ip) = if requester_admin {
            let username = match user_id {
                Some(uid) => self.username_by_id(uid).await.unwrap_or_default(),
                None => None,
            };
            (username, Some(ip.to_string()))
        } else {
            (None, None)
        };

        Some(UserDetails {
            connection_id,
            groups,
            username,
            ip,
        })
    }

    /// The login name for a user id, if it exists.
    async fn username_by_id(&self, uid: u32) -> Result<Option<String>> {
        let uid = i64::from(uid);
        let username = self
            .sqlite
            .conn(move |conn| {
                conn.query_row("SELECT username FROM USER WHERE id = ?1;", [uid], |row| {
                    row.get::<_, String>(0)
                })
                .optional()
            })
            .await?;
        Ok(username)
    }

    /// (Admin) Kick a connected user by connection id. The connection is dropped
    /// from the roster immediately (as if the user had never connected), the
    /// client is told the connection is closing, and its read loop is cancelled
    /// so the socket is torn down.
    ///
    /// # Errors
    ///
    /// Returns an error if no connected user has that id.
    async fn kick_user(&self, connection_id: u16) -> Result<()> {
        // Remove from the roster up front so the kick takes effect immediately,
        // regardless of when the client's read loop notices.
        let target = {
            let mut connections = self.connections.write().await;
            let Some(pos) = connections
                .iter()
                .position(|c| c.connection_id == connection_id)
            else {
                return Err(anyhow!("No connected user with id {connection_id}"));
            };
            connections.remove(pos)
        };

        // Tell the client the connection is closing and stop its read loop; the
        // per-client task then drops the read half and the write half is dropped
        // once `target` and that task both release it, closing the socket.
        let disconnect = ClientMessagesEncrypted::Disconnect.to_vec();
        let _ = target.conn.write().await.send(&disconnect).await;
        target.cancel.notify_one();

        // Update everyone else and the trackers now that they're gone.
        self.broadcast_user_list().await;
        self.notify_trackers();
        Ok(())
    }

    fn mdns_service_info(&self) -> mdns_sd::Result<ServiceInfo> {
        use base64::Engine;

        let host_name = format!("{}.local.", self.ip);
        let key_encoded = base64::engine::general_purpose::STANDARD.encode(self.public_key);
        let server_name = self.server_name();
        let properties = [
            (conclave_common::MDNS_VERSION, VERSION.to_string()),
            (conclave_common::MDNS_DESCRIPTION, self.server_description()),
            (conclave_common::MDNS_KEY, key_encoded),
            (
                conclave_common::MDNS_ANONYMOUS,
                self.anonymous_clients_allowed().to_string(),
            ),
        ];

        let mut service = ServiceInfo::new(
            conclave_common::MDNS_NAME,
            &server_name,
            &host_name,
            self.ip,
            self.port,
            &properties[..],
        )?;
        if self.ip.is_unspecified() {
            service = service.enable_addr_auto();
        }

        Ok(service)
    }
}

/// In-memory tail of the most recent log output, shown in the GUI log window.
#[cfg(feature = "gui")]
static LOG_BUFFER: LazyLock<std::sync::Mutex<Vec<u8>>> =
    LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// A `tracing` writer that appends formatted log lines to [`LOG_BUFFER`], keeping
/// only the most recent output so memory stays bounded.
#[cfg(feature = "gui")]
#[derive(Clone)]
struct LogBufferWriter;

#[cfg(feature = "gui")]
impl std::io::Write for LogBufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        /// Keep at most this many bytes of recent log output.
        const CAP: usize = 64 * 1024;

        let mut guard = LOG_BUFFER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.extend_from_slice(buf);
        if guard.len() > CAP {
            // Drop whole lines from the front so the window never shows a
            // truncated first line.
            let over = guard.len() - CAP;
            let cut = guard[over..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(guard.len(), |i| over + i + 1);
            guard.drain(..cut);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "gui")]
impl tracing_subscriber::fmt::MakeWriter<'_> for LogBufferWriter {
    type Writer = LogBufferWriter;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Initialize tracing for GUI mode so log output goes both to stdout and to the
/// in-app log window (via [`LOG_BUFFER`]).
#[cfg(feature = "gui")]
pub fn init_gui_tracing() {
    use tracing_subscriber::prelude::*;

    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(LogBufferWriter),
        )
        .try_init();
}

#[cfg(feature = "gui")]
impl eframe::App for State {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        use zeroize::Zeroize;

        ui.request_repaint();

        let connections = futures::executor::block_on(self.connections.read()).len();
        eframe::egui::CentralPanel::default().show(ui, |ui| {
            ui.label(format!("Current clients: {connections}"));
            ui.label(format!(
                "Total connections: {}",
                self.total_visits.load(Ordering::Relaxed)
            ));
            ui.separator();
            eframe::egui::widgets::global_theme_preference_buttons(ui);
            ui.checkbox(&mut self.log, "Log window");

            if let Some(password) = &self.password
                && !self.password_acknowledged.load(Ordering::Relaxed)
            {
                let text_buff = password.clone();
                let acknowledged = self.password_acknowledged.clone();
                ui.show_viewport_deferred(
                    eframe::egui::ViewportId::from_hash_of("conclave_server_admin_password"),
                    eframe::egui::ViewportBuilder::default()
                        .with_title("Conclave Server Admin Password")
                        .with_resizable(false)
                        .with_close_button(false)
                        .with_inner_size([320.0, 100.0]),
                    move |context, _class| {
                        let text_buff_str = futures::executor::block_on(text_buff.read()).clone();
                        eframe::egui::CentralPanel::default().show(context, |inner_ui| {
                            inner_ui.label("Below is the initial admin password for this server.");
                            inner_ui.text_edit_singleline(&mut text_buff_str.as_str());

                            if inner_ui.button("Confirm").clicked() {
                                acknowledged.store(true, Ordering::Relaxed);
                                futures::executor::block_on(text_buff.write()).zeroize();
                            }
                        });
                    },
                );
            }

            if self.log {
                ui.show_viewport_deferred(
                    eframe::egui::ViewportId::from_hash_of("conclave_server_log"),
                    eframe::egui::ViewportBuilder::default()
                        .with_title("Conclave Server Log")
                        .with_resizable(true)
                        .with_clamp_size_to_monitor_size(true)
                        .with_close_button(false)
                        .with_inner_size([480.0, 320.0]),
                    |context, _class| {
                        eframe::egui::CentralPanel::default().show(context, |inner_ui| {
                            let log = {
                                let guard = LOG_BUFFER
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                String::from_utf8_lossy(&guard).into_owned()
                            };
                            eframe::egui::ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .stick_to_bottom(true)
                                .show(inner_ui, |inner_ui| {
                                    inner_ui.add(
                                        eframe::egui::TextEdit::multiline(&mut log.as_str())
                                            .desired_width(f32::INFINITY)
                                            .font(eframe::egui::TextStyle::Monospace),
                                    );
                                });
                        });
                        // Repaint periodically so new log lines appear live.
                        context.request_repaint_after(std::time::Duration::from_millis(500));
                    },
                );
            }
        });
    }
}

/// Send a single encrypted message to a client over its write half.
#[inline]
/// Build a file-operation error reply carrying a human-readable reason.
fn file_error(reason: impl Into<String>) -> ClientMessagesEncrypted {
    ClientMessagesEncrypted::Error(ServerError::ActionFailed(reason.into()))
}

/// In-progress upload for a single client connection: bytes are written to a
/// reserved temp file and renamed into place on completion.
struct Upload {
    /// Temp file receiving the bytes.
    temp_path: PathBuf,
    /// Destination the temp file is renamed to on success.
    final_path: PathBuf,
    /// Open handle to the temp file.
    file: std::fs::File,
    /// Bytes written so far.
    written: u64,
    /// Optional maximum size, enforced as bytes arrive.
    max: Option<u64>,
}

/// Finalize an upload: flush, ensure the destination is still free, then rename.
fn finalize_upload(mut upload: Upload) -> Result<()> {
    use std::io::Write;
    upload.file.flush()?;
    drop(upload.file); // close before renaming
    if std::fs::symlink_metadata(&upload.final_path).is_ok() {
        let _ = std::fs::remove_file(&upload.temp_path);
        return Err(anyhow!("A file with that name already exists"));
    }
    std::fs::rename(&upload.temp_path, &upload.final_path)?;
    Ok(())
}

async fn reply(
    write: &Arc<RwLock<EncryptedWrite<DEFAULT_REKEY_INTERVAL>>>,
    addr: &SocketAddr,
    msg: &ClientMessagesEncrypted,
) {
    if let Err(e) = write.write().await.send(&msg.to_vec()).await {
        error!("Failed to send response to {addr:?}: {e}");
    }
}

/// Pack an RGB colour into the `0xRRGGBB` integer stored in the database.
#[inline]
fn color_to_db([r, g, b]: [u8; 3]) -> i64 {
    (i64::from(r) << 16) | (i64::from(g) << 8) | i64::from(b)
}

/// Unpack a database `0xRRGGBB` integer into RGB bytes.
#[inline]
fn color_from_db(value: i64) -> [u8; 3] {
    [
        u8::try_from((value >> 16) & 0xFF).unwrap_or(0),
        u8::try_from((value >> 8) & 0xFF).unwrap_or(0),
        u8::try_from(value & 0xFF).unwrap_or(0),
    ]
}

/// Argon hash for storing passwords.
#[inline]
#[track_caller]
fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

#[cfg(test)]
mod tests {
    use conclave_common::net::random_keypair;
    use conclave_common::tracker::TrackerProtocol::AdvertiseServer;
    use conclave_common::tracker::{Advertise, TrackerProtocol};

    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Duration;
    use tokio::net::TcpStream;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn advertise() {
        const PORT: u16 = 8080;

        conclave_common::init_tracing();

        let version = env!("CARGO_PKG_VERSION").parse().unwrap();
        let keys = conclave_tracker::Keys::default();
        let state = conclave_tracker::State::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT, keys);
        let (_server_signing, server_verifying) = random_keypair();

        let state_clone = state.clone();
        let tracker = tokio::spawn(async move {
            state_clone.serve().await.expect("Failed to start tracker");
        });
        assert!(!tracker.is_finished());
        tokio::time::sleep(Duration::seconds(1).to_std().unwrap()).await;

        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();

            TrackerProtocol::GetServers.send(&mut stream).await.unwrap();
            let response = TrackerProtocol::receive(&mut stream).await.unwrap();
            match response {
                TrackerProtocol::ServersList(servers) => {
                    assert!(servers.servers.is_empty());
                }
                _ => panic!("Unexpected response type"),
            }
        }

        // Advertise over a persistent connection. The server is listed for as
        // long as this connection stays open.
        let mut advertiser = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        AdvertiseServer(Advertise {
            name: "Testing".to_string(),
            description: "Testing".to_string(),
            version,
            anonymous: false,
            users_connected: 0,
            uptime: Duration::seconds(0),
            url: String::new(),
            key: server_verifying,
        })
        .send(&mut advertiser)
        .await
        .unwrap();

        // Give the tracker a moment to register the advertiser.
        tokio::time::sleep(Duration::milliseconds(300).to_std().unwrap()).await;

        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();

            TrackerProtocol::GetServers.send(&mut stream).await.unwrap();

            let resp = TrackerProtocol::receive(&mut stream).await.unwrap();
            match resp {
                TrackerProtocol::ServersList(servers) => {
                    assert_eq!(servers.servers.len(), 1);
                    assert_eq!(servers.servers[0].name, "Testing");
                    assert!(!servers.signature_bytes().is_empty());
                }
                _ => panic!("Unexpected response type"),
            }
        }
        assert_eq!(state.servers().servers.len(), 1);

        // Closing the advertiser's connection removes the server immediately.
        drop(advertiser);
        tokio::time::sleep(Duration::milliseconds(10).to_std().unwrap()).await;

        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();

            TrackerProtocol::GetServers.send(&mut stream).await.unwrap();
            let resp = TrackerProtocol::receive(&mut stream).await.unwrap();
            match resp {
                TrackerProtocol::ServersList(servers) => {
                    assert!(servers.servers.is_empty());
                }
                _ => panic!("Unexpected response type"),
            }
        }
        assert!(state.servers().servers.is_empty());

        tracker.abort();
    }

    // Convert from properties key/value pairs to DNS TXT record content
    // Lightly adapted from https://github.com/keepsimple1/mdns-sd/blob/d5f906028c45b15e1ce8ee9edd4b05a51c35fb3a/src/service_info.rs#L895
    fn encode_txt<'a>(properties: impl Iterator<Item = &'a mdns_sd::TxtProperty>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for prop in properties {
            let mut s = prop.key().as_bytes().to_vec();
            if let Some(v) = &prop.val() {
                s.extend(b"=");
                s.extend(*v);
            }

            // Property that exceed the length are truncated
            let sz: u8 = s.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "Property {} is too long, greater than 255 bytes",
                    prop.key()
                );
            });

            // TXT uses (Length,Value) format for each property,
            // i.e. the first byte is the length.
            bytes.push(sz);
            bytes.extend(s);
        }
        if bytes.is_empty() {
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn mdns_advertisement() {
        conclave_common::init_tracing();

        let tempdir = tempdir::TempDir::new("conclave_testing").unwrap();
        let server_db = tempdir
            .path()
            .join(format!("testing_server_{}.db", uuid::Uuid::new_v4()));

        let (state, _) = crate::State::new(
            "Testing Server 123".into(),
            "Testing Description my super cool Conclave server!!!!!!!!!!".into(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some("myserver.example.com".into()),
            1010,
            true,
            server_db,
        )
        .unwrap();

        let service_info = state.mdns_service_info().unwrap();
        let properties = service_info.get_properties();

        let mut properties_total = 0;
        for property in properties.iter() {
            println!("{property} size:{}", property.to_string().len());
            assert!(!property.to_string().is_empty());
            assert!(property.to_string().len() < 255);
            properties_total += property.to_string().len();
        }
        println!("Total properties size: {properties_total}");

        let dns_record = encode_txt(properties.iter());
        println!("DNS record size: {}", dns_record.len());
        assert!(dns_record.len() < 512);
    }
}
