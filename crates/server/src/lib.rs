// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_common::URL_PROTOCOL;
use conclave_common::net::{DefaultEncryptedStream, random_keypair};
use conclave_common::server::{
    ClientMessagesEncrypted, ConnectedUser, ServerError, ServerInformation,
    ServerMessagesEncrypted, UserAuthentication, unencrypted,
};
use conclave_common::tracker::Advertise;
use conclave_common::tracker::TrackerProtocol::AdvertiseServer;

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow, bail, ensure};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_sqlite::rusqlite::fallible_iterator::FallibleIterator;
use async_sqlite::rusqlite::{Batch, Connection, OptionalExtension};
use async_sqlite::{Client, ClientBuilder, JournalMode};
use chrono::{DateTime, Duration, Local, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use semver::Version;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
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
    /// Encrypted connection to the client
    conn: Arc<RwLock<DefaultEncryptedStream>>,

    /// User information
    user: Arc<ConnectedUser>,

    /// Client's address
    addr: Arc<SocketAddr>,
}

impl Clone for ClientConnection {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            user: self.user.clone(),
            addr: self.addr.clone(),
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
    /// Server name
    name: String,

    /// Server description
    description: String,

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

    /// Trackers, expected to be IP:PORT
    trackers: Arc<RwLock<Vec<(String, u16)>>>,

    /// Whether the tracker advertisements should be running
    tracker_advertise: Arc<AtomicBool>,

    /// Active connections
    connections: Arc<RwLock<Vec<ClientConnection>>>,

    /// Total visitors
    total_visits: Arc<AtomicU32>,

    /// Whether the server is currently serving requests
    serving: Arc<AtomicBool>,

    /// Advertising via Multicast DNS
    mdns: Option<ServiceDaemon>,

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
        write!(f, "Conclave Server: {}", self.name)
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let connections = futures::executor::block_on(self.connections.read()).len();
        write!(
            f,
            "Conclave Server {} with {connections} connections",
            self.name
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
                name,
                description,
                url,
                ip,
                port,
                started: Local::now().to_utc(),
                public_key,
                private_key,
                sqlite,
                trackers: Arc::new(RwLock::new(Vec::new())),
                tracker_advertise: Arc::new(AtomicBool::new(false)),
                connections: Arc::new(RwLock::new(Vec::new())),
                total_visits: Arc::new(AtomicU32::new(0)),
                serving: Arc::new(AtomicBool::new(false)),
                mdns: mdns.then(|| ServiceDaemon::new().expect("Failed to start Multicast DNS")),
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
    pub fn load<P: AsRef<Path>>(ip: IpAddr, port: u16, mdns: bool, sqlite_path: P) -> Result<Self> {
        ensure!(
            sqlite_path.as_ref().exists(),
            "Database file does not exist"
        );
        ensure!(
            sqlite_path.as_ref().is_file(),
            "Database path is not a file"
        );

        let (name, description, private_key, public_key, url, trackers) = {
            let conn = Connection::open(&sqlite_path)?;
            let mut stmt = conn
                .prepare("SELECT name, description, key, version, advertised_domain, trackers FROM SERVER_CONFIG")?;
            let (name, description, keypair, version, advertised_domain, trackers_string) = stmt
                .query_row([], |row| {
                    let name: String = row.get(0)?;
                    let description: String = row.get(1)?;
                    let key_string: String = row.get(2)?;
                    let version: String = row.get(3)?;
                    let advertised_domain: Option<String> = row.get(4)?;
                    let trackers: Option<String> = row.get(5)?;
                    Ok((
                        name,
                        description,
                        key_string,
                        version,
                        advertised_domain,
                        trackers.unwrap_or_default(),
                    ))
                })?;

            let keypair = hex::decode(keypair)?;
            let keypair: [u8; 64] = keypair
                .try_into()
                .map_err(|_| anyhow!("Invalid keypair length"))?;

            let private_key = SigningKey::from_keypair_bytes(&keypair)
                .map_err(|_| anyhow!("Invalid private key"))?;
            let public_key = private_key.verifying_key();

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

            let mut trackers = Vec::new();

            if !trackers_string.is_empty() {
                for tracker in trackers_string.split('|') {
                    let mut tracker_parts = tracker.split(':');
                    let ip = tracker_parts
                        .next()
                        .ok_or_else(|| anyhow!("Invalid tracker IP"))?;
                    let port: u16 = tracker_parts
                        .next()
                        .ok_or_else(|| anyhow!("Invalid tracker port"))?
                        .parse()?;
                    trackers.push((ip.to_string(), port));
                }
            }

            let url = if let Some(advertised_domain) = advertised_domain {
                format!("{URL_PROTOCOL}{advertised_domain}:{port}")
            } else {
                format!("{URL_PROTOCOL}{ip}:{port}")
            };

            (name, description, private_key, public_key, url, trackers)
        };

        let sqlite = ClientBuilder::new()
            .journal_mode(JournalMode::Wal)
            .path(sqlite_path)
            .open_blocking()?;

        Ok(Self {
            name,
            description,
            url,
            ip,
            port,
            started: Local::now().to_utc(),
            public_key,
            private_key,
            sqlite,
            trackers: Arc::new(RwLock::new(trackers)),
            tracker_advertise: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(RwLock::new(Vec::new())),
            total_visits: Arc::new(AtomicU32::new(0)),
            serving: Arc::new(AtomicBool::new(false)),
            mdns: mdns.then(|| ServiceDaemon::new().expect("Failed to start Multicast DNS")),
            #[cfg(feature = "gui")]
            log: false,
            #[cfg(feature = "gui")]
            password: None,
            #[cfg(feature = "gui")]
            password_acknowledged: Arc::new(AtomicBool::new(true)),
        })
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
    pub async fn anonymous_clients_allowed(&self) -> Result<bool> {
        let anonymous = self
            .sqlite
            .conn(move |conn| {
                conn.query_one(
                    "SELECT allow_anonymous_clients FROM SERVER_CONFIG;",
                    [],
                    |row| {
                        let anonymous: bool = row.get(0)?;
                        Ok(anonymous)
                    },
                )
            })
            .await?;
        Ok(anonymous)
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
        Ok(())
    }

    /// Authenticate a user, returns the user's ID if authenticated
    ///
    /// # Errors
    ///
    /// Errors result if the password is incorrect, of the user doesn't have a password or doesn't exist,
    /// or if there's a database error.
    pub async fn authenticate_user(&self, auth: UserAuthentication) -> Result<u32> {
        let auth_clone = auth.clone();
        let (id, db_password) = self
            .sqlite
            .conn(move |conn| {
                conn.query_one(
                    "SELECT id, password FROM USER WHERE username = ?1;",
                    [&auth_clone.username],
                    |row| {
                        let id: i32 = row.get(0)?;
                        let password: String = row.get(1)?;
                        Ok((id, password))
                    },
                )
            })
            .await?;

        let password_hashed = PasswordHash::new(&db_password)?;
        Argon2::default().verify_password(auth.password.as_ref(), &password_hashed)?;

        Ok(u32::try_from(id)?)
    }

    /// Create a new user
    ///
    /// # Errors
    ///
    /// Returns an error if the username already exists or if there's a database error.
    pub async fn create_user(&self, username: String, password: &str) -> Result<()> {
        let username_clone = username.clone();
        let user_id = self
            .sqlite
            .conn(move |conn| {
                conn.query_one(
                    "SELECT id from USER where username = ?1;",
                    [username_clone],
                    |row| {
                        let id: Option<i32> = row.get(0)?;
                        Ok(id)
                    },
                )
                .optional()
            })
            .await?;

        ensure!(user_id.is_none(), "User already exists");

        let hashed_password = hash_password(password);
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "INSERT INTO USER(username, password) VALUES(?1, ?2);",
                    [username, hashed_password],
                )
            })
            .await?;

        Ok(())
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

    /// Add a tracker to the server configuration
    ///
    /// # Errors
    ///
    /// An error might occur if there's a database update problem.
    pub async fn add_tracker(&self, ip: IpAddr, port: u16) -> Result<()> {
        let mut trackers = self.trackers.write().await;
        trackers.push((ip.to_string(), port));

        let trackers = trackers
            .iter()
            .map(|(ip, port)| format!("{ip}:{port}"))
            .collect::<Vec<_>>()
            .join("|");
        self.sqlite
            .conn(move |conn| {
                let mut stmt = conn.prepare("UPDATE SERVER_CONFIG SET trackers = ?1")?;
                stmt.execute([&trackers])
            })
            .await?;

        Ok(())
    }

    /// Advertise the server to tracker(s).
    ///
    /// # Errors
    ///
    /// Returns an error if there's a network problem.
    fn advertise_trackers(&self) -> Result<()> {
        if self.tracker_advertise.load(Ordering::Relaxed) {
            bail!("Already advertising to trackers");
        }

        self.tracker_advertise.store(true, Ordering::Relaxed);
        let self_clone = self.clone();

        tokio::spawn(async move {
            loop {
                let self_clone = self_clone.clone();
                let advert = AdvertiseServer(Advertise {
                    name: self_clone.name.clone(),
                    description: self_clone.description.clone(),
                    version: VERSION.clone(),
                    anonymous: self_clone
                        .anonymous_clients_allowed()
                        .await
                        .unwrap_or_default(),
                    users_connected: u32::try_from(self_clone.connected_users().await.len())
                        .unwrap_or_default(),
                    uptime: self_clone.since(),
                    url: self_clone.url.clone(),
                    key: self_clone.public_key,
                });

                for (tracker_host, tracker_port) in self_clone.trackers.read().await.iter() {
                    let Ok(mut stream) =
                        TcpStream::connect(format!("{tracker_host}:{tracker_port}")).await
                    else {
                        error!("Failed to connect to tracker {tracker_host}:{tracker_port}");
                        continue;
                    };

                    if let Err(e) = advert.send(&mut stream).await {
                        error!("Failed to send advertise message: {e}");
                    }
                }

                if !self_clone.tracker_advertise.load(Ordering::Relaxed) {
                    break;
                }

                tokio::time::sleep(Duration::seconds(30).to_std().unwrap()).await;
            }
        });

        self.tracker_advertise.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Run the server logic, does not return.
    ///
    /// # Errors
    ///
    /// An error returns if there's a network or database problem.
    #[allow(clippy::too_many_lines)]
    #[tracing::instrument]
    pub async fn serve(&self) -> Result<()> {
        self.advertise_trackers()?;
        self.serving.store(true, Ordering::Relaxed);
        let self_clone = self.clone();

        if let Some(mdns) = &self_clone.mdns {
            let service = self_clone.mdns_service_info()?;
            trace!("Registering MDNS service...");
            mdns.register(service)?;
        }

        let disconnect_bytes = ServerMessagesEncrypted::Disconnect.to_vec();
        let listener = TcpListener::bind((self.ip, self.port)).await?;
        tokio::spawn(async move {
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
                                            let user_id = if let Some(inner_auth) = auth {
                                                if let Ok(user_id) =
                                                    self_clone.authenticate_user(inner_auth).await
                                                {
                                                    Some(user_id)
                                                } else {
                                                    let error_message =
                                                        ClientMessagesEncrypted::Error(
                                                            ServerError::AuthenticationFailed,
                                                        )
                                                        .to_vec();
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
                                                .anonymous_clients_allowed()
                                                .await
                                                .unwrap_or(false)
                                            {
                                                None
                                            } else {
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

                                            let server_bytes =
                                                ClientMessagesEncrypted::ServerInformationResponse(
                                                    ServerInformation {
                                                        name: self_clone.name.clone(),
                                                        description: self_clone.description.clone(),
                                                        url: self_clone.url.clone(),
                                                        key: self_clone.public_key,
                                                        version: VERSION.clone(),
                                                        anonymous: false,
                                                        users_connected: u32::try_from(
                                                            self_clone
                                                                .connections
                                                                .read()
                                                                .await
                                                                .len(),
                                                        )
                                                        .unwrap_or_default(),
                                                    },
                                                )
                                                .to_vec();
                                            if let Err(e) = stream.send(&server_bytes).await {
                                                error!(
                                                    "Failed to send server info to {client}: {e}"
                                                );
                                                continue;
                                            }

                                            let connection = ClientConnection {
                                                conn: Arc::new(RwLock::new(stream)),
                                                user: Arc::new(ConnectedUser {
                                                    display_name,
                                                    admin: false,
                                                    connected_since: Duration::default(),
                                                    user_id,
                                                    timezone: user_local_time,
                                                }),
                                                addr: Arc::new(client),
                                            };
                                            self_clone.connections.write().await.push(connection);
                                        }
                                        Ok(_) => {
                                            if let Err(e) = stream.send(&disconnect_bytes).await {
                                                error!(
                                                    "Failed to send keep alive to {client}: {e}"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            error!("Error decoding message from {client}: {e}");
                                        }
                                    },
                                    Err(e) => {
                                        error!("Error decoding message from {client}: {e}");
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

        let keep_alive_bytes = ServerMessagesEncrypted::KeepAlive.to_vec();

        while self.serving.load(Ordering::Relaxed) {
            let mut to_disconnect = Vec::new();
            for (index, client) in self.connections.read().await.iter().enumerate() {
                let mut conn = client.conn.write().await;
                let Ok(message) = conn.recv().await else {
                    continue;
                };
                match ServerMessagesEncrypted::from_bytes(&message) {
                    Ok(ServerMessagesEncrypted::KeepAlive) => {
                        if let Err(e) = conn.send(&keep_alive_bytes).await {
                            error!("Failed to send keep alive: {e}");
                        }
                    }

                    Ok(ServerMessagesEncrypted::ServerInformationRequest) => {
                        let connections = self.connections.read().await;
                        let info =
                            ClientMessagesEncrypted::ServerInformationResponse(ServerInformation {
                                name: self.name.clone(),
                                description: self.description.clone(),
                                url: self.url.clone(),
                                key: self.public_key,
                                version: VERSION.clone(),
                                anonymous: false,
                                users_connected: u32::try_from(connections.len())
                                    .unwrap_or_default(),
                            })
                            .to_vec();
                        if let Err(e) = conn.send(&info).await {
                            error!("Failed to send server info response: {e}");
                        }
                    }

                    Ok(ServerMessagesEncrypted::Disconnect) => {
                        to_disconnect.push(index);
                    }

                    Ok(ServerMessagesEncrypted::ListConnectedUsersRequest) => {
                        let connected_users = self.connected_users().await;
                        let response =
                            ClientMessagesEncrypted::ListConnectedUsersResponse(connected_users)
                                .to_vec();
                        if let Err(e) = conn.send(&response).await {
                            error!("Failed to send list connected users response: {e}");
                        }
                    }

                    Ok(x) => {
                        error!("Unexpected message from {client:?}: {x:?}");
                        break;
                    }
                    Err(e) => {
                        error!("Error decoding message from {client:?}: {e}");
                        break;
                    }
                }
            }

            if !to_disconnect.is_empty() {
                let mut connections = self.connections.write().await;
                to_disconnect.sort_unstable();
                to_disconnect.reverse();
                for index in to_disconnect {
                    connections.remove(index);
                }
            }
        }

        Ok(())
    }

    /// Get a list of connected users
    pub async fn connected_users(&self) -> Vec<ConnectedUser> {
        let connections = self.connections.read().await;
        info!("Server: got read lock on connections");
        connections
            .iter()
            .map(|conn| (*conn.user).clone())
            .collect()
    }

    fn mdns_service_info(&self) -> mdns_sd::Result<ServiceInfo> {
        use base64::Engine;

        let host_name = format!("{}.local.", self.ip);
        let key_encoded = base64::engine::general_purpose::STANDARD.encode(self.public_key);
        let properties = [
            (conclave_common::MDNS_VERSION, VERSION.to_string()),
            (conclave_common::MDNS_DESCRIPTION, self.description.clone()),
            (conclave_common::MDNS_KEY, key_encoded),
        ];

        let mut service = ServiceInfo::new(
            conclave_common::MDNS_NAME,
            &self.name,
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

#[cfg(feature = "gui")]
impl eframe::App for State {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        use zeroize::Zeroize;

        ui.request_repaint();

        let connections = futures::executor::block_on(self.connections.read()).len();
        eframe::egui::CentralPanel::default().show_inside(ui, |ui| {
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
                        eframe::egui::CentralPanel::default().show_inside(context, |inner_ui| {
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
                        .with_inner_size([200.0, 100.0]),
                    |context, _class| {
                        eframe::egui::CentralPanel::default().show_inside(context, |inner_ui| {
                            inner_ui.label("Log will go here");
                        });
                    },
                );
            }
        });
    }
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
        let state = conclave_tracker::State::<15>::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT, keys);
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

        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
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
            .send(&mut stream)
            .await
            .unwrap();
        }

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

        tokio::time::sleep(state.duration()).await;

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
