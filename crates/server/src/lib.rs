// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_common::URL_PROTOCOL;
use conclave_common::net::{DefaultEncryptedStream, random_server_keys};
use conclave_common::server::{
    ClientMessagesEncrypted, ClientMessagesUnencrypted, ConnectedUser, ServerInformation,
    ServerMessagesEncrypted, ServerMessagesUnencrypted,
};
use conclave_common::tracker::Advertise;
use conclave_common::tracker::TrackerProtocol::AdvertiseServer;

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow, bail, ensure};
use async_sqlite::rusqlite::fallible_iterator::FallibleIterator;
use async_sqlite::rusqlite::{Batch, Connection};
use async_sqlite::{Client, ClientBuilder, JournalMode};
use bytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::{SinkExt, StreamExt};
use semver::Version;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{error, info, warn};

const SCHEMA: &str = include_str!("schema.sql");

static VERSION_SEMVER: LazyLock<Version> =
    LazyLock::new(|| Version::parse(env!("CARGO_PKG_VERSION")).unwrap());

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
#[allow(dead_code)]
pub struct State {
    /// Server name
    name: String,

    /// Server description
    description: String,

    /// Advertised URL
    url: String,

    /// Listening IP
    ip: IpAddr,

    /// Unencrypted Server port
    unc_port: u16,

    /// Encrypted Server port
    enc_port: u16,

    /// When the server started
    started: SystemTime,

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
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conclave Server: {}", self.name)
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conclave Server: {}", self.name)
    }
}

impl State {
    /// Create a new server state
    ///
    /// # Errors
    ///
    /// An error results if the database creation fails, including inability to write to the provided file path.
    pub fn new<P: AsRef<Path>>(
        name: String,
        description: String,
        ip: IpAddr,
        unc_port: u16,
        enc_port: u16,
        sqlite_path: P,
    ) -> Result<Self> {
        ensure!(
            !sqlite_path.as_ref().exists(),
            "Database path already exists"
        );
        let (private_key, public_key) = random_server_keys();

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
        }

        let sqlite = ClientBuilder::new()
            .journal_mode(JournalMode::Wal)
            .path(sqlite_path)
            .open_blocking()?;

        Ok(Self {
            name,
            description,
            url: format!("{URL_PROTOCOL}{ip}:{unc_port}"),
            ip,
            enc_port,
            unc_port,
            started: SystemTime::now(),
            public_key,
            private_key,
            sqlite,
            trackers: Arc::new(RwLock::new(Vec::new())),
            tracker_advertise: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(RwLock::new(Vec::new())),
            total_visits: Arc::new(AtomicU32::new(0)),
            serving: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Load a server from an existing database
    ///
    /// # Errors
    ///
    /// An error results if the database can't be read.
    pub fn load<P: AsRef<Path>>(
        ip: IpAddr,
        enc_port: u16,
        unc_port: u16,
        sqlite_path: P,
    ) -> Result<Self> {
        ensure!(
            sqlite_path.as_ref().exists(),
            "Database file does not exist"
        );
        ensure!(
            sqlite_path.as_ref().is_file(),
            "Database path is not a file"
        );

        let (name, description, private_key, public_key, trackers) = {
            let conn = Connection::open(&sqlite_path)?;
            let mut stmt = conn
                .prepare("SELECT name, description, key, version, trackers FROM SERVER_CONFIG")?;
            let (name, description, keypair, version, trackers_string) =
                stmt.query_row([], |row| {
                    let name: String = row.get(0)?;
                    let description: String = row.get(1)?;
                    let key_string: String = row.get(2)?;
                    let version: String = row.get(3)?;
                    let trackers: Option<String> = row.get(4)?;
                    Ok((
                        name,
                        description,
                        key_string,
                        version,
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

            (name, description, private_key, public_key, trackers)
        };

        let sqlite = ClientBuilder::new()
            .journal_mode(JournalMode::Wal)
            .path(sqlite_path)
            .open_blocking()?;

        Ok(Self {
            name,
            description,
            url: format!("{URL_PROTOCOL}{ip}:{unc_port}"),
            ip,
            unc_port,
            enc_port,
            started: SystemTime::now(),
            public_key,
            private_key,
            sqlite,
            trackers: Arc::new(RwLock::new(trackers)),
            tracker_advertise: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(RwLock::new(Vec::new())),
            total_visits: Arc::new(AtomicU32::new(0)),
            serving: Arc::new(AtomicBool::new(false)),
        })
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
                    version: VERSION_SEMVER.clone(),
                    anonymous: false,
                    users_connected: u32::try_from(self_clone.connected_users().await.len())
                        .unwrap_or_default(),
                    uptime: self_clone.started.elapsed().unwrap_or_default(),
                    url: self_clone.url.clone(),
                    key: self_clone.public_key,
                });

                for (tracker_host, tracker_port) in self_clone.trackers.read().await.iter() {
                    let Ok(stream) =
                        TcpStream::connect(format!("{tracker_host}:{tracker_port}")).await
                    else {
                        error!("Failed to connect to tracker {tracker_host}:{tracker_port}");
                        continue;
                    };
                    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
                    let serialized = match postcard::to_stdvec(&advert) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            error!("Failed to serialize advertise message: {e}");
                            continue;
                        }
                    };
                    if let Err(e) = framed.send(Bytes::from(serialized)).await {
                        error!("Failed to send advertise message: {e}");
                    }
                }

                if !self_clone.tracker_advertise.load(Ordering::Relaxed) {
                    break;
                }

                tokio::time::sleep(Duration::from_secs(30)).await;
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
        let server_key_port =
            ClientMessagesUnencrypted::KeyResponse((self.enc_port, self.public_key));
        let server_key_port = postcard::to_allocvec(&server_key_port)?;
        self.advertise_trackers()?;
        self.serving.store(true, Ordering::Relaxed);
        let self_clone = self.clone();

        tokio::spawn(async move {
            self_clone.serve_encrypted().await;
        });

        let unc_listener = TcpListener::bind((self.ip, self.enc_port)).await?;
        let _keep_alive_bytes = postcard::to_stdvec(&ServerMessagesEncrypted::KeepAlive)?;
        let disconnect_bytes = postcard::to_stdvec(&ServerMessagesEncrypted::Disconnect)?;
        let enc_clone = self.clone();
        tokio::spawn(async move {
            loop {
                match unc_listener.accept().await {
                    Ok((socket, client)) => {
                        match DefaultEncryptedStream::accept(socket, &enc_clone.private_key).await {
                            Ok(mut stream) => {
                                match stream.recv().await {
                                    Ok(bytes) => {
                                        match postcard::from_bytes::<ServerMessagesEncrypted>(&bytes) {
                                            Ok(ServerMessagesEncrypted::ServerAuthenticationRequest(_auth)) => {
                                                let server_info = ServerInformation {
                                                    name: enc_clone.name.clone(),
                                                    description: enc_clone.description.clone(),
                                                    url: enc_clone.url.clone(),
                                                    key: enc_clone.public_key,
                                                    version: VERSION_SEMVER.clone(),
                                                    anonymous: false,
                                                    users_connected: u32::try_from(enc_clone.connections.read().await.len()).unwrap_or_default(),
                                                };
                                                let Ok(server_bytes) = postcard::to_stdvec(&server_info) else {
                                                    error!("Failed to serialize server info");
                                                    continue;
                                                };
                                                if let Err(e) = stream.send(&server_bytes).await {
                                                    error!("Failed to send server info to {client}: {e}");
                                                    continue;
                                                }
                                                let connection = ClientConnection {
                                                    conn: Arc::new(RwLock::new(stream)),
                                                    user: Arc::new(ConnectedUser {
                                                        display_name: "Unnamed".to_string(),
                                                        authenticated: false,
                                                        admin: false,
                                                        connected_since: Duration::default(),
                                                    }),
                                                    addr: Arc::new(client),
                                                };
                                                enc_clone.connections.write().await.push(connection);
                                            }
                                            Ok(_) => {
                                                if let Err(e) = stream.send(&disconnect_bytes).await {
                                                    error!("Failed to send keep alive to {client}: {e}");
                                                }
                                            }
                                            Err(e) => {
                                                error!("Error decoding message from {client}: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Error receiving encrypted connection: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Error accepting encrypted connection: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error accepting encrypted connection: {e}");
                    }
                }
            }
        });

        let unc_listener = TcpListener::bind((self.ip, self.unc_port)).await?;
        loop {
            match unc_listener.accept().await {
                Ok((socket, client)) => {
                    let mut framed = Framed::new(socket, LengthDelimitedCodec::new());
                    match framed.next().await {
                        Some(Ok(bytes)) => {
                            match postcard::from_bytes::<ServerMessagesUnencrypted>(&bytes) {
                                Ok(msg) => match msg {
                                    ServerMessagesUnencrypted::KeyRequest => {
                                        if let Err(e) =
                                            framed.send(Bytes::from(server_key_port.clone())).await
                                        {
                                            error!("Failed to send key response: {e}");
                                        }
                                    }
                                    ServerMessagesUnencrypted::Disconnect => {
                                        if let Err(e) = framed.close().await {
                                            error!("Failed to close connection: {e}");
                                        }
                                        break;
                                    }
                                },
                                Err(e) => {
                                    error!("Error decoding message from {client}: {e}");
                                }
                            }
                        }
                        None => {}
                        Some(Err(e)) => {
                            error!("Error decoding message from {client}: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!("Error accepting unencrypted connection: {e}");
                }
            }
        }

        #[allow(unreachable_code)]
        self.serving.store(false, Ordering::Relaxed);

        Ok(())
    }

    #[tracing::instrument]
    async fn serve_encrypted(&self) {
        let keep_alive_bytes = postcard::to_stdvec(&ServerMessagesEncrypted::KeepAlive).unwrap();

        loop {
            let mut to_disconnect = Vec::new();
            for (index, client) in self.connections.read().await.iter().enumerate() {
                let mut conn = client.conn.write().await;
                let Ok(message) = conn.recv().await else {
                    continue;
                };
                match postcard::from_bytes::<ServerMessagesEncrypted>(&message) {
                    Ok(ServerMessagesEncrypted::KeepAlive) => {
                        if let Err(e) = conn.send(&keep_alive_bytes).await {
                            error!("Failed to send keep alive: {e}");
                        }
                    }

                    Ok(ServerMessagesEncrypted::ServerInformationRequest) => {
                        let connections = self.connections.read().await;
                        let info = ServerInformation {
                            name: self.name.clone(),
                            description: self.description.clone(),
                            url: self.url.clone(),
                            key: self.public_key,
                            version: VERSION_SEMVER.clone(),
                            anonymous: false,
                            users_connected: u32::try_from(connections.len()).unwrap_or_default(),
                        };
                        let response = match postcard::to_stdvec(&info) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                error!("Failed to serialize server info: {e}");
                                continue;
                            }
                        };
                        if let Err(e) = conn.send(&response).await {
                            error!("Failed to send server info response: {e}");
                        }
                    }

                    Ok(ServerMessagesEncrypted::Disconnect) => {
                        to_disconnect.push(index);
                    }

                    Ok(ServerMessagesEncrypted::ListConnectedUsersRequest) => {
                        let connected_users = self.connected_users().await;
                        let response =
                            ClientMessagesEncrypted::ListConnectedUsersResponse(connected_users);
                        let response = match postcard::to_stdvec(&response) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                error!("Failed to serialize list connected users response: {e}");
                                continue;
                            }
                        };
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
}

#[cfg(test)]
mod tests {
    use conclave_common::net::random_server_keys;
    use conclave_common::tracker::TrackerProtocol::AdvertiseServer;
    use conclave_common::tracker::{Advertise, TrackerProtocol};

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpStream;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn advertise() {
        const PORT: u16 = 8080;

        conclave_common::init_tracing();

        let version = env!("CARGO_PKG_VERSION").parse().unwrap();
        let state = conclave_tracker::State::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT);
        let (_server_signing, server_verifying) = random_server_keys();

        let state_clone = state.clone();
        let tracker = tokio::spawn(async move {
            state_clone.serve().await.expect("Failed to start tracker");
        });
        assert!(!tracker.is_finished());
        tokio::time::sleep(Duration::from_secs(1)).await;

        {
            let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            let serialized = postcard::to_stdvec(&TrackerProtocol::GetServers).unwrap();
            framed.send(Bytes::from(serialized)).await.unwrap();
            if let Some(res_result) = framed.next().await {
                let bytes = res_result.unwrap();
                let resp: TrackerProtocol = postcard::from_bytes(&bytes).unwrap();
                match resp {
                    TrackerProtocol::ServersList(servers) => {
                        assert!(servers.is_empty());
                    }
                    _ => panic!("Unexpected response type"),
                }
            }
        }

        {
            let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            let server = AdvertiseServer(Advertise {
                name: "Testing".to_string(),
                description: "Testing".to_string(),
                version,
                anonymous: false,
                users_connected: 0,
                uptime: Duration::from_secs(0),
                url: String::new(),
                key: server_verifying,
            });
            let serialized = postcard::to_stdvec(&server).unwrap();
            framed.send(Bytes::from(serialized)).await.unwrap();
        }

        {
            let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            let serialized = postcard::to_stdvec(&TrackerProtocol::GetServers).unwrap();
            framed.send(Bytes::from(serialized)).await.unwrap();
            if let Some(res_result) = framed.next().await {
                let bytes = res_result.unwrap();
                let resp: TrackerProtocol = postcard::from_bytes(&bytes).unwrap();
                match resp {
                    TrackerProtocol::ServersList(servers) => {
                        assert_eq!(servers.len(), 1);
                        assert_eq!(servers[0].name, "Testing");
                    }
                    _ => panic!("Unexpected response type"),
                }
            }
        }
        assert_eq!(state.servers().len(), 1);

        tokio::time::sleep(conclave_common::tracker::SERVER_EXPIRATION).await;

        {
            let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            let serialized = postcard::to_stdvec(&TrackerProtocol::GetServers).unwrap();
            framed.send(Bytes::from(serialized)).await.unwrap();
            if let Some(res_result) = framed.next().await {
                let bytes = res_result.unwrap();
                let resp: TrackerProtocol = postcard::from_bytes(&bytes).unwrap();
                match resp {
                    TrackerProtocol::ServersList(servers) => {
                        assert!(servers.is_empty());
                    }
                    _ => panic!("Unexpected response type"),
                }
            }
        }
        assert!(state.servers().is_empty());

        tracker.abort();
    }
}
