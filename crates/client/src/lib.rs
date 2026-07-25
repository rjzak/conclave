// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

/// Admin GUI elements
pub mod adminui;

/// Avatar image handling: normalising, thumbnailing, decoding, and config serde.
pub mod avatar;

/// Client configuration file data structures and I/O functions.
pub mod config;

/// Server connection management and protocol handling.
pub mod conn;

use crate::config::{BookmarkEntry, ClientConfig};
use crate::conn::ConclaveConnection;
use conclave_common::net::{DefaultEncryptedStream, EncryptedStream};
use conclave_common::server::{
    AuthRequest, ClientMessagesEncrypted, ServerInformation, ServerMessagesEncrypted,
    UserAuthentication, VerifyingKey, unencrypted,
};
use conclave_common::tracker::{Advertise, Tracker, TrackerProtocol, TrackerWithKey};

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow, bail, ensure};
use dashmap::DashSet;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use semver::Version;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{error, info, trace, warn};

/// Conclave version
pub static VERSION: LazyLock<Version> =
    LazyLock::new(|| Version::parse(env!("CONCLAVE_VERSION")).unwrap());

/// Conclave client
pub struct Client {
    /// Active connections to various services
    connection: Arc<RwLock<Vec<ConclaveConnection>>>,

    /// Trackers, domain or IP and port
    trackers: Arc<DashSet<TrackerWithKey>>,

    /// Config file path
    config_file: PathBuf,

    /// Client's config
    config: Arc<RwLock<ClientConfig>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conclave Client")
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conclave Client")
    }
}

// TODO: Save and reuse tracker keys
// TODO: Only ask for tracker key once

impl Client {
    /// Create a client from a path to a config file. If the file doesn't exist,
    /// a default config will be created and saved to the path.
    ///
    /// # Errors
    ///
    /// An error may result if a config file can't be created.
    pub fn new<P: AsRef<Path>>(config: P) -> Result<Self> {
        let path = PathBuf::from(config.as_ref());
        let config = if path.exists() {
            ClientConfig::load(&path)?
        } else {
            let conf = ClientConfig::default();
            conf.save(&path)?;
            conf
        };

        Ok(Self {
            connection: Arc::new(RwLock::new(Vec::new())),
            trackers: Arc::new(DashSet::from_iter(config.trackers.clone())),
            config_file: path,
            config: Arc::new(RwLock::new(config)),
        })
    }

    /// Update the user's default display name and write to the config file.
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn update_default_username(&self, username: &String) -> Result<()> {
        self.config
            .write()
            .await
            .default_display_name
            .clone_from(username);
        self.config.read().await.save(&self.config_file)
    }

    /// Add a tracker to the list of known trackers and update the database
    ///
    /// # Errors
    ///
    /// Returns errors if there is a database error
    pub async fn add_tracker(&self, tracker: &Tracker) -> Result<()> {
        let tracker_with_key = tracker.as_with_key().await?;
        self.add_tracker_with_key(tracker_with_key).await
    }

    /// Add a tracker to the list of known trackers and update the database
    ///
    /// # Errors
    ///
    /// Returns errors if there is a database error
    pub async fn add_tracker_with_key(&self, tracker_with_key: TrackerWithKey) -> Result<()> {
        if let Some(existing_entry) = self.trackers.get(&tracker_with_key) {
            trace!(
                "Tracker {}:{} already known",
                tracker_with_key.host, tracker_with_key.port
            );
            ensure!(
                existing_entry.key == tracker_with_key.key,
                "Tracker key mismatch!"
            );
        } else {
            trace!(
                "Adding tracker {}:{} to database",
                tracker_with_key.host, tracker_with_key.port
            );
            self.trackers.insert(tracker_with_key.clone());
            self.config.write().await.trackers.push(tracker_with_key);
            self.config.read().await.save(&self.config_file)?;
        }

        Ok(())
    }

    /// Remove a tracker from the list of known trackers and from the database
    ///
    /// # Errors
    ///
    /// Returns errors if there is a database error
    pub async fn remove_tracker(&self, tracker_name: &str, tracker_port: u16) -> Result<()> {
        let mut to_remove = None;
        for tracker in self.trackers.iter() {
            if tracker.host == tracker_name && tracker.port == tracker_port {
                to_remove = Some(tracker.clone());
                break;
            }
        }
        if let Some(to_remove) = to_remove {
            self.trackers.remove(&to_remove);
        }

        let tracker_name = String::from(tracker_name);
        trace!(
            "Removing tracker {}:{} from database",
            tracker_name, tracker_port
        );
        self.config
            .write()
            .await
            .trackers
            .retain(|t| t.host != tracker_name || t.port != tracker_port);
        self.config.read().await.save(&self.config_file)?;

        Ok(())
    }

    /// Get the client's trackers to show to the user. Creates a clone of each tracker.
    #[inline]
    #[must_use]
    pub fn list_trackers(&self) -> Vec<TrackerWithKey> {
        self.trackers.as_ref().iter().map(|t| t.clone()).collect()
    }

    /// Get a list of unique servers from all the known trackers.
    ///
    /// # Errors
    ///
    /// Errors may arise from network problems.
    pub async fn list_servers_from_trackers(&self) -> Result<HashSet<Advertise>> {
        let mut servers_set = HashSet::new();

        info!(
            "Requesting servers list from {} trackers",
            self.trackers.len()
        );
        for tracker in self.trackers.iter() {
            info!("Connecting to tracker {}:{}", tracker.host, tracker.port);
            let mut stream =
                TcpStream::connect(format!("{}:{}", tracker.host, tracker.port)).await?;

            if let Err(e) = TrackerProtocol::GetServers.send(&mut stream).await {
                error!("Error sending server list request to tracker: {e}");
                continue;
            }

            let servers = match TrackerProtocol::receive(&mut stream).await {
                Ok(TrackerProtocol::ServersList(servers)) => servers,
                Ok(_) => {
                    error!("Error unexpected response from tracker");
                    continue;
                }
                Err(e) => {
                    error!("Error getting server list from tracker: {e}");
                    continue;
                }
            };

            info!(
                "Received {} servers list from tracker {}:{}: {:?}",
                servers.servers.len(),
                tracker.host,
                tracker.port,
                servers
                    .servers
                    .iter()
                    .map(|s| s.name.clone())
                    .collect::<Vec<_>>()
            );
            if servers.version > *VERSION {
                warn!(
                    "Tracker version {} is newer than client version {}",
                    servers.version, *VERSION
                );
            }
            if servers.verify(&tracker.key) {
                servers_set.extend(servers.servers);
            } else {
                warn!("Received server list from tracker but the signature was invalid.");
            }
        }

        Ok(servers_set)
    }

    /// Subscribe to every configured tracker for a live server listing.
    ///
    /// Spawns a background task per tracker that holds a persistent connection
    /// and rewrites `out` with the merged, de-duplicated set of advertised
    /// servers each time any tracker pushes a change. Dropping the returned
    /// handle (or sending `true` on it) stops every task.
    #[must_use]
    pub fn watch_servers_from_trackers(
        &self,
        out: &Arc<std::sync::RwLock<Vec<Advertise>>>,
    ) -> tokio::sync::watch::Sender<bool> {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        // Latest listing per tracker (keyed by address), merged into `out`.
        let latest: Arc<RwLock<std::collections::HashMap<String, Vec<Advertise>>>> =
            Arc::new(RwLock::new(std::collections::HashMap::new()));

        for tracker in self.list_trackers() {
            let out = out.clone();
            let latest = latest.clone();
            let stop_rx = stop_rx.clone();
            tokio::spawn(async move {
                Self::watch_one_tracker(tracker, out, latest, stop_rx).await;
            });
        }

        stop_tx
    }

    /// Hold a persistent subscription to a single tracker, applying every pushed
    /// listing until stopped. Reconnects with a short delay after any drop.
    async fn watch_one_tracker(
        tracker: TrackerWithKey,
        out: Arc<std::sync::RwLock<Vec<Advertise>>>,
        latest: Arc<RwLock<std::collections::HashMap<String, Vec<Advertise>>>>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let addr = format!("{}:{}", tracker.host, tracker.port);

        while !*stop.borrow() {
            let mut stream = match TcpStream::connect(&addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("Failed to connect to tracker {addr}: {e}");
                    if stop_or_delay(&mut stop).await {
                        return;
                    }
                    continue;
                }
            };

            if let Err(e) = TrackerProtocol::Subscribe.send(&mut stream).await {
                error!("Failed to subscribe to tracker {addr}: {e}");
                if stop_or_delay(&mut stop).await {
                    return;
                }
                continue;
            }

            loop {
                tokio::select! {
                    // Stop signalled, or the sender was dropped: exit and let the
                    // in-flight read be cancelled (the stream is discarded).
                    _ = stop.changed() => return,
                    message = TrackerProtocol::receive(&mut stream) => {
                        match message {
                            Ok(TrackerProtocol::ServersList(list)) => {
                                if list.verify(&tracker.key) {
                                    latest.write().await.insert(addr.clone(), list.servers);
                                    merge_trackers(&latest, &out).await;
                                } else {
                                    warn!("Invalid signature from tracker {addr}");
                                }
                            }
                            Ok(_) => {}
                            // Disconnected: reconnect after a delay.
                            Err(_) => break,
                        }
                    }
                }
            }

            // Forget this tracker's servers so they don't linger while we're
            // disconnected, then push the merged view.
            latest.write().await.remove(&addr);
            merge_trackers(&latest, &out).await;

            if stop_or_delay(&mut stop).await {
                return;
            }
        }
    }

    /// Fetch a server's public key over the unencrypted channel, without
    /// otherwise connecting. Used when bookmarking a server so the key can be
    /// pinned and displayed.
    ///
    /// # Errors
    ///
    /// Networking errors may result, or the server may not return a key.
    pub async fn fetch_server_key(host: &str, port: u16) -> Result<VerifyingKey> {
        let mut stream = TcpStream::connect(format!("{host}:{port}")).await?;

        info!("Requesting key from server");
        unencrypted::ClientToServer::KeyRequest
            .send(&mut stream)
            .await?;

        let key_response = unencrypted::ServerToClient::receive(&mut stream).await?;
        let unencrypted::ServerToClient::PublicKey(key) = key_response else {
            bail!("Server did not provide a public key")
        };

        info!("Received key from server");
        Ok(key)
    }

    /// Fetch a server's information (name, description, etc.) by performing the
    /// encrypted handshake, without keeping the connection. Requires the
    /// server's key; supply credentials if the server does not allow guests.
    ///
    /// # Errors
    ///
    /// Networking or authentication errors may result.
    pub async fn fetch_server_info(
        host: &str,
        port: u16,
        key: VerifyingKey,
        display_name: &str,
        auth: Option<UserAuthentication>,
    ) -> Result<ServerInformation> {
        let mut stream = TcpStream::connect(format!("{host}:{port}")).await?;
        unencrypted::ClientToServer::GoCrypto
            .send(&mut stream)
            .await?;

        let mut encrypted_stream: DefaultEncryptedStream =
            EncryptedStream::connect(stream, &key, None).await?;

        let login = ServerMessagesEncrypted::ServerAuthenticationRequest(AuthRequest {
            display_name: display_name.to_string(),
            timezone: None,
            avatar: None,
            // A transient info fetch does not register a durable roster entry, so
            // no profile or links are shared here.
            profile: String::new(),
            urls: BTreeMap::new(),
            auth,
        })
        .to_vec();
        encrypted_stream.send(&login).await?;

        let response = encrypted_stream.recv().await?;
        match ClientMessagesEncrypted::from_bytes(&response)? {
            ClientMessagesEncrypted::ServerInformationResponse(info) => Ok(info),
            ClientMessagesEncrypted::Error(error) => Err(error.into()),
            x => Err(anyhow!("Unexpected message from server: {x:?}")),
        }
    }

    /// Add a server bookmark to the config file
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn add_bookmark(&self, bookmark: &BookmarkEntry) -> Result<()> {
        self.config.write().await.bookmarks.push(bookmark.clone());
        self.config.read().await.save(&self.config_file)
    }

    /// Replace the bookmark at `index` and save the config file. Does nothing if
    /// the index is out of range.
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn update_bookmark(&self, index: usize, bookmark: &BookmarkEntry) -> Result<()> {
        {
            let mut config = self.config.write().await;
            if let Some(existing) = config.bookmarks.get_mut(index) {
                *existing = bookmark.clone();
            }
        }
        self.config.read().await.save(&self.config_file)
    }

    /// Remove a server bookmark by server's index in the list
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn remove_bookmark_by_index(&self, index: usize) -> Result<()> {
        self.config.write().await.bookmarks.remove(index);
        self.config.read().await.save(&self.config_file)
    }

    /// Remove a server bookmark by server's IP address or domain name
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn remove_bookmark_by_ip_domain(&self, server: &str) -> Result<()> {
        self.config
            .write()
            .await
            .bookmarks
            .retain(|b| b.server.host != server);
        self.config.read().await.save(&self.config_file)
    }

    /// Remove a server bookmark by server's name
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn remove_bookmark_by_name(&self, name: &str) -> Result<()> {
        self.config
            .write()
            .await
            .bookmarks
            .retain(|b| b.name != name);
        self.config.read().await.save(&self.config_file)
    }

    /// Remove a server bookmark by server's key
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn remove_bookmark_by_key(&self, key: VerifyingKey) -> Result<()> {
        self.config
            .write()
            .await
            .bookmarks
            .retain(|b| b.server.key != key);
        self.config.read().await.save(&self.config_file)
    }

    /// Read the user's configured default display name without blocking.
    #[must_use]
    pub fn default_display_name(&self) -> String {
        self.config
            .try_read()
            .map(|c| c.default_display_name.clone())
            .unwrap_or_default()
    }

    /// Read whether the user wants to share their local timezone by default when
    /// connecting, without blocking.
    #[must_use]
    pub fn default_share_timezone(&self) -> bool {
        self.config
            .try_read()
            .is_ok_and(|c| c.default_share_timezone)
    }

    /// Read the user's saved server bookmarks without blocking.
    #[must_use]
    pub fn bookmarks(&self) -> Vec<BookmarkEntry> {
        self.config
            .try_read()
            .map(|c| c.bookmarks.clone())
            .unwrap_or_default()
    }

    /// Read the user's stored avatar (a 512×512 PNG) without blocking.
    #[must_use]
    pub fn avatar(&self) -> Option<Vec<u8>> {
        self.config.try_read().ok().and_then(|c| c.avatar.clone())
    }

    /// Set (or clear, with `None`) the user's avatar and write to the config
    /// file. The bytes are expected to already be a canonical 512×512 PNG.
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn set_avatar(&self, avatar: Option<Vec<u8>>) -> Result<()> {
        self.config.write().await.avatar = avatar;
        self.config.read().await.save(&self.config_file)
    }

    /// Read the user's default profile text without blocking.
    #[must_use]
    pub fn profile(&self) -> String {
        self.config
            .try_read()
            .map(|c| c.profile.clone())
            .unwrap_or_default()
    }

    /// Read the user's default shared links (description → URL) without blocking.
    #[must_use]
    pub fn urls(&self) -> BTreeMap<String, String> {
        self.config
            .try_read()
            .map(|c| c.urls.clone())
            .unwrap_or_default()
    }

    /// Set the user's default profile text and shared links, then write the
    /// config file. These seed new bookmarks and are used whenever a connection
    /// does not carry a per-server override.
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn set_profile(&self, profile: String, urls: BTreeMap<String, String>) -> Result<()> {
        {
            let mut config = self.config.write().await;
            config.profile = profile;
            config.urls = urls;
        }
        self.config.read().await.save(&self.config_file)
    }

    /// Connect to a server
    ///
    /// # Errors
    ///
    /// Networking errors may result
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        server: &str,
        port: u16,
        share_time: bool,
        display_name: String,
        auth: Option<UserAuthentication>,
        key: Option<VerifyingKey>,
        avatar: Option<Vec<u8>>,
        profile: String,
        urls: BTreeMap<String, String>,
    ) -> Result<ConclaveConnection> {
        let key = if let Some(key) = key {
            key
        } else {
            Self::fetch_server_key(server, port).await?
        };

        let mut stream = TcpStream::connect(format!("{server}:{port}")).await?;

        info!(
            "Connecting to the server on port {port} with key {}",
            hex::encode(key.as_bytes())
        );
        unencrypted::ClientToServer::GoCrypto
            .send(&mut stream)
            .await?;

        let config = self.config.read().await;
        let signing_key = config.signing_key.clone();
        // Derive a small 32×32 thumbnail to share with the server. Prefer the
        // per-connection avatar (e.g. from a bookmark), falling back to the
        // client's default; a decode failure just means no avatar is sent.
        let avatar_thumb = avatar
            .or_else(|| config.avatar.clone())
            .as_deref()
            .and_then(|png| match avatar::thumbnail(png) {
                Ok(thumb) => Some(thumb),
                Err(e) => {
                    warn!("Failed to build avatar thumbnail: {e}");
                    None
                }
            });

        // Share the per-server profile and links when set, otherwise fall back
        // to the client's global defaults.
        let profile = if profile.is_empty() {
            config.profile.clone()
        } else {
            profile
        };
        let urls = if urls.is_empty() {
            config.urls.clone()
        } else {
            urls
        };

        info!("Creating encrypted stream to server");
        let mut encrypted_stream =
            EncryptedStream::connect(stream, &key, Some(&signing_key)).await?;
        info!("Client: EncryptedStream created");

        // Share our timezone as whole hours relative to GMT so peers can compute the
        // difference; keep a copy so the GUI shows offsets relative to us.
        let own_timezone: Option<i16> = share_time.then(|| {
            let seconds = chrono::Local::now().offset().local_minus_utc();
            // Round to the nearest hour (halves away from zero).
            let hours = (seconds + if seconds >= 0 { 1800 } else { -1800 }) / 3600;
            i16::try_from(hours).unwrap_or(0)
        });
        let login = ServerMessagesEncrypted::ServerAuthenticationRequest(AuthRequest {
            display_name: display_name.clone(),
            timezone: own_timezone,
            avatar: avatar_thumb,
            profile,
            urls,
            auth,
        })
        .to_vec();
        encrypted_stream.send(&login).await?;

        info!("Expecting information request");
        let server_info = encrypted_stream.recv().await?;
        let server_info = ClientMessagesEncrypted::from_bytes(&server_info)?;

        match server_info {
            ClientMessagesEncrypted::ServerInformationResponse(server_info) => {
                if server_info.version > *VERSION {
                    warn!(
                        "Server version {} is newer than client version {}",
                        server_info.version, *VERSION
                    );
                }
                let conn = ConclaveConnection::new(
                    encrypted_stream,
                    server_info,
                    &display_name,
                    signing_key,
                    own_timezone,
                );
                self.connection.write().await.push(conn.clone());
                Ok(conn)
            }
            ClientMessagesEncrypted::Error(error) => Err(error.into()),
            x => Err(anyhow!("Unexpected message from server: {x:?}")),
        }
    }

    /// Call a closure for each Conclave connection
    pub async fn map_connections(&self, f: impl FnMut(&ConclaveConnection)) {
        let conns = self.connection.write().await;
        conns.iter().for_each(f);
    }

    /// Disconnects from all servers and remove the server connections from the list.
    pub async fn disconnect_all(&self) {
        let mut conns = self.connection.write().await;
        for conn in conns.drain(..) {
            if let Err(e) = conn.disconnect().await {
                error!("Error disconnecting from {}: {e}", conn.server_info().name);
            }
        }
    }

    /// Drop any connections whose listener has ended (the server closed the
    /// connection or kicked us), releasing their sockets.
    pub async fn prune_disconnected(&self) {
        self.connection
            .write()
            .await
            .retain(|conn| conn.connected_since().is_some());
    }
}

/// Local Conclave servers discovered by Multicast DNS
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoveredServer {
    /// Server name
    pub name: String,

    /// Server's description
    pub description: String,

    /// Server host: domain or IP address
    pub host: String,

    /// Server port
    pub port: u16,

    /// Server's public key
    pub key: VerifyingKey,

    /// Server's Conclave version
    pub version: Version,

    /// Whether anonymous connections are allowed
    pub anonymous_allowed: bool,
}

/// Look up the Conclave SRV record for `domain`, returning the target host (or
/// IP) and port. The query name is [`conclave_common::DNS_SRV_RECORD`] followed
/// by `domain`, resolved using the system's DNS configuration.
///
/// # Errors
///
/// Returns an error if the names are invalid, if there isn't a SRV record, or the DNS query fails.
pub async fn lookup_srv_record(domain: &str) -> Result<(String, u16)> {
    use domain::base::name::{Name, RelativeName};
    use domain::resolv::StubResolver;

    // `lookup_srv` joins the relative service prefix with the domain itself, so
    // pass only the prefix here (the const, minus its trailing root dot) — not
    // the full name, or the domain would be appended twice.
    let service = RelativeName::<Vec<u8>>::from_chars(
        conclave_common::DNS_SRV_RECORD
            .trim_end_matches('.')
            .chars(),
    )
    .map_err(|e| anyhow!("Invalid SRV service label: {e}"))?;
    let name = Name::<Vec<u8>>::from_chars(domain.chars())
        .map_err(|e| anyhow!("Invalid domain {domain}: {e}"))?;

    let resolver = StubResolver::new();
    let found = resolver
        .lookup_srv(service, name, 0)
        .await
        .map_err(|e| anyhow!("SRV lookup for {domain} failed: {e}"))?
        .ok_or_else(|| anyhow!("The Conclave service is unavailable at {domain}"))?;

    let srv = found
        .into_srvs()
        .next()
        .ok_or_else(|| anyhow!("No SRV entries for {domain}"))?;

    // Strip the trailing root dot for a plain, connectable host name.
    let host = srv.target().to_string().trim_end_matches('.').to_string();
    let port = srv.port();
    ensure!(port > 0, "Invalid port {port} for {domain}");
    Ok((host, port))
}

/// Discover local Conclave servers using Multicast DNS
///
/// # Errors
///
/// Returns a networking error
pub fn discover_servers() -> Result<Vec<DiscoveredServer>> {
    use base64::Engine;

    const MAX_ITERS: usize = 5;

    let mdns = ServiceDaemon::new()?;

    // Use a set as we will likely get the same server multiple times
    let mut servers = HashSet::new();
    let receiver = mdns.browse(conclave_common::MDNS_NAME)?;

    let mut counter = 0;
    while let Ok(event) = receiver.recv() {
        if let ServiceEvent::ServiceResolved(resolved) = event {
            let host = resolved.host.replace(".local.", "");
            let key = if let Some(key) = resolved.txt_properties.get(conclave_common::MDNS_KEY) {
                let Ok(key) = base64::engine::general_purpose::STANDARD.decode(key.val_str())
                else {
                    error!("Server key failed base64 decoding");
                    continue;
                };
                if key.len() != 32 {
                    error!("Invalid key length: {}", key.len());
                    continue;
                }
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key);
                let Ok(key) = VerifyingKey::from_bytes(&key_array) else {
                    error!("Server key failed to be parsed");
                    continue;
                };
                key
            } else {
                error!("Server did not provide a key");
                continue;
            };

            let version =
                if let Some(version) = resolved.txt_properties.get(conclave_common::MDNS_VERSION) {
                    let Ok(version) = Version::parse(version.val_str()) else {
                        error!("Server version failed Semver parsing");
                        continue;
                    };
                    version
                } else {
                    error!("Server did not provide a version");
                    continue;
                };

            if version > *VERSION {
                warn!(
                    "Server version {version} is newer than client version {}",
                    *VERSION
                );
            }

            let description = if let Some(description) = resolved
                .txt_properties
                .get(conclave_common::MDNS_DESCRIPTION)
            {
                description.val_str().to_string()
            } else {
                error!("Server did not provide a description");
                continue;
            };

            let anonymous_allowed =
                if let Some(anon) = resolved.txt_properties.get(conclave_common::MDNS_ANONYMOUS) {
                    anon.val_str().eq("true")
                } else {
                    true
                };

            let server = DiscoveredServer {
                host,
                key,
                version,
                description,
                port: resolved.port,
                name: resolved.fullname.replace(conclave_common::MDNS_NAME, ""),
                anonymous_allowed,
            };

            servers.insert(server);
        }
        counter += 1;
        if counter > MAX_ITERS {
            break;
        }
    }

    if mdns.shutdown().is_err() {
        // Pass
    }

    Ok(servers.into_iter().collect())
}

/// Merge every tracker's latest listing into `out`, de-duplicated by server URL
/// and sorted by name.
async fn merge_trackers(
    latest: &RwLock<std::collections::HashMap<String, Vec<Advertise>>>,
    out: &std::sync::RwLock<Vec<Advertise>>,
) {
    let mut by_url: std::collections::HashMap<String, Advertise> = std::collections::HashMap::new();
    for servers in latest.read().await.values() {
        for server in servers {
            by_url.insert(server.url.clone(), server.clone());
        }
    }
    let mut merged: Vec<Advertise> = by_url.into_values().collect();
    merged.sort_by(|a, b| a.name.cmp(&b.name));
    *out.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = merged;
}

/// Wait out the reconnect delay, returning `true` early if the subscription was
/// asked to stop (or its stop handle was dropped).
async fn stop_or_delay(stop: &mut tokio::sync::watch::Receiver<bool>) -> bool {
    /// Delay before reconnecting to a tracker after a failure or disconnect.
    const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

    tokio::select! {
        _ = stop.changed() => true,
        () = tokio::time::sleep(RECONNECT_DELAY) => false,
    }
}

#[tokio::test]
#[ignore = "Don't test in CI"]
async fn test_srv() {
    let response = lookup_srv_record("richardzak.md").await.unwrap();
    println!("Got: {response:?}");
    assert_eq!(response.1, 1122);
    assert_eq!(response.0, "conclave.richardzak.md");
}
