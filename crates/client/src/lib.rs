// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

/// Client configuration file data structures and I/O functions.
pub mod config;

/// Server connection management and protocol handling.
pub mod conn;

use crate::config::{BookmarkEntry, ClientConfig, Tracker};
use crate::conn::ConclaveConnection;
use conclave_common::net::EncryptedStream;
use conclave_common::server::{
    ClientMessagesEncrypted, ServerMessagesEncrypted, UserAuthentication, VerifyingKey, unencrypted,
};
use conclave_common::tracker::{Advertise, TrackerProtocol};

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow, bail, ensure};
use dashmap::DashSet;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use semver::Version;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, trace, warn};

/// Conclave version
pub static VERSION: LazyLock<Version> =
    LazyLock::new(|| Version::parse(env!("CONCLAVE_VERSION")).unwrap());

/// Default config file name.
pub const DEFAULT_FILE: &str = "client.toml";

/// Conclave client
pub struct Client {
    /// Active connections to various services
    connection: Arc<RwLock<Vec<ConclaveConnection>>>,

    /// Trackers, domain or IP and port
    trackers: Arc<DashSet<Tracker>>,

    /// Config file path
    config_file: Mutex<PathBuf>,

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

impl Default for Client {
    fn default() -> Self {
        Self::new(DEFAULT_FILE).unwrap()
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
            config_file: Mutex::new(path),
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
        let config_file = self.config_file.lock().await;
        self.config.read().await.save(&*config_file)
    }

    /// Add a tracker to the list of known trackers and update the database
    ///
    /// # Errors
    ///
    /// Returns errors if there is a database error
    pub async fn add_tracker(&self, tracker_name: &str, tracker_port: u16) -> Result<()> {
        let mut stream = TcpStream::connect(format!("{tracker_name}:{tracker_port}")).await?;

        TrackerProtocol::KeyRequest.send(&mut stream).await?;

        let TrackerProtocol::TrackerKey(tracker_key) =
            TrackerProtocol::receive(&mut stream).await?
        else {
            bail!("Unexpected");
        };

        let tracker_entry = Tracker {
            name: tracker_name.to_string(),
            port: tracker_port,
            key: tracker_key,
        };

        if let Some(existing_entry) = self.trackers.get(&tracker_entry) {
            trace!("Tracker {tracker_name}:{tracker_port} already known");
            ensure!(existing_entry.key == tracker_key, "Tracker key mismatch!");
        } else {
            trace!(
                "Adding tracker {}:{} to database",
                tracker_name, tracker_port
            );
            self.trackers.insert(tracker_entry.clone());
            self.config.write().await.trackers.push(tracker_entry);
            let config_file = self.config_file.lock().await;
            self.config.read().await.save(&*config_file)?;
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
            if tracker.name == tracker_name && tracker.port == tracker_port {
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
            .retain(|t| t.name != tracker_name || t.port != tracker_port);
        let config_file = self.config_file.lock().await;
        self.config.read().await.save(&*config_file)?;

        Ok(())
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
            info!("Connecting to tracker {}:{}", tracker.name, tracker.port);
            let mut stream =
                TcpStream::connect(format!("{}:{}", tracker.name, tracker.port)).await?;

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
                tracker.name,
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

    /// Add a server bookmark to the config file
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn add_bookmark(&self, bookmark: &BookmarkEntry) -> Result<()> {
        self.config.write().await.bookmarks.push(bookmark.clone());
        let config_file = self.config_file.lock().await;
        self.config.read().await.save(&*config_file)
    }

    /// Remove a server bookmark by server's index in the list
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn remove_bookmark_by_index(&self, index: usize) -> Result<()> {
        self.config.write().await.bookmarks.remove(index);
        let config_file = self.config_file.lock().await;
        self.config.read().await.save(&*config_file)
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
            .retain(|b| b.server != server);
        let config_file = self.config_file.lock().await;
        self.config.read().await.save(&*config_file)
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
        let config_file = self.config_file.lock().await;
        self.config.read().await.save(&*config_file)
    }

    /// Remove a server bookmark by server's key
    ///
    /// # Errors
    ///
    /// I/O errors may occur when writing to the config file.
    pub async fn remove_bookmark_by_key(&self, key: VerifyingKey) -> Result<()> {
        self.config.write().await.bookmarks.retain(|b| b.key != key);
        let config_file = self.config_file.lock().await;
        self.config.read().await.save(&*config_file)
    }

    /// Connect to a server
    ///
    /// # Errors
    ///
    /// Networking errors may result
    pub async fn connect(
        &self,
        server: &str,
        port: u16,
        share_time: bool,
        display_name: String,
        auth: Option<UserAuthentication>,
        key: Option<VerifyingKey>,
    ) -> Result<usize> {
        let key = if let Some(key) = key {
            key
        } else {
            let mut stream = TcpStream::connect(format!("{server}:{port}")).await?;

            info!("Requesting key from server");
            unencrypted::ClientToServer::KeyRequest
                .send(&mut stream)
                .await?;

            let key_response = unencrypted::ServerToClient::receive(&mut stream).await?;
            let unencrypted::ServerToClient::PublicKey(key) = key_response else {
                bail!("Server did not provide a public key")
            };

            info!("Received key from server");
            key
        };

        let mut stream = TcpStream::connect(format!("{server}:{port}")).await?;

        info!(
            "Connecting to the server on port {port} with key {:?}",
            key.as_bytes()
        );
        unencrypted::ClientToServer::GoCrypto
            .send(&mut stream)
            .await?;

        info!("Creating encrypted stream to server");
        let mut encrypted_stream = EncryptedStream::connect(stream, &key, None).await?;
        info!("Client: EncryptedStream created");

        let login = ServerMessagesEncrypted::ServerAuthenticationRequest((
            display_name.clone(),
            share_time.then(chrono::Local::now),
            auth,
        ))
        .to_vec();
        encrypted_stream.send(&login).await?;

        info!("Expecting information request");
        let server_info = encrypted_stream.recv().await?;
        let server_info = ClientMessagesEncrypted::from_bytes(&server_info)?;

        match server_info {
            ClientMessagesEncrypted::ServerInformationResponse(server_info) => {
                eprintln!("Received server information");
                if server_info.version > *VERSION {
                    warn!(
                        "Server version {} is newer than client version {}",
                        server_info.version, *VERSION
                    );
                }
                let conn = ConclaveConnection::new(encrypted_stream, server_info, &display_name);
                let mut conns = self.connection.write().await;
                conns.push(conn);
                Ok(conns.len())
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
                error!(
                    "Error disconnecting from {}: {e}",
                    conn.server_info.read().await.name
                );
            }
        }
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

            let server = DiscoveredServer {
                host,
                key,
                version,
                description,
                port: resolved.port,
                name: resolved.fullname.replace(conclave_common::MDNS_NAME, ""),
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
