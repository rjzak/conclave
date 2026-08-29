// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_common::TRACKER_DEFAULT_PORT;
use conclave_common::pqc::{Generate, Keypair, MlDsaPrivateKey, MlDsaPublicKey};
use conclave_common::tracker::{Advertise, SignedServerList, TrackerProtocol};

use std::fmt::{Debug, Display};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::{Result, bail};
use dashmap::DashMap;
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Conclave version
pub static VERSION: LazyLock<Version> =
    LazyLock::new(|| Version::parse(env!("CONCLAVE_VERSION")).unwrap());

const DEFAULT_TRACKER_FILE: &str = "conclave-tracker.toml";

/// Find a conf file from the common Conclave config directory
///
/// # Panics
///
/// Panics if the home directory can't be found or if the config directory can't be found/created.
#[must_use]
pub fn default_config_path() -> PathBuf {
    let mut config_file = conclave_common::default_config_directory()
        .expect("Unable to determine default config directory");
    config_file.push(DEFAULT_TRACKER_FILE);
    config_file
}

/// Config file
#[derive(Serialize, Deserialize)]
pub struct TrackerConfig {
    /// Listening IP address
    #[serde(default = "default_ip")]
    pub ip: IpAddr,

    /// Listening port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Path to signing keys
    /// Keys will be generated if missing.
    #[serde(default)]
    pub keys: Keys,
}

#[inline]
const fn default_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[inline]
const fn default_port() -> u16 {
    TRACKER_DEFAULT_PORT
}

impl TrackerConfig {
    /// Load config keys from a file path, using the file extension to determine the format.
    ///
    /// Supported formats:
    /// - JSON
    /// - TOML
    ///
    /// # Errors
    ///
    /// Returns errors if the file cannot be read, doesn't have an extension, isn't JSON or TOML,
    /// or holds a public key that doesn't belong to the private key beside it.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(&path)?;

        let config: Self = match path.as_ref().extension() {
            Some(ext) if ext == "toml" => toml::from_str(&contents)?,
            Some(ext) if ext == "json" => serde_json::from_str(&contents)?,
            Some(ext) => bail!("Unsupported file format {}", ext.display()),
            None => bail!("File {} has no extension", path.as_ref().display()),
        };

        // The public key is derivable from the private key, so a mismatch means the file was
        // edited or merged by hand and the tracker would sign with a key nobody expects.
        if config.keys.private_key.verifying_key() != config.keys.public_key {
            bail!(
                "Public key in {} does not belong to the private key beside it",
                path.as_ref().display()
            );
        }

        Ok(config)
    }

    /// Save the config and keys to a file path, using the file extension to determine the format
    ///
    /// Supported formats:
    /// - JSON
    /// - TOML
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or if the extension doesn't indicate a JSON or TOML format.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = match path.as_ref().extension() {
            Some(ext) if ext == "toml" => toml::to_string(&self)?,
            Some(ext) if ext == "json" => serde_json::to_string(&self)?,
            Some(ext) => bail!("Unsupported file format {}", ext.display()),
            None => bail!("File {} has no extension", path.as_ref().display()),
        };

        let mut options = OpenOptions::new();
        options
            .write(true)
            .create(true)
            .append(false)
            .truncate(true);

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }

        let mut file = options.open(&path)?;
        write!(file, "{contents}")?;
        Ok(())
    }

    /// Load or save config. If a file exists, it's loaded. Otherwise config & keys are generated and saved.
    ///
    /// Supported formats:
    /// - JSON
    /// - TOML
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or if the extension doesn't indicate a JSON or TOML format.
    pub fn load_or_save<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            Self::load(path)
        } else {
            let config = Self::default();
            config.save(path)?;
            Ok(config)
        }
    }
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            ip: default_ip(),
            port: default_port(),
            keys: Keys::default(),
        }
    }
}

/// Tracker keypair
#[derive(Serialize, Deserialize)]
pub struct Keys {
    /// ML-DSA 87 private key, stored as the 32-byte seed it is derived from
    #[serde(
        serialize_with = "conclave_common::serde::serialize_mldsa_private_key",
        deserialize_with = "conclave_common::serde::deserialize_mldsa_private_key"
    )]
    private_key: MlDsaPrivateKey,

    /// ML-DSA 87 public key
    #[serde(
        serialize_with = "conclave_common::serde::serialize_mldsa_public_key",
        deserialize_with = "conclave_common::serde::deserialize_mldsa_public_key"
    )]
    public_key: MlDsaPublicKey,
}

impl Default for Keys {
    fn default() -> Self {
        let private_key = MlDsaPrivateKey::generate();
        let public_key = private_key.verifying_key();
        Self {
            private_key,
            public_key,
        }
    }
}

impl Keys {
    /// The public key clients use to verify this tracker's server listings
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }
}

/// Tracker state
pub struct State {
    /// Servers currently advertised, keyed by the id of the advertiser
    /// connection. An entry lives exactly as long as that connection: the server
    /// is added when it connects and removed the moment the connection closes.
    servers: Arc<DashMap<u64, Advertise>>,

    /// Source of unique ids for advertiser connections.
    next_id: Arc<AtomicU64>,

    /// Bumped whenever the set of advertised servers changes so that subscribers
    /// can be pushed an updated listing.
    changes: Arc<watch::Sender<u64>>,

    /// IP Address and port to listen on
    ip: IpAddr,

    /// Port to listen on
    port: u16,

    /// Number of times the tracker has been asked for a server listing
    queries: Arc<AtomicU32>,

    /// Whether the tracker is currently serving requests
    serving: Arc<AtomicBool>,

    /// ML-DSA 87 keypair
    keys: Arc<Keys>,
}

impl Clone for State {
    fn clone(&self) -> Self {
        Self {
            servers: self.servers.clone(),
            next_id: self.next_id.clone(),
            changes: self.changes.clone(),
            ip: self.ip,
            port: self.port,
            queries: self.queries.clone(),
            serving: self.serving.clone(),
            keys: self.keys.clone(),
        }
    }
}

impl From<TrackerConfig> for State {
    fn from(config: TrackerConfig) -> Self {
        Self::new(config.ip, config.port, config.keys)
    }
}

impl State {
    /// Create a new Tracker object
    #[must_use]
    pub fn new(ip: IpAddr, port: u16, keys: Keys) -> Self {
        let (changes, _) = watch::channel(0u64);
        Self {
            servers: Arc::new(DashMap::new()),
            next_id: Arc::new(AtomicU64::new(0)),
            changes: Arc::new(changes),
            ip,
            port,
            queries: Arc::new(AtomicU32::new(0)),
            serving: Arc::new(AtomicBool::new(false)),
            keys: Arc::new(keys),
        }
    }

    /// Start the tracker service
    ///
    /// # Errors
    ///
    /// Errors result if there's a network problem
    #[tracing::instrument]
    pub async fn serve(&self) -> Result<()> {
        let listener = TcpListener::bind((self.ip, self.port)).await?;
        self.serving.store(true, Ordering::Relaxed);

        while self.serving() {
            let (socket, client) = listener.accept().await.inspect_err(|e| {
                tracing::error!("Error accepting connection: {e}");
                self.serving.store(false, Ordering::Relaxed);
            })?;

            // Every connection is persistent and handled on its own task so that
            // subscribers can be pushed updates and advertisers can be dropped
            // the instant they disconnect.
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone.handle_connection(socket, client).await;
            });
        }

        Ok(())
    }

    /// Handle a single persistent connection until it closes.
    async fn handle_connection(&self, mut socket: TcpStream, client: SocketAddr) {
        loop {
            // EOF or a broken socket means the peer is gone.
            let Ok(message) = TrackerProtocol::receive(&mut socket).await else {
                break;
            };

            match message {
                TrackerProtocol::KeyRequest => {
                    if let Err(e) = TrackerProtocol::TrackerKey(self.keys.public_key.clone())
                        .send(&mut socket)
                        .await
                    {
                        tracing::error!("Error sending public key: {e}");
                        break;
                    }
                }
                TrackerProtocol::GetServers => {
                    if let Err(e) = TrackerProtocol::ServersList(self.servers())
                        .send(&mut socket)
                        .await
                    {
                        tracing::error!("Error sending signed server list: {e}");
                        break;
                    }
                    self.queries.fetch_add(1, Ordering::Relaxed);
                }
                // These take over the connection for its remaining lifetime.
                TrackerProtocol::Subscribe => {
                    self.run_subscriber(&mut socket).await;
                    break;
                }
                TrackerProtocol::AdvertiseServer(advertise) => {
                    self.run_advertiser(&mut socket, advertise, client).await;
                    break;
                }
                TrackerProtocol::TrackerKey(_) | TrackerProtocol::ServersList(_) => {}
            }
        }
    }

    /// Serve a subscriber: send the current listing immediately, then push a new
    /// one every time the set of advertised servers changes, until the client
    /// disconnects.
    async fn run_subscriber(&self, socket: &mut TcpStream) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        let mut updates = self.changes.subscribe();
        let (mut read, mut write) = socket.split();

        if TrackerProtocol::ServersList(self.servers())
            .send(&mut write)
            .await
            .is_err()
        {
            return;
        }

        loop {
            tokio::select! {
                changed = updates.changed() => {
                    if changed.is_err() {
                        break; // tracker shutting down
                    }
                    if TrackerProtocol::ServersList(self.servers())
                        .send(&mut write)
                        .await
                        .is_err()
                    {
                        break; // subscriber went away mid-send
                    }
                }
                // Reading serves only to notice the client disconnecting; any
                // message it sends is ignored.
                incoming = TrackerProtocol::receive(&mut read) => {
                    if incoming.is_err() {
                        break;
                    }
                }
            }
        }
    }

    /// Serve an advertiser: register the server for the lifetime of the
    /// connection, applying any updated advertisements in place, and remove it
    /// the moment the connection closes.
    async fn run_advertiser(&self, socket: &mut TcpStream, first: Advertise, client: SocketAddr) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.servers.insert(id, Self::fixup_url(first, client));
        self.bump();

        loop {
            match TrackerProtocol::receive(socket).await {
                Ok(TrackerProtocol::AdvertiseServer(update)) => {
                    self.servers.insert(id, Self::fixup_url(update, client));
                    self.bump();
                }
                // Ignore anything else the advertiser might send.
                Ok(_) => {}
                // Disconnected: drop the server from the listing immediately.
                Err(_) => break,
            }
        }

        self.servers.remove(&id);
        self.bump();
        tracing::info!("Advertiser {client} disconnected; server removed from tracker");
    }

    /// Replace an unspecified advertised address with the peer's actual address.
    fn fixup_url(mut advertise: Advertise, client: SocketAddr) -> Advertise {
        if advertise.url.contains("0.0.0.0") {
            advertise.url = advertise.url.replace("0.0.0.0", &client.ip().to_string());
        }
        advertise
    }

    /// Signal every subscriber that the server listing changed.
    fn bump(&self) {
        self.changes.send_modify(|version| {
            *version = version.wrapping_add(1);
        });
    }

    /// Number of queries received by the tracker
    #[inline]
    #[must_use]
    pub fn queries(&self) -> u32 {
        self.queries.load(Ordering::Relaxed)
    }

    /// Whether the tracker is currently serving requests
    #[inline]
    #[must_use]
    pub fn serving(&self) -> bool {
        self.serving.load(Ordering::Relaxed)
    }

    /// The current signed list of advertised servers. Presence is tied to each
    /// advertiser's connection, so no expiration sweep is needed here.
    #[must_use]
    #[tracing::instrument]
    pub fn servers(&self) -> SignedServerList {
        let servers = self
            .servers
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();

        SignedServerList::new(servers, VERSION.clone(), &self.keys.private_key)
    }
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tracker:{}", self.servers.len())
    }
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Conclave Tracker advertising {} servers on {}:{}",
            self.servers.len(),
            self.ip,
            self.port
        )
    }
}

#[cfg(feature = "gui")]
impl eframe::App for State {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        ui.request_repaint();

        eframe::egui::CentralPanel::default().show(ui, |ui| {
            ui.label(format!("Servers: {}", self.servers.len()));
            ui.label(format!("Queries: {}", self.queries()));
            ui.separator();
            eframe::egui::widgets::global_theme_preference_buttons(ui);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys survive a save/load cycle in both supported formats, and `load_or_save` reuses an
    /// existing file rather than replacing the tracker's identity.
    #[test]
    fn keys_round_trip() {
        let dir = tempdir::TempDir::new("conclave_tracker_keys").unwrap();

        for name in ["config.toml", "config.json"] {
            let path = dir.path().join(name);

            let config = TrackerConfig::default();
            config.save(&path).unwrap();

            let loaded = TrackerConfig::load(&path).unwrap();
            assert_eq!(loaded.keys.public_key(), config.keys.public_key());
            assert_eq!(
                loaded.keys.private_key.to_seed(),
                config.keys.private_key.to_seed()
            );

            assert_eq!(
                TrackerConfig::load_or_save(&path)
                    .unwrap()
                    .keys
                    .public_key(),
                config.keys.public_key()
            );
        }
    }

    /// A key file whose public key belongs to some other private key is rejected rather than
    /// silently signing with a key nobody has pinned.
    #[test]
    fn mismatched_keys_are_rejected() {
        let dir = tempdir::TempDir::new("conclave_tracker_mismatch").unwrap();
        let path = dir.path().join("config.toml");

        let config = TrackerConfig {
            ip: default_ip(),
            port: 1234,
            keys: Keys {
                private_key: Keys::default().private_key,
                public_key: Keys::default().public_key,
            },
        };
        config.save(&path).unwrap();

        assert!(TrackerConfig::load(&path).is_err());
    }
}
