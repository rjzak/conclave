// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_common::tracker::{Advertise, SignedServerList, TrackerProtocol};

use std::fmt::{Debug, Display};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};

use anyhow::{Result, bail};
use dashmap::DashMap;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_mldsa::mldsa87_keypair;
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

/// Conclave version
pub static VERSION: LazyLock<Version> =
    LazyLock::new(|| Version::parse(env!("CONCLAVE_VERSION")).unwrap());

const TRACKER_SERVER_EXPIRATION: u64 = conclave_common::tracker::SERVER_EXPIRATION.as_secs();

/// Tracker keypair
#[derive(Serialize, Deserialize)]
pub struct Keys {
    /// ML-DSA 87 private key
    #[serde(
        serialize_with = "conclave_common::serde::serialize_mldsa_private_key",
        deserialize_with = "conclave_common::serde::deserialize_mldsa_private_key"
    )]
    private_key: mldsa87::SecretKey,

    /// ML-DSA 87 public key
    #[serde(
        serialize_with = "conclave_common::serde::serialize_mldsa_public_key",
        deserialize_with = "conclave_common::serde::deserialize_mldsa_public_key"
    )]
    public_key: mldsa87::PublicKey,
}

impl Default for Keys {
    fn default() -> Self {
        let (public_key, private_key) = mldsa87_keypair();
        Self {
            private_key,
            public_key,
        }
    }
}

impl Keys {
    /// Load keys from a file path, using the file extension to determine the format.
    ///
    /// Supported formats:
    /// - JSON
    /// - TOML
    ///
    /// # Errors
    ///
    /// Returns errors if the file cannot be read, doesn't have an extension, or isn't JSON or TOML.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(&path)?;

        match path.as_ref().extension() {
            Some(ext) if ext == "toml" => Ok(toml::from_str(&contents)?),
            Some(ext) if ext == "json" => Ok(serde_json::from_str(&contents)?),
            Some(ext) => bail!("Unsupported file format {}", ext.display()),
            None => bail!("File {} has no extension", path.as_ref().display()),
        }
    }

    /// Save the keys to a file path, using the file extension to determine the format
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
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Load or save keys. If a file exists, it's loaded. Otherwise keys are generated and saved.
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
            let keys = Keys::default();
            keys.save(path)?;
            Ok(keys)
        }
    }
}

/// Tracker state with server record duration of one minute
pub type DefaultState = State<TRACKER_SERVER_EXPIRATION>;

/// Tracker state
pub struct State<const DURATION_SECONDS: u64> {
    /// List of servers advertised by the tracker
    servers: Arc<DashMap<Advertise, SystemTime>>,

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

impl<const DURATION_SECONDS: u64> Clone for State<DURATION_SECONDS> {
    fn clone(&self) -> Self {
        Self {
            servers: self.servers.clone(),
            ip: self.ip,
            port: self.port,
            queries: self.queries.clone(),
            serving: self.serving.clone(),
            keys: self.keys.clone(),
        }
    }
}

impl<const DURATION_SECONDS: u64> State<DURATION_SECONDS> {
    /// Create a new Tracker object
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(ip: IpAddr, port: u16, keys: Keys) -> Self {
        Self {
            servers: Arc::new(DashMap::new()),
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
            let (mut socket, client) = listener.accept().await.inspect_err(|e| {
                tracing::error!("Error accepting connection: {e}");
                self.serving.store(false, Ordering::Relaxed);
            })?;
            let self_clone = self.clone();

            let message = match TrackerProtocol::receive(&mut socket).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!("Error getting request: {e}");
                    continue;
                }
            };

            match message {
                TrackerProtocol::KeyRequest => {
                    if let Err(e) = TrackerProtocol::TrackerKey(self_clone.keys.public_key)
                        .send(&mut socket)
                        .await
                    {
                        tracing::error!("Error sending public key: {e}");
                    }
                }
                TrackerProtocol::GetServers => {
                    if let Err(e) = TrackerProtocol::ServersList(self_clone.servers())
                        .send(&mut socket)
                        .await
                    {
                        tracing::error!("Error sending signed server list: {e}");
                    } else {
                        self_clone.queries.fetch_add(1, Ordering::Relaxed);
                    }
                }
                TrackerProtocol::AdvertiseServer(server) => {
                    let server = if server.url.contains("0.0.0.0") {
                        let mut fixed = server.clone();
                        fixed.url = fixed
                            .url
                            .replace("0.0.0.0", client.ip().to_string().as_str());
                        fixed
                    } else {
                        server
                    };
                    self_clone.servers.insert(server, SystemTime::now());
                }
                TrackerProtocol::TrackerKey(_) | TrackerProtocol::ServersList(_) => {}
            }
        }

        Ok(())
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

    /// List of servers advertised by the tracker, and expire old ones
    #[must_use]
    #[tracing::instrument]
    pub fn servers(&self) -> SignedServerList {
        let mut to_remove = Vec::new();

        for entry in self.servers.iter() {
            if let Ok(duration) = entry.value().elapsed()
                && duration >= self.duration()
            {
                to_remove.push(entry.key().clone());
            }
        }

        for server in to_remove {
            tracing::info!("Removing expired server: {}", server.name);
            self.servers.remove(&server);
        }

        let servers = self
            .servers
            .iter()
            .map(|e| e.key().clone())
            .collect::<Vec<_>>();

        SignedServerList::new(servers, VERSION.clone(), &self.keys.private_key)
    }

    /// Tracker's expiration duration for server advertisements
    #[inline]
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn duration(&self) -> Duration {
        Duration::from_secs(DURATION_SECONDS)
    }
}

impl<const DURATION_SECONDS: u64> Debug for State<DURATION_SECONDS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tracker:{}", self.servers.len())
    }
}

impl<const DURATION_SECONDS: u64> Display for State<DURATION_SECONDS> {
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
impl<const DURATION_SECONDS: u64> eframe::App for State<DURATION_SECONDS> {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        ui.request_repaint();

        eframe::egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.label(format!("Servers: {}", self.servers.len()));
            ui.label(format!("Queries: {}", self.queries()));
            ui.separator();
            eframe::egui::widgets::global_theme_preference_buttons(ui);
        });
    }
}
