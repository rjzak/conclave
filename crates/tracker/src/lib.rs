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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_mldsa::mldsa87_keypair;
use semver::Version;
use tokio::net::TcpListener;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Conclave version
pub static VERSION: LazyLock<Version> =
    LazyLock::new(|| Version::parse(env!("CONCLAVE_VERSION")).unwrap());

const TRACKER_SERVER_EXPIRATION: u64 = conclave_common::tracker::SERVER_EXPIRATION.as_secs();

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

    /// ML-DSA 87 private key
    private_key: mldsa87::SecretKey,

    /// ML-DSA 87 public key
    public_key: mldsa87::PublicKey,
}

impl<const DURATION_SECONDS: u64> Clone for State<DURATION_SECONDS> {
    fn clone(&self) -> Self {
        Self {
            servers: self.servers.clone(),
            ip: self.ip,
            port: self.port,
            queries: self.queries.clone(),
            serving: self.serving.clone(),
            private_key: self.private_key,
            public_key: self.public_key,
        }
    }
}

// TODO: Serialize, Deserialize tracker config to save the key

impl<const DURATION_SECONDS: u64> State<DURATION_SECONDS> {
    /// Create a new Tracker object
    #[must_use]
    pub fn new(ip: IpAddr, port: u16) -> Self {
        let (public_key, private_key) = mldsa87_keypair();

        Self {
            servers: Arc::new(DashMap::new()),
            ip,
            port,
            queries: Arc::new(AtomicU32::new(0)),
            serving: Arc::new(AtomicBool::new(false)),
            public_key,
            private_key,
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

        loop {
            let (socket, client) = listener.accept().await.inspect_err(|e| {
                tracing::error!("Error accepting connection: {e}");
                self.serving.store(false, Ordering::Relaxed);
            })?;
            let self_clone = self.clone();

            tokio::spawn(async move {
                let mut framed = Framed::new(socket, LengthDelimitedCodec::new());

                while let Some(result) = framed.next().await {
                    match result {
                        Ok(bytes) => {
                            if let Ok(proto) = TrackerProtocol::from_bytes(&bytes) {
                                match proto {
                                    TrackerProtocol::KeyRequest => {
                                        let response =
                                            TrackerProtocol::TrackerKey(self_clone.public_key)
                                                .to_vec();
                                        if let Err(e) = framed.send(Bytes::from(response)).await {
                                            tracing::error!("Response error: {e}");
                                        }
                                    }
                                    TrackerProtocol::GetServers => {
                                        let servers = self_clone.servers();
                                        let signature = mldsa87::sign(
                                            &Advertise::servers_to_vec(&servers),
                                            &self_clone.private_key,
                                        );
                                        let response =
                                            TrackerProtocol::ServersList(SignedServerList {
                                                servers,
                                                version: VERSION.clone(),
                                                signature,
                                            })
                                            .to_vec();
                                        if let Err(e) = framed.send(Bytes::from(response)).await {
                                            tracing::error!("Response error: {e}");
                                        } else {
                                            self_clone.queries.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    TrackerProtocol::AdvertiseServer(server) => {
                                        let server = if server.url.contains("0.0.0.0") {
                                            let mut fixed = server.clone();
                                            fixed.url = fixed.url.replace(
                                                "0.0.0.0",
                                                client.ip().to_string().as_str(),
                                            );
                                            fixed
                                        } else {
                                            server
                                        };
                                        self_clone.servers.insert(server, SystemTime::now());
                                    }
                                    TrackerProtocol::TrackerKey(_)
                                    | TrackerProtocol::ServersList(_) => {}
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error decoding message from {client}: {e}");
                        }
                    }
                }
            });
        }
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
    pub fn servers(&self) -> Vec<Advertise> {
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

        self.servers
            .iter()
            .map(|e| e.key().clone())
            .collect::<Vec<_>>()
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
