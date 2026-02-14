// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_common::tracker::{Advertise, SERVER_EXPIRATION, TrackerProtocol};

use std::fmt::{Debug, Display};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::SystemTime;

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Tracker state
pub struct State {
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
}

impl Clone for State {
    fn clone(&self) -> Self {
        Self {
            servers: self.servers.clone(),
            ip: self.ip,
            port: self.port,
            queries: self.queries.clone(),
            serving: self.serving.clone(),
        }
    }
}

impl State {
    /// Create a new Tracker object
    #[must_use]
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            servers: Arc::new(DashMap::new()),
            ip,
            port,
            queries: Arc::new(AtomicU32::new(0)),
            serving: Arc::new(AtomicBool::new(false)),
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
                            if let Ok(proto) = postcard::from_bytes(&bytes) {
                                match proto {
                                    TrackerProtocol::GetServers => {
                                        let response =
                                            TrackerProtocol::ServersList(self_clone.servers());
                                        let response = match postcard::to_allocvec(&response) {
                                            Ok(b) => b,
                                            Err(e) => {
                                                tracing::error!("Serialization error: {e}");
                                                continue;
                                            }
                                        };
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
                                    TrackerProtocol::ServersList(_) => {}
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
    #[must_use]
    pub fn queries(&self) -> u32 {
        self.queries.load(Ordering::Relaxed)
    }

    /// Whether the tracker is currently serving requests
    #[must_use]
    pub fn serving(&self) -> bool {
        self.serving.load(Ordering::Relaxed)
    }

    /// List of servers advertised by the tracker, and expire old ones
    #[must_use]
    pub fn servers(&self) -> Vec<Advertise> {
        let mut to_remove = Vec::new();

        for entry in self.servers.iter() {
            if let Ok(duration) = entry.value().elapsed()
                && duration >= SERVER_EXPIRATION
            {
                tracing::info!("Removing expired server: {}", entry.key().name);
                to_remove.push(entry.key().clone());
            }
        }

        for server in to_remove {
            self.servers.remove(&server);
        }

        self.servers
            .iter()
            .map(|e| e.key().clone())
            .collect::<Vec<_>>()
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
