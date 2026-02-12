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
}

impl State {
    /// Create a new Tracker object
    #[must_use]
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            servers: Arc::new(DashMap::new()),
            ip,
            port,
        }
    }

    /// Start the tracker service
    ///
    /// # Errors
    ///
    /// Errors result if there's a network problem
    #[tracing::instrument]
    pub async fn serve(self) -> Result<()> {
        let listener = TcpListener::bind((self.ip, self.port)).await?;
        let servers = self.servers.clone();

        loop {
            let (socket, client) = listener.accept().await?;
            let servers = servers.clone();

            tokio::spawn(async move {
                let mut to_remove = Vec::new();

                for entry in servers.clone().iter() {
                    if let Ok(duration) = entry.value().elapsed()
                        && duration >= SERVER_EXPIRATION
                    {
                        tracing::info!("Removing expired server: {}", entry.key().name);
                        to_remove.push(entry.key().clone());
                    }
                }

                for server in to_remove {
                    servers.remove(&server);
                }

                let mut framed = Framed::new(socket, LengthDelimitedCodec::new());

                while let Some(result) = framed.next().await {
                    match result {
                        Ok(bytes) => {
                            if let Ok(proto) = postcard::from_bytes(&bytes) {
                                match proto {
                                    TrackerProtocol::GetServers => {
                                        let servers = servers
                                            .clone()
                                            .iter()
                                            .map(|e| e.key().clone())
                                            .collect::<Vec<_>>();
                                        let response = TrackerProtocol::ServersList(servers);
                                        let response = match postcard::to_allocvec(&response) {
                                            Ok(b) => b,
                                            Err(e) => {
                                                tracing::error!("Serialization error: {e}");
                                                continue;
                                            }
                                        };
                                        if let Err(e) = framed.send(Bytes::from(response)).await {
                                            tracing::error!("Response error: {e}");
                                        }
                                    }
                                    TrackerProtocol::AdvertiseServer(server) => {
                                        servers.clone().insert(server, SystemTime::now());
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
