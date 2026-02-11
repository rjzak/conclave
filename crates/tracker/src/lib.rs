// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_common::tracker::{Advertise, TrackerProtocol};

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Tracker state
pub struct State {
    /// List of servers advertised by the tracker
    pub servers: Arc<RwLock<HashSet<Advertise>>>,

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
            servers: Arc::new(RwLock::new(HashSet::new())),
            ip,
            port,
        }
    }

    /// Start the tracker service
    ///
    /// # Errors
    ///
    /// Errors result if there's a network problem
    pub async fn serve(self) -> Result<()> {
        let listener = TcpListener::bind((self.ip, self.port)).await?;
        let servers = self.servers;

        loop {
            let (socket, client) = listener.accept().await?;

            let servers_clone = servers.clone();
            tokio::spawn(async move {
                let mut framed = Framed::new(socket, LengthDelimitedCodec::new());

                while let Some(result) = framed.next().await {
                    match result {
                        Ok(bytes) => {
                            if let Ok(proto) = postcard::from_bytes(&bytes) {
                                match proto {
                                    TrackerProtocol::GetServers => {
                                        let servers = servers_clone.read().await;
                                        let servers = servers.iter().cloned().collect();
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
                                        let mut servers = servers_clone.write().await;
                                        servers.insert(server);
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
