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

use crate::config::{ClientConfig, Tracker};
use crate::conn::ConclaveConnection;
use conclave_common::net::EncryptedStream;
use conclave_common::server::{
    ClientMessagesUnencrypted, ServerInformation, ServerMessagesEncrypted,
    ServerMessagesUnencrypted, UserAuthentication, VerifyingKey,
};
use conclave_common::tracker::{Advertise, TrackerProtocol};

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use dashmap::DashSet;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, trace};

/// Conclave client
pub struct Client {
    /// Active connections to various services
    connection: Arc<RwLock<Vec<ConclaveConnection>>>,

    /// Trackers, domain or IP and port
    trackers: Arc<DashSet<(String, u16)>>,

    /// SQL Lite client
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

impl Default for Client {
    fn default() -> Self {
        Self::new("conclave_client.db").unwrap()
    }
}

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
            trackers: Arc::new(
                config
                    .trackers
                    .iter()
                    .map(|t| (t.server.clone(), t.port))
                    .collect(),
            ),
            config_file: path,
            config: Arc::new(RwLock::new(config)),
        })
    }

    /// Add a tracker to the list of known trackers and update the database
    ///
    /// # Errors
    ///
    /// Returns errors if there is a database error
    pub async fn add_tracker(&self, tracker_name: &str, tracker_port: u16) -> Result<()> {
        if self
            .trackers
            .insert((String::from(tracker_name), tracker_port))
        {
            trace!(
                "Adding tracker {}:{} to database",
                tracker_name, tracker_port
            );
            self.config.write().await.trackers.push(Tracker {
                server: tracker_name.to_string(),
                port: tracker_port,
            });
            self.config.read().await.save(&self.config_file)?;
        } else {
            trace!("Tracker {}:{} already known", tracker_name, tracker_port);
        }

        Ok(())
    }

    /// Remove a tracker from the list of known trackers and from the database
    ///
    /// # Errors
    ///
    /// Returns errors if there is a database error
    pub async fn remove_tracker(&self, tracker_name: &str, tracker_port: u16) -> Result<()> {
        self.trackers
            .remove(&(String::from(tracker_name), tracker_port));

        let tracker_name = String::from(tracker_name);
        trace!(
            "Removing tracker {}:{} from database",
            tracker_name, tracker_port
        );
        self.config
            .write()
            .await
            .trackers
            .retain(|t| t.server != tracker_name || t.port != tracker_port);
        self.config.read().await.save(&self.config_file)?;

        Ok(())
    }

    /// Get a list of unique servers from all the known trackers.
    ///
    /// # Errors
    ///
    /// Errors may arise from network problems.
    pub async fn list_servers(&self) -> Result<Vec<Advertise>> {
        let mut servers_set = HashSet::new();
        let get_servers_bytes = postcard::to_stdvec(&TrackerProtocol::GetServers)?;

        info!(
            "Requesting servers list from {} trackers",
            self.trackers.len()
        );
        for tracker in self.trackers.iter() {
            info!("Connecting to tracker {}:{}", tracker.0, tracker.1);
            let stream = TcpStream::connect(format!("{}:{}", tracker.0, tracker.1)).await?;
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            framed.send(Bytes::from(get_servers_bytes.clone())).await?;
            if let Some(res_result) = framed.next().await {
                let bytes = res_result?;
                let resp: TrackerProtocol = postcard::from_bytes(&bytes)?;
                if let TrackerProtocol::ServersList(servers) = resp {
                    info!(
                        "Received {} servers list from tracker {}:{}: {:?}",
                        servers.len(),
                        tracker.0,
                        tracker.1,
                        servers
                    );
                    servers_set.extend(servers.into_iter());
                }
            }
        }

        Ok(servers_set.into_iter().collect())
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
        display_name: &str,
        auth: Option<UserAuthentication>,
        key: Option<VerifyingKey>,
    ) -> Result<()> {
        let (port, key) = if let Some(key) = key {
            (port, key)
        } else {
            let stream = TcpStream::connect(format!("{server}:{port}")).await?;
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            // Request key from the server
            eprintln!("Requesting key from server");
            let key_request = ServerMessagesUnencrypted::KeyRequest;
            let key_request = postcard::to_stdvec(&key_request)?;
            framed.send(Bytes::from(key_request)).await?;

            let (port, key) = if let Some(result) = framed.next().await {
                eprintln!("Received key bytes from server");
                let result = result?;
                match postcard::from_bytes::<ClientMessagesUnencrypted>(&result) {
                    Ok(ClientMessagesUnencrypted::KeyResponse(key)) => key,
                    Ok(x) => return Err(anyhow!("Unexpected message from server: {x:?}")),
                    Err(e) => return Err(e.into()),
                }
            } else {
                return Err(anyhow!("Server did not respond with key"));
            };

            info!("Received key from server: {key:?}");
            (port, key)
        };

        eprintln!("Re-connecting to the server on port {port}");
        let stream = TcpStream::connect(format!("{server}:{port}")).await?;
        eprintln!("Creating encrypted stream to server");
        let mut encrypted_stream = EncryptedStream::connect(stream, &key).await?;
        eprintln!("Client: EncryptedStream created");

        let login =
            postcard::to_stdvec(&ServerMessagesEncrypted::ServerAuthenticationRequest(auth))?;
        encrypted_stream.send(&login).await?;

        eprintln!("Expecting information request");
        let server_info = encrypted_stream.recv().await?;
        let server_info = postcard::from_bytes::<ServerInformation>(&server_info)?;

        eprintln!("Received server information");
        let conn = ConclaveConnection::new(encrypted_stream, server_info, display_name);
        self.connection.write().await.push(conn);
        Ok(())
    }
}
