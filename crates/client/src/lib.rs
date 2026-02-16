// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_common::net::EncryptedStream;
use conclave_common::server::{
    ClientMessagesUnencrypted, ServerInformation, ServerMessagesEncrypted,
    ServerMessagesUnencrypted, UserAuthentication, VerifyingKey,
};
use conclave_common::tracker::{Advertise, TrackerProtocol};

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_sqlite::rusqlite::fallible_iterator::FallibleIterator;
use async_sqlite::rusqlite::{Batch, Connection, params};
use async_sqlite::{ClientBuilder, JournalMode};
use bytes::Bytes;
use dashmap::DashSet;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, trace};

const SCHEMA: &str = include_str!("schema.sql");

/// Conclave client
pub struct Client {
    /// Active connections to various services
    connection: Arc<RwLock<Vec<ConclaveConnection>>>,

    /// Trackers, domain or IP and port
    trackers: Arc<DashSet<(String, u16)>>,

    /// SQL Lite client
    sqlite: async_sqlite::Client,
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
    /// Create a client
    ///
    /// # Errors
    ///
    /// An error may result if a config file can't be created.
    pub fn new<P: AsRef<Path>>(sqlite_path: P) -> Result<Self> {
        let trackers = if sqlite_path.as_ref().exists() {
            let conn = Connection::open(&sqlite_path)?;
            let mut stmt = conn.prepare("SELECT server, port FROM trackers")?;

            let rows = stmt.query_map([], |row| {
                let server: String = row.get(0)?;
                let port: u16 = row.get(1)?;
                Ok((server, port))
            })?;

            let trackers = rows.flatten().collect::<Vec<_>>();
            DashSet::from_iter(trackers)
        } else {
            let conn = Connection::open(&sqlite_path)?;
            let mut batch = Batch::new(&conn, SCHEMA);
            while let Some(mut stmt) = batch.next()? {
                stmt.execute([])?;
            }

            conn.execute(
                "INSERT INTO CLIENT_CONFIG(version) VALUES(?1)",
                [env!("CARGO_PKG_VERSION")],
            )?;

            DashSet::new()
        };

        let sqlite = ClientBuilder::new()
            .journal_mode(JournalMode::Wal)
            .path(sqlite_path)
            .open_blocking()?;

        Ok(Self {
            connection: Arc::new(RwLock::new(Vec::new())),
            sqlite,
            trackers: Arc::new(trackers),
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
            let tracker_name = String::from(tracker_name);
            self.sqlite
                .conn(move |conn| {
                    conn.execute(
                        "insert into trackers(server, port) values(?1, ?2)",
                        params![tracker_name, tracker_port],
                    )
                })
                .await?;
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
        self.sqlite
            .conn(move |conn| {
                conn.execute(
                    "delete from trackers where server = ?1 and port = ?2",
                    params![tracker_name, tracker_port],
                )
            })
            .await?;

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
        let conn = ConclaveConnection {
            connection: encrypted_stream,
            display_name: display_name.to_string(),
            server_name: server_info.name,
        };

        self.connection.write().await.push(conn);
        Ok(())
    }
}

/// Connection information
#[allow(dead_code)]
struct ConclaveConnection {
    /// Encrypted connection to a server
    connection: EncryptedStream,

    /// Display name shown for the user on this server
    display_name: String,

    /// Name of the server
    server_name: String,
}

impl std::fmt::Display for ConclaveConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} on {}", self.display_name, self.server_name)
    }
}
