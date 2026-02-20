// SPDX-License-Identifier: Apache-2.0

use conclave_common::net::{DefaultEncryptedStream, EncryptedWrite};
use conclave_common::server::{
    ClientMessagesEncrypted, ServerInformation, ServerMessagesEncrypted,
};

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Connection information
#[allow(dead_code)]
pub struct ConclaveConnection {
    /// Encrypted connection to a server
    pub(crate) connection: Arc<RwLock<EncryptedWrite<1000>>>,

    /// Server information
    pub(crate) server_info: Arc<RwLock<ServerInformation>>,

    /// Display name shown for the user on this server
    pub(crate) display_name: Arc<RwLock<String>>,

    /// Join handle for the task which listens for messages from the server
    pub(crate) listen_handle: JoinHandle<()>,
}

impl ConclaveConnection {
    /// Create a connection object
    pub fn new(conn: DefaultEncryptedStream, info: ServerInformation, display_name: &str) -> Self {
        let (mut read, write) = conn.into_split();
        let server_info = Arc::new(RwLock::new(info));

        // TODO: This will need to be a function so the task may access the whole struct
        let server_info_clone = server_info.clone();
        let reader = tokio::spawn(async move {
            loop {
                let data = match read.recv().await {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("Error reading from encrypted stream: {e:?}");
                        continue;
                    }
                };

                let protocol: ClientMessagesEncrypted = match postcard::from_bytes(&data) {
                    Ok(protocol) => protocol,
                    Err(e) => {
                        tracing::error!("Error decoding encrypted message: {e:?}");
                        continue;
                    }
                };
                tracing::trace!("Received encrypted message: {:?}", protocol);

                match protocol {
                    ClientMessagesEncrypted::KeepAlive => (),
                    ClientMessagesEncrypted::Disconnect => break,
                    ClientMessagesEncrypted::ServerInformationResponse(info) => {
                        server_info_clone.write().await.clone_from(&info);
                    }
                    _ => tracing::warn!("Received unexpected encrypted message: {:?}", protocol),
                }
            }
        });

        ConclaveConnection {
            connection: Arc::new(RwLock::new(write)),
            server_info,
            display_name: Arc::new(RwLock::new(display_name.to_string())),
            listen_handle: reader,
        }
    }

    /// Update server information locally and return the data
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn server_info(&self) -> Result<()> {
        let request = postcard::to_stdvec(&ServerMessagesEncrypted::ServerInformationRequest)?;
        self.connection.write().await.send(&request).await?;
        Ok(())
    }

    /// Get users connected to the server
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn connected_users(&self) -> Result<()> {
        let request = postcard::to_stdvec(&ServerMessagesEncrypted::ListConnectedUsersRequest)?;
        self.connection.write().await.send(&request).await?;
        Ok(())
    }

    /// Send a keep-alive message to the server
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn keep_alive(&self) -> Result<()> {
        let request = postcard::to_stdvec(&ServerMessagesEncrypted::KeepAlive)?;
        self.connection.write().await.send(&request).await?;
        Ok(())
    }

    /// Send a disconnect message to the server and close the connection.
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn disconnect(&self) -> Result<()> {
        let request = postcard::to_stdvec(&ServerMessagesEncrypted::Disconnect)?;
        self.connection.write().await.send(&request).await?;
        self.listen_handle.abort();
        Ok(())
    }
}

impl std::fmt::Debug for ConclaveConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conclave Client Connection")
    }
}
