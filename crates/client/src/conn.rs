// SPDX-License-Identifier: Apache-2.0

use conclave_common::net::DefaultEncryptedStream;
use conclave_common::server::{ConnectedUser, ServerInformation, ServerMessagesEncrypted};

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;

/// Connection information
#[allow(dead_code)]
pub struct ConclaveConnection {
    /// Encrypted connection to a server
    pub(crate) connection: Arc<RwLock<DefaultEncryptedStream>>,

    /// Server information
    pub(crate) server_info: Arc<RwLock<ServerInformation>>,

    /// Display name shown for the user on this server
    pub(crate) display_name: Arc<RwLock<String>>,
}

impl ConclaveConnection {
    /// Create a connection object
    pub fn new(conn: DefaultEncryptedStream, info: ServerInformation, display_name: &str) -> Self {
        ConclaveConnection {
            connection: Arc::new(RwLock::new(conn)),
            server_info: Arc::new(RwLock::new(info)),
            display_name: Arc::new(RwLock::new(display_name.to_string())),
        }
    }

    /// Update server information locally and return the data
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn server_info(&self) -> Result<ServerInformation> {
        let request = postcard::to_stdvec(&ServerMessagesEncrypted::ServerInformationRequest)?;
        self.connection.write().await.send(&request).await?;

        let server_info = self.connection.write().await.recv().await?;
        let server_info = postcard::from_bytes::<ServerInformation>(&server_info)?;
        self.server_info.write().await.clone_from(&server_info);

        Ok(server_info)
    }

    /// Get users connected to the server
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn connected_users(&self) -> Result<Vec<ConnectedUser>> {
        let request = postcard::to_stdvec(&ServerMessagesEncrypted::ListConnectedUsersRequest)?;
        self.connection.write().await.send(&request).await?;

        let users = self.connection.write().await.recv().await?;
        let users = postcard::from_bytes::<Vec<ConnectedUser>>(&users)?;
        Ok(users)
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
        self.connection.write().await.shutdown().await?;
        Ok(())
    }
}

impl std::fmt::Debug for ConclaveConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conclave Client Connection")
    }
}
