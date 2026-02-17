// SPDX-License-Identifier: Apache-2.0

use conclave_common::server::VerifyingKey;

use std::path::Path;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Client configuration
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct ClientConfig {
    /// Default display name to use when connecting to servers
    pub default_display_name: String,

    /// List of trackers to use
    pub trackers: Vec<Tracker>,

    /// List of servers for easy access
    pub bookmarks: Vec<BookmarkEntry>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            default_display_name: "Unnamed User".to_string(),
            trackers: Vec::new(),
            bookmarks: Vec::new(),
        }
    }
}

impl ClientConfig {
    /// Load a config from a file path, using the file extension to determine the format.
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

    /// Save the config to a file path, using the file extension to determine the format
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
}

/// Tracker listing entry
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct Tracker {
    /// Domain or IP address of the tracker
    pub server: String,

    /// Port of the tracker
    pub port: u16,
}

/// Server bookmark entry
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct BookmarkEntry {
    /// Domain or IP address of the server
    pub server: String,

    /// Port of the server
    pub port: u16,

    /// User's display name
    pub display_name: String,

    /// User's username
    pub auth: Option<UserAuth>,

    /// Server's public key
    pub key: VerifyingKey,
}

/// User's credential for a server
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct UserAuth {
    /// User name
    pub username: String,

    /// Password
    pub password: String,
}
