// SPDX-License-Identifier: Apache-2.0

use conclave_common::server::VerifyingKey;

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use pqcrypto_mldsa::mldsa87;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const DEFAULT_CLIENT_FILE: &str = "conclave.toml";

/// Find a conf file, either in the home directory or in the current directory.
///
/// # Errors
///
/// Filesystem errors are possible.
pub fn default_config_path() -> Result<PathBuf> {
    if let Some(mut home_config) = home::home_dir() {
        home_config.push(".config");
        if !home_config.exists() {
            std::fs::create_dir_all(&home_config)?;
        }
        home_config.push(DEFAULT_CLIENT_FILE);
        Ok(home_config)
    } else {
        Ok(PathBuf::from(DEFAULT_CLIENT_FILE))
    }
}

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
#[derive(Clone, Deserialize, Serialize)]
pub struct Tracker {
    /// Domain or IP address of the tracker
    pub name: String,

    /// Port of the tracker
    pub port: u16,

    /// Tracker's public key
    #[serde(
        serialize_with = "conclave_common::serde::serialize_mldsa_public_key",
        deserialize_with = "conclave_common::serde::deserialize_mldsa_public_key"
    )]
    pub key: mldsa87::PublicKey,
}

impl std::fmt::Debug for Tracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tracker")
            .field("server", &self.name)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Eq for Tracker {}

impl PartialEq for Tracker {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.port == other.port
    }
}

impl std::hash::Hash for Tracker {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.port.hash(state);
    }
}

/// Server bookmark entry
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct BookmarkEntry {
    /// Domain or IP address of the server
    pub server: String,

    /// Name of the server
    #[serde(default)]
    pub name: String,

    /// Port of the server
    pub port: Port,

    /// User's display name
    pub display_name: String,

    /// User's username
    #[serde(default)]
    pub auth: Option<UserAuth>,

    /// Server's public key
    #[serde(
        serialize_with = "conclave_common::serde::serialize_dalek_public_key",
        deserialize_with = "conclave_common::serde::deserialize_dalek_public_key"
    )]
    #[zeroize(skip)]
    pub key: VerifyingKey,

    /// Share local time (and timezone, which provides location information) with the server.
    #[serde(default)]
    pub share_time: bool,
}

/// User's credential for a server
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct UserAuth {
    /// User name
    pub username: String,

    /// Password
    pub password: String,
}

/// Port information
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub enum Port {
    /// Unencrypted port
    Unencrypted(u16),

    /// Encrypted port
    Encrypted(u16),

    /// Encrypted and unencrypted port, in that order
    EncryptedAndUnencrypted((u16, u16)),
}
