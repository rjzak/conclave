// SPDX-License-Identifier: Apache-2.0

use conclave_common::net::{SigningKey, random_keypair};
use conclave_common::server::VerifyingKey;
use conclave_common::tracker::TrackerWithKey;

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default client config file
const DEFAULT_CLIENT_FILE: &str = "conclave.toml";

/// Find the client config file from the common OS-specific Conclave config directory
///
/// # Panics
///
/// Panics if the home directory can't be created in the user's home directory.
#[must_use]
pub fn default_config_path() -> PathBuf {
    let mut config_file = conclave_common::default_config_directory();
    config_file.push(DEFAULT_CLIENT_FILE);
    config_file
}

/// Client configuration
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ClientConfig {
    /// Default display name to use when connecting to servers
    pub default_display_name: String,

    /// Whether to share the local timezone with the server
    pub default_share_timezone: bool,

    /// User's profile
    #[serde(default)]
    pub profile: String,

    /// User's social links. Name:URL
    #[serde(default)]
    pub urls: BTreeMap<String, String>,

    /// Signing (private) key
    #[serde(
        serialize_with = "conclave_common::serde::serialize_dalek_private_key",
        deserialize_with = "conclave_common::serde::deserialize_dalek_private_key"
    )]
    pub signing_key: SigningKey,

    /// Verifying (public) key
    #[serde(
        serialize_with = "conclave_common::serde::serialize_dalek_public_key",
        deserialize_with = "conclave_common::serde::deserialize_dalek_public_key"
    )]
    pub verifying_key: VerifyingKey,

    /// List of trackers to use
    pub trackers: Vec<TrackerWithKey>,

    /// List of servers for easy access
    pub bookmarks: Vec<BookmarkEntry>,

    /// Cached keys for servers previously connected to
    pub known_hosts: Vec<KnownHost>,

    /// The user's avatar, stored as a 512×512 PNG. A 32×32 thumbnail is shared
    /// with servers and shown next to the user's name.
    #[serde(default, with = "crate::avatar::serde_b64")]
    pub avatar: Option<Vec<u8>>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        let (signing_key, verifying_key) = random_keypair();

        Self {
            default_display_name: "Unnamed User".to_string(),
            default_share_timezone: true,
            profile: String::new(),
            urls: BTreeMap::new(),
            trackers: Vec::new(),
            bookmarks: Vec::new(),
            known_hosts: Vec::new(),
            avatar: None,
            signing_key,
            verifying_key,
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
            Some(ext) if ext == "toml" => toml::to_string_pretty(&self)?,
            Some(ext) if ext == "json" => serde_json::to_string_pretty(&self)?,
            Some(ext) => bail!("Unsupported file format {}", ext.display()),
            None => bail!("File {} has no extension", path.as_ref().display()),
        };

        let mut options = OpenOptions::new();
        options
            .write(true)
            .create(true)
            .append(false)
            .truncate(true);

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }

        let mut file = options.open(&path)?;
        write!(file, "{contents}")?;

        Ok(())
    }
}

/// Server bookmark entry
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct BookmarkEntry {
    /// Domain or IP address of the server
    #[serde(flatten)]
    pub server: KnownHost,

    /// Name of the server
    pub name: String,

    /// User's display name
    pub display_name: String,

    /// User's profile
    #[serde(default)]
    pub profile: String,

    /// User's social links. Name: URL
    #[serde(default)]
    #[zeroize(skip)]
    pub urls: BTreeMap<String, String>,

    /// User's username
    #[serde(default)]
    pub auth: Option<UserAuth>,

    /// Share local time (and timezone, which provides location information) with the server.
    #[serde(default)]
    pub share_time: bool,

    /// Avatar to present on this server, stored as a 512×512 PNG. When `None`,
    /// the client's default avatar (if any) is used instead.
    #[serde(default, with = "crate::avatar::serde_b64")]
    #[zeroize(skip)]
    pub avatar: Option<Vec<u8>>,
}

/// User's credential for a server
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct UserAuth {
    /// User name
    pub username: String,

    /// Password
    pub password: String,
}

/// Server and key for each server with which the client has successfully connected
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct KnownHost {
    /// Server IP or DNS
    pub host: String,

    /// Port of the server
    pub port: u16,

    /// Server's key
    #[serde(
        serialize_with = "conclave_common::serde::serialize_dalek_public_key",
        deserialize_with = "conclave_common::serde::deserialize_dalek_public_key"
    )]
    #[zeroize(skip)]
    pub key: VerifyingKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avatar_round_trips_through_toml_and_json() {
        let mut config = ClientConfig::default();

        // `None` must serialise cleanly (TOML has no null) and reload as `None`.
        let toml_text = toml::to_string_pretty(&config).expect("serialize toml");
        assert!(!toml_text.contains("avatar"));
        let loaded: ClientConfig = toml::from_str(&toml_text).expect("parse toml");
        assert_eq!(loaded.avatar, None);

        // `Some` bytes round-trip unchanged through both formats.
        config.avatar = Some(vec![0u8, 1, 2, 3, 254, 255]);
        let toml_text = toml::to_string_pretty(&config).expect("serialize toml");
        let loaded: ClientConfig = toml::from_str(&toml_text).expect("parse toml");
        assert_eq!(loaded.avatar, config.avatar);

        let json_text = serde_json::to_string(&config).expect("serialize json");
        let loaded: ClientConfig = serde_json::from_str(&json_text).expect("parse json");
        assert_eq!(loaded.avatar, config.avatar);

        // A bookmark's optional avatar round-trips the same way.
        config.bookmarks.push(BookmarkEntry {
            server: KnownHost {
                host: "example.com".into(),
                port: 1111,
                key: config.verifying_key,
            },
            name: "Example".into(),
            display_name: "Me".into(),
            profile: String::new(),
            urls: BTreeMap::new(),
            auth: None,
            share_time: false,
            avatar: Some(vec![9u8, 8, 7, 6]),
        });
        let toml_text = toml::to_string_pretty(&config).expect("serialize toml");
        let loaded: ClientConfig = toml::from_str(&toml_text).expect("parse toml");
        assert_eq!(loaded.bookmarks[0].avatar, Some(vec![9u8, 8, 7, 6]));
    }
}
