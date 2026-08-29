// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::path::PathBuf;

/// Administrative data structures
pub mod admin;

/// Data structures for communicating with the tracker
pub mod tracker;

/// Networking utilities
pub mod net;

/// Post-quantum primitives, from the `RustCrypto` project's `ml-dsa` and `ml-kem` crates
pub mod pqc;

/// End-to-end encryption for direct messages between users
pub mod dm;

/// Data structures for the optional file-sharing feature
pub mod files;

/// Data structures for the optional threaded-discussion (forum) feature
pub mod forum;

/// Serialization and deserialization utilities for cryptographic keys. Keys stored in config files
/// are base64-encoded; the `_bytes` variants, along with the signature helpers, keep the same
/// material as raw bytes for the ML-DSA types sent over the network, which have no `serde`
/// implementations of their own.
pub mod serde;

/// Data structures for communicating with the server
pub mod server;

/// URL protocol
pub const URL_PROTOCOL: &str = "conclave://";

/// Endpoint name for use with Multicast DNS
pub const MDNS_NAME: &str = "_conclave._tcp.local.";

/// Multicast DNS property indicating whether anonymous connections are allowed
pub const MDNS_ANONYMOUS: &str = "anonymous";

/// Multicast DNS property for the server's description
pub const MDNS_DESCRIPTION: &str = "description";

/// Multicast DNS property containing the server's public key
pub const MDNS_KEY: &str = "key";

/// Multicast DNS property for the server's version
pub const MDNS_VERSION: &str = "version";

/// DNS SRV record if just given a domain name without a port
pub const DNS_SRV_RECORD: &str = "_conclave._tcp.conclave-srv.";

/// Default server port
pub const SERVER_DEFAULT_PORT: u16 = 9123;

/// Default tracker port
pub const TRACKER_DEFAULT_PORT: u16 = 9321;

/// Initialize tracing
pub fn init_tracing() {
    use std::sync::Once;

    // Useful currently for testing
    static TRACING: Once = Once::new();
    TRACING.call_once(tracing_subscriber::fmt::init);
}

/// Get a path for storing various config files for Conclave in this order:
///
/// 1. User's home directory: `$HOME/.config/conclave/`, `%USERPROFILE%\AppData\Local\Conclave` on Windows, or
///    `/boot/home/config/settings/Conclave` on Haiku.
/// 2. The directory containing the executable.
/// 3. The current working directory.
///
/// # Panics
///
/// A panic occurs if the configuration directory cannot be created in the user's home directory. It's
/// expected that this function is only called when the program immediately loads, so it won't interfere
/// with a long-running process.
#[inline]
#[must_use]
pub fn default_config_directory() -> PathBuf {
    #[cfg(target_os = "haiku")]
    {
        use std::str::FromStr;

        let path = PathBuf::from_str("/boot/home/config/settings/Conclave").unwrap();
        if !path.exists() {
            std::fs::create_dir_all(&path)
                .map_err(|e| {
                    panic!(
                        "Error creating Conclave's config directory {}: {e}",
                        path.display()
                    )
                })
                .unwrap();
        }
        return path;
    }

    #[cfg(not(target_os = "haiku"))]
    if let Some(mut home_config) = home::home_dir() {
        #[cfg(target_family = "windows")]
        {
            home_config.push("AppData");
            home_config.push("Local");
            home_config.push("Conclave");
        }
        #[cfg(not(target_family = "windows"))]
        {
            home_config.push(".config");
            home_config.push("conclave");
        }
        if !home_config.exists() {
            std::fs::create_dir_all(&home_config)
                .map_err(|e| {
                    panic!(
                        "Error creating Conclave's config directory {}: {e}",
                        home_config.display()
                    )
                })
                .unwrap();
        }
        home_config
    } else if let Ok(exe_path) = std::env::current_exe()
        && let Some(parent) = exe_path.parent()
    {
        parent.into()
    } else {
        PathBuf::from("./")
    }
}
