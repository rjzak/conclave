// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

/// Data structures for communicating with the tracker
pub mod tracker;

/// Networking utilities
pub mod net;

/// Data structures for communicating with the server
pub mod server;

/// Protocol magic
pub const HELLO: &[u8] = b"HELLO CONCLAVE!";

/// URL protocol
pub const URL_PROTOCOL: &str = "conclave://";

/// Initialize tracing
pub fn init_tracing() {
    use std::sync::Once;

    // Useful currently for testing
    static TRACING: Once = Once::new();
    TRACING.call_once(tracing_subscriber::fmt::init);
}
