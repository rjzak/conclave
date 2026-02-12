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

/// Protocol magic
pub const HELLO: &[u8] = b"HELLO CONCLAVE!";

/// URL protocol
pub const URL_PROTOCOL: &str = "conclave://";
