// SPDX-License-Identifier: Apache-2.0

//! Shared data structures for the file-sharing feature.
//!
//! A server may optionally expose a single directory tree. Access is controlled
//! per directory by a hidden [`ACL_FILENAME`] file that grants permissions to
//! groups (by name) and, explicitly, to unauthenticated guests. Permissions are
//! inherited from the nearest ancestor directory that has an ACL; the root
//! denies everything unless it has an ACL of its own.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Prefix reserved for the client/server's own files (ACLs, upload temporaries).
/// Names beginning with it are never listed, downloadable, uploadable, or
/// deletable by clients.
pub const RESERVED_PREFIX: &str = ".conclave-";

/// Name of the hidden per-directory access-control file. It is never served to
/// clients (it begins with [`RESERVED_PREFIX`]).
pub const ACL_FILENAME: &str = ".conclave-acl.toml";

/// A permission a principal (a group, or guests) may hold on a directory.
///
/// Permissions are independent, so a directory can be write-only (grant `Write`
/// without `List`/`Read`) to act as a drop box.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FilePermission {
    /// See the directory's entries.
    List,

    /// Download files from the directory.
    Read,

    /// Upload files into the directory.
    Write,

    /// Delete files from the directory.
    Delete,
}

impl FilePermission {
    /// All permissions, for building admin UIs.
    pub const ALL: [Self; 4] = [Self::List, Self::Read, Self::Write, Self::Delete];

    /// A short human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::List => "List",
            Self::Read => "Download",
            Self::Write => "Upload",
            Self::Delete => "Delete",
        }
    }
}

/// The access-control list for one shared directory: which groups (and guests)
/// hold which permissions. Serialized as [`ACL_FILENAME`] within the directory.
///
/// `guests` is written first so the file is valid TOML (a top-level array must
/// precede the `[groups]` table).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DirAcl {
    /// Permissions granted to unauthenticated guests. Guests get nothing unless
    /// listed here explicitly.
    #[serde(default)]
    pub guests: Vec<FilePermission>,

    /// Permissions granted per group, keyed by group name.
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<FilePermission>>,
}

/// Read-only summary of the server's shared directory, for administrators.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShareInfo {
    /// Absolute path of the shared directory on the server.
    pub path: String,

    /// Total size of the filesystem holding it, in bytes.
    pub total_bytes: u64,

    /// Space still available on that filesystem, in bytes.
    pub available_bytes: u64,
}

/// One entry in a shared-directory listing.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileEntry {
    /// File or subdirectory name (a single path component, never a path).
    pub name: String,

    /// Whether the entry is a subdirectory.
    pub is_dir: bool,

    /// Size in bytes (0 for directories).
    pub size: u64,
}
