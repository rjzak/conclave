// SPDX-License-Identifier: Apache-2.0

//! Server-side file sharing: path confinement, directory listing, and reading
//! and writing per-directory access-control lists.

pub(crate) use conclave_common::files::{
    ACL_FILENAME, DirAcl, FileEntry, FilePermission, RESERVED_PREFIX,
};

use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow, bail, ensure};

/// Resolve a client-supplied `/`-separated relative path against `root`,
/// rejecting traversal outside the root and any symbolic link encountered.
///
/// Every component must be a plain name (no `.`, `..`, absolute, or drive
/// components) and must not be a symlink; intermediate components must exist.
///
/// # Errors
///
/// Returns an error for an invalid component, a symlink, a missing path, or a
/// path that escapes the root.
pub fn resolve(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() {
            continue;
        }
        // Accept only a single, normal path component.
        let mut components = Path::new(part).components();
        let (Some(Component::Normal(name)), None) = (components.next(), components.next()) else {
            bail!("Invalid path component");
        };
        path.push(name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| anyhow!("No such path"))?;
        if metadata.file_type().is_symlink() {
            bail!("Symbolic links are not allowed");
        }
    }
    // The root is canonical and no symlinks or `..` were followed, so this holds;
    // verified anyway as defence in depth.
    if !path.starts_with(root) {
        bail!("Path escapes the shared directory");
    }
    Ok(path)
}

/// Resolve a target path for a new file (upload). The parent directory must
/// exist and resolve safely; the final name must be a single normal component
/// that is not reserved. The target itself need not exist.
///
/// # Errors
///
/// Returns an error for an empty/invalid/reserved name or an unsafe parent.
pub fn resolve_target(root: &Path, rel: &str) -> Result<PathBuf> {
    let trimmed = rel.trim_matches('/');
    ensure!(!trimmed.is_empty(), "Empty path");
    let (parent, name) = trimmed.rsplit_once('/').unwrap_or(("", trimmed));

    let mut components = Path::new(name).components();
    let (Some(Component::Normal(name)), None) = (components.next(), components.next()) else {
        bail!("Invalid file name");
    };
    ensure!(
        !name.to_string_lossy().starts_with(RESERVED_PREFIX),
        "Reserved file name"
    );

    let dir = resolve(root, parent)?;
    ensure!(dir.is_dir(), "Destination is not a directory");
    Ok(dir.join(name))
}

/// Path to a directory's ACL file.
fn acl_path(dir: &Path) -> PathBuf {
    dir.join(ACL_FILENAME)
}

/// Read a directory's own ACL, if present and parseable.
fn read_own_acl(dir: &Path) -> Option<DirAcl> {
    let contents = std::fs::read_to_string(acl_path(dir)).ok()?;
    toml::from_str(&contents).ok()
}

/// Read a directory's own ACL, defaulting to an empty ACL when absent.
#[must_use]
pub fn read_acl(dir: &Path) -> DirAcl {
    read_own_acl(dir).unwrap_or_default()
}

/// Write a directory's ACL atomically (temp file + rename).
///
/// # Errors
///
/// Returns an error on serialization or filesystem failure.
pub fn write_acl(dir: &Path, acl: &DirAcl) -> Result<()> {
    let contents = toml::to_string_pretty(acl)?;
    let temp_path = dir.join(format!("{ACL_FILENAME}.tmp"));
    std::fs::write(&temp_path, contents)?;
    std::fs::rename(&temp_path, acl_path(dir))?;
    Ok(())
}

/// The effective ACL for `dir`: its own ACL, or the nearest ancestor's up to and
/// including `root`. `None` means deny-by-default (no ACL found).
fn effective_acl(root: &Path, dir: &Path) -> Option<DirAcl> {
    let mut current = dir;
    loop {
        if let Some(acl) = read_own_acl(current) {
            return Some(acl);
        }
        if current == root {
            return None;
        }
        current = current.parent()?;
        if !current.starts_with(root) {
            return None;
        }
    }
}

/// Whether a requester holds `perm` on `dir`. Guests receive only the ACL's
/// explicit guest permissions; authenticated users receive those plus the union
/// of their groups' permissions. Administrators bypass this check entirely.
#[must_use]
pub fn has_permission(
    root: &Path,
    dir: &Path,
    groups: &[String],
    is_guest: bool,
    perm: FilePermission,
) -> bool {
    let Some(acl) = effective_acl(root, dir) else {
        return false;
    };
    if acl.guests.contains(&perm) {
        return true;
    }
    if is_guest {
        return false;
    }
    groups.iter().any(|group| {
        acl.groups
            .get(group)
            .is_some_and(|perms| perms.contains(&perm))
    })
}

/// List a directory's entries, hiding ACL files and symlinks. Sorted with
/// directories first, then case-insensitively by name.
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub fn list_dir(dir: &Path) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Hide the client/server's own files (ACLs, upload temporaries).
        if name.starts_with(RESERVED_PREFIX) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue; // never expose symlinks
        }
        let size = if file_type.is_file() {
            entry.metadata().map_or(0, |m| m.len())
        } else {
            0
        };
        entries.push(FileEntry {
            name,
            is_dir: file_type.is_dir(),
            size,
        });
    }
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

/// Delete a file or empty directory. Reserved files cannot be deleted; `target`
/// must already have passed [`resolve`] (which rejects symlinks).
///
/// # Errors
///
/// Returns an error for a reserved name, a non-empty directory, or a filesystem
/// failure.
pub fn delete(target: &Path) -> Result<()> {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    ensure!(
        !name.starts_with(RESERVED_PREFIX),
        "Cannot delete a reserved file"
    );
    if std::fs::symlink_metadata(target)?.file_type().is_dir() {
        std::fs::remove_dir(target)?; // empty directories only
    } else {
        std::fs::remove_file(target)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{has_permission, list_dir, resolve, resolve_target, write_acl};
    use conclave_common::files::{DirAcl, FilePermission};

    fn temp_root(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("conclave-files-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    #[test]
    fn rejects_traversal_and_bad_components() {
        let root = temp_root("resolve");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        assert!(resolve(&root, "../etc/passwd").is_err());
        assert!(resolve(&root, "sub/../..").is_err());
        assert!(resolve(&root, "sub").is_ok());
        assert!(resolve(&root, "").is_ok()); // the root itself
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn permission_model() {
        let root = temp_root("perms");
        // Grant guests List only, and group "staff" List + Read.
        let mut acl = DirAcl::default();
        acl.guests.push(FilePermission::List);
        acl.groups.insert(
            "staff".to_string(),
            vec![FilePermission::List, FilePermission::Read],
        );
        write_acl(&root, &acl).unwrap();

        // Guest: can List, cannot Read.
        assert!(has_permission(
            &root,
            &root,
            &[],
            true,
            FilePermission::List
        ));
        assert!(!has_permission(
            &root,
            &root,
            &[],
            true,
            FilePermission::Read
        ));
        // Staff member: can Read (group), and List (inherited guest grant).
        let staff = vec!["staff".to_string()];
        assert!(has_permission(
            &root,
            &root,
            &staff,
            false,
            FilePermission::Read
        ));
        assert!(has_permission(
            &root,
            &root,
            &staff,
            false,
            FilePermission::List
        ));
        // Other authenticated user: only the guest grant (List).
        let other = vec!["random".to_string()];
        assert!(has_permission(
            &root,
            &root,
            &other,
            false,
            FilePermission::List
        ));
        assert!(!has_permission(
            &root,
            &root,
            &other,
            false,
            FilePermission::Read
        ));

        // A subdirectory with no ACL inherits the root's.
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        assert!(has_permission(
            &root,
            &sub,
            &staff,
            false,
            FilePermission::Read
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn upload_target_validation() {
        let root = temp_root("upload");
        assert!(resolve_target(&root, "file.txt").is_ok());
        assert!(resolve_target(&root, ".conclave-acl.toml").is_err()); // reserved
        assert!(resolve_target(&root, ".conclave-upload-1.tmp").is_err()); // reserved
        assert!(resolve_target(&root, "../evil").is_err()); // traversal
        assert!(resolve_target(&root, "nope/file.txt").is_err()); // missing parent
        assert!(resolve_target(&root, "").is_err()); // empty
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn drop_box_is_write_only() {
        let root = temp_root("dropbox");
        let mut acl = DirAcl::default();
        acl.groups
            .insert("dropper".to_string(), vec![FilePermission::Write]);
        write_acl(&root, &acl).unwrap();
        let dropper = vec!["dropper".to_string()];
        assert!(has_permission(
            &root,
            &root,
            &dropper,
            false,
            FilePermission::Write
        ));
        assert!(!has_permission(
            &root,
            &root,
            &dropper,
            false,
            FilePermission::List
        ));
        assert!(!has_permission(
            &root,
            &root,
            &dropper,
            false,
            FilePermission::Read
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn listing_hides_acl_file() {
        let root = temp_root("listing");
        std::fs::write(root.join("hello.txt"), b"hi").unwrap();
        write_acl(&root, &DirAcl::default()).unwrap();
        let entries = list_dir(&root).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        let _ = std::fs::remove_dir_all(&root);
    }
}
