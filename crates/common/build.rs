// SPDX-License-Identifier: Apache-2.0

use chrono::Utc;

fn main() {
    println!("cargo::rustc-env=CONCLAVE_VERSION={}", version());
    println!(
        "cargo::rustc-env=CONCLAVE_BUILD_DATE={}",
        Utc::now().format("%Y-%m-%d")
    );
}

/// Get the commit hash and whether the project is dirty (uncommited changes).
fn version() -> String {
    let package = env!("CARGO_PKG_VERSION");
    let Some(git_dir) = git(&["rev-parse", "--git-dir"]) else {
        // No git checkout (a source tarball, say): report the version from Cargo.toml
        return package.to_string();
    };

    // Ensure changes to the git structure trigger a rebuild.
    let git_path = std::path::Path::new(&git_dir);
    for input in ["HEAD", "packed-refs", "refs/heads", "refs/tags"] {
        if git_path.join(input).exists() {
            println!("cargo::rerun-if-changed={git_dir}/{input}");
        }
    }

    let Some(hash) = git(&["rev-parse", "--short", "HEAD"]).filter(|h| !h.is_empty()) else {
        // A repository with no commit yet.
        return package.to_string();
    };

    // Tracked changes only
    let dirty = std::process::Command::new("git")
        .args(["diff", "--quiet", "HEAD", "--"])
        .status()
        .is_ok_and(|status| !status.success());

    if dirty {
        format!("{package}+{hash}.dirty")
    } else {
        format!("{package}+{hash}")
    }
}

/// Run a git command, returning its trimmed stdout when it succeeds.
fn git(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?.trim();
    Some(text.to_string())
}
