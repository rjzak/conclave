// SPDX-License-Identifier: Apache-2.0

use std::ops::Add;

use chrono::Utc;

fn main() {
    // Manually get Git information
    // Adapted from https://github.com/ratatui/async-template/blob/main/ratatui-counter/build.rs

    let git_output = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok();
    let git_dir = git_output
        .as_ref()
        .and_then(|output| std::str::from_utf8(&output.stdout).ok().map(str::trim));

    // Tell cargo to rebuild if the head or any relevant refs change.
    if let Some(git_dir) = git_dir {
        let git_path = std::path::Path::new(git_dir);
        let refs_path = git_path.join("refs");
        if git_path.join("HEAD").exists() {
            println!("cargo:rerun-if-changed={}/HEAD", git_dir);
        }
        if git_path.join("packed-refs").exists() {
            println!("cargo:rerun-if-changed={}/packed-refs", git_dir);
        }
        if refs_path.join("heads").exists() {
            println!("cargo:rerun-if-changed={}/refs/heads", git_dir);
        }
        if refs_path.join("tags").exists() {
            println!("cargo:rerun-if-changed={}/refs/tags", git_dir);
        }
        let git_short_hash_cmd = std::process::Command::new("git")
            .args(["rev-parse", "--short", "head"])
            .output()
            .ok();
        let git_short_hash = git_short_hash_cmd
            .as_ref()
            .and_then(|output| std::str::from_utf8(&output.stdout).ok().map(str::trim));

        // Default git_describe to cargo_pkg_version
        let mut git_describe = String::from(env!("CARGO_PKG_VERSION"));
        if let Some(git_short_hash) = git_short_hash {
            git_describe = format!("v{git_describe}-{git_short_hash}");
        }

        let git_dirty_cmd = std::process::Command::new("git")
            .args(["describe", "--all", "--dirty"])
            .output()
            .ok();
        let git_dirty = git_dirty_cmd
            .as_ref()
            .and_then(|output| std::str::from_utf8(&output.stdout).ok().map(str::trim));
        let dirty = git_dirty.map(|d| d.contains("dirty")).unwrap_or(false);
        if dirty {
            git_describe = git_describe.add("-dirty");
        }

        println!("cargo:rustc-env=CONCLAVE_VERSION={}", git_describe);
    } else {
        println!(
            "cargo:rustc-env=CONCLAVE_VERSION=v{}",
            env!("CARGO_PKG_VERSION")
        );
    }

    println!(
        "cargo:rustc-env=CONCLAVE_BUILD_DATE={}",
        Utc::now().format("%Y-%m-%d")
    );
}
