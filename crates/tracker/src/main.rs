// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(
    all(not(debug_assertions), feature = "gui"),
    windows_subsystem = "windows"
)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_tracker::TrackerConfig;

use std::path::PathBuf;

use clap::{Parser, ValueHint};

pub const VERSION: &str = concat!(
    "v",
    env!("CONCLAVE_VERSION"),
    " ",
    env!("CONCLAVE_BUILD_DATE")
);

/// Conclave Tracker
#[derive(Parser, Debug)]
#[command(author, about, version = VERSION)]
struct Args {
    /// Path to config
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = conclave_tracker::default_config_path().into_os_string())]
    config: PathBuf,
}

#[cfg(not(feature = "gui"))]
#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    conclave_common::init_tracing();
    let args = Args::parse();
    let config = TrackerConfig::load_or_save(&args.config)
        .map_err(|e| panic!("Unable to read {}: {e}", args.config.display()))
        .unwrap();

    let tracker = conclave_tracker::State::new(config.ip, config.port, config.keys);
    println!("Listening on {}:{}", config.ip, config.port);
    tracker.serve().await?;
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(feature = "gui")]
fn main() -> eframe::Result {
    conclave_common::init_tracing();
    let args = Args::parse();
    let config = TrackerConfig::load_or_save(&args.config)
        .map_err(|e| panic!("Unable to read {}: {e}", args.config.display()))
        .unwrap();

    let tracker = conclave_tracker::State::new(config.ip, config.port, config.keys);
    println!("Listening on {}:{}", config.ip, config.port);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let tracker_copy = tracker.clone();
    rt.spawn(async move {
        if let Err(e) = tracker_copy.serve().await {
            eprintln!("Tracker error: {e}");
        }
    });

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([240.0, 85.0])
            .with_resizable(false),
        ..Default::default()
    };

    eframe::run_native(
        "Conclave Tracker",
        options,
        Box::new(|_cc| Ok(Box::new(tracker))),
    )
}

#[test]
fn cli() {
    use clap::CommandFactory;

    Args::command().debug_assert();
}
