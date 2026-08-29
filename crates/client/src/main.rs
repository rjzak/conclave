// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

mod gui;

use conclave_client::{Client, config::default_config_path};

use std::path::PathBuf;

use clap::{Parser, ValueHint};

pub const VERSION: &str = concat!(
    "v",
    env!("CONCLAVE_VERSION"),
    " ",
    env!("CONCLAVE_BUILD_DATE")
);

/// Conclave Client
#[derive(Parser, Debug)]
#[command(author, about, version = VERSION)]
struct Args {
    /// Config file path
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = default_config_path().into_os_string())]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> eframe::Result {
    conclave_common::init_tracing();
    let args = Args::parse();
    let client = Client::new(&args.config)
        .map_err(|e| panic!("Unable to read {}: {e}", args.config.display()))
        .unwrap();

    #[cfg(debug_assertions)]
    {
        let wgpu = wgpu::Instance::enabled_backend_features();
        eprintln!("WGPU Features: {wgpu:?}");
    }

    // Fixed, non-resizable main window. The absolute size below is a starting
    // point; on the first frame the GUI clamps it to the monitor (preserving the
    // aspect ratio) so it stays proportional across platforms and DPI settings.
    // See `gui::MAIN_WINDOW_SIZE` and `ConclaveGUI::fit_main_window`.
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(gui::MAIN_WINDOW_SIZE)
            .with_resizable(false),
        ..Default::default()
    };
    eframe::run_native(
        "Conclave",
        native_options,
        Box::new(|cc| Ok(Box::new(gui::ConclaveGUI::new(client, cc)))),
    )
}
