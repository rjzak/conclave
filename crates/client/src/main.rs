// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

mod gui;

use conclave_client::{Client, config::DEFAULT_CLIENT_FILE};

use std::path::PathBuf;

use clap::Parser;

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
    #[arg(short, long, default_value = DEFAULT_CLIENT_FILE)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> eframe::Result {
    conclave_common::init_tracing();
    let args = Args::parse();
    let _client = Client::new(args.config).unwrap();

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([400.0, 300.0])
            .with_min_inner_size([300.0, 220.0]),
        ..Default::default()
    };
    eframe::run_native(
        "eframe template",
        native_options,
        Box::new(|cc| Ok(Box::new(gui::ConclaveClient::new(cc)))),
    )
}
