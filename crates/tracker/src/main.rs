// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::net::IpAddr;

use clap::Parser;

pub const VERSION: &str = concat!(env!("CONCLAVE_VERSION"), " ", env!("CONCLAVE_BUILD_DATE"));

/// Conclave Tracker
#[derive(Parser, Debug)]
#[command(author, about, version = VERSION)]
struct Args {
    /// IP Address to listen on
    ip: IpAddr,

    /// Port to listen on
    port: u16,
}

#[cfg(not(feature = "gui"))]
#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    conclave_common::init_tracing();
    let args = Args::parse();
    let tracker = conclave_tracker::State::new(args.ip, args.port);
    println!("Listening on {}:{}", args.ip, args.port);
    tracker.serve().await?;
    Ok(std::process::ExitCode::SUCCESS)
}

#[allow(unused_variables)]
#[cfg(feature = "gui")]
fn main() -> eframe::Result {
    conclave_common::init_tracing();
    let args = Args::parse();
    let tracker = conclave_tracker::State::new(args.ip, args.port);
    println!("Listening on {}:{}", args.ip, args.port);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()
        .unwrap();
    let tracker_copy = tracker.clone();
    rt.spawn(async move {
        if let Err(e) = tracker_copy.serve().await {
            eprintln!("Server error: {e}");
        }
    });

    let wgpu = wgpu::Instance::enabled_backend_features();
    #[cfg(debug_assertions)]
    eprintln!("WGPU Features: {wgpu:?}");

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([240.0, 85.0]),
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
