// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::process::ExitCode;

use anyhow::Result;
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

#[tokio::main]
async fn main() -> Result<ExitCode> {
    conclave_common::init_tracing();
    let args = Args::parse();
    let tracker = conclave_tracker::State::new(args.ip, args.port);
    println!("Listening on {}:{}", args.ip, args.port);
    tracker.serve().await?;
    Ok(ExitCode::SUCCESS)
}

#[test]
fn cli() {
    use clap::CommandFactory;

    Args::command().debug_assert();
}
