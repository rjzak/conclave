// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use conclave_server::State;

pub const VERSION: &str = concat!(env!("CONCLAVE_VERSION"), " ", env!("CONCLAVE_BUILD_DATE"));

/// Conclave Server
#[derive(Parser, Debug)]
#[command(author, about, version = VERSION)]
struct Args {
    /// IP Address to listen on
    #[arg(short, long, default_value = "127.0.0.1")]
    ip: IpAddr,

    /// Advertised domain
    #[arg(short, long)]
    domain: Option<String>,

    /// Port to listen on
    #[arg(short, long)]
    port: u16,

    /// Database file path
    #[arg(short, long, default_value = "server.db")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let args = Args::parse();
    let state = if args.config.exists() {
        State::load(args.ip, args.port, &args.config)
    } else {
        State::new(
            "Conclave".into(),
            "Conclave server".into(),
            args.ip,
            args.port,
            args.config,
        )
    }?;
    state.advertise_trackers()?;
    state.serve()?;

    Ok(ExitCode::SUCCESS)
}

#[test]
fn cli() {
    use clap::CommandFactory;

    Args::command().debug_assert();
}
