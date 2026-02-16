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

    /// Port to listen on for unencrypted connections
    #[arg(short, long)]
    unc_port: u16,

    /// Port to listen on for encrypted connections, for use the unencrypted port plus one
    #[arg(short, long)]
    enc_port: Option<u16>,

    /// Database file path
    #[arg(short, long, default_value = "server.db")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    conclave_common::init_tracing();
    let args = Args::parse();

    let enc_port = args.enc_port.unwrap_or(args.unc_port + 1);

    let state = if args.config.exists() {
        State::load(args.ip, enc_port, args.unc_port, &args.config)
    } else {
        State::new(
            "Conclave".into(),
            "Conclave server".into(),
            args.ip,
            enc_port,
            args.unc_port,
            args.config,
        )
    }?;
    state.serve().await?;

    Ok(ExitCode::SUCCESS)
}

#[test]
fn cli() {
    use clap::CommandFactory;

    Args::command().debug_assert();
}
