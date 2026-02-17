// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_client::Client;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

pub const VERSION: &str = concat!(env!("CONCLAVE_VERSION"), " ", env!("CONCLAVE_BUILD_DATE"));

/// Conclave Client
#[derive(Parser, Debug)]
#[command(author, about, version = VERSION)]
struct Args {
    /// Config file path
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    conclave_common::init_tracing();
    let args = Args::parse();
    let _client = Client::new(args.config)?;

    Ok(ExitCode::SUCCESS)
}
