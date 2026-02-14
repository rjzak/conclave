// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_client::Client;

use std::path::PathBuf;

use clap::Parser;

pub const VERSION: &str = concat!(env!("CONCLAVE_VERSION"), " ", env!("CONCLAVE_BUILD_DATE"));

/// Conclave Client
#[derive(Parser, Debug)]
#[command(author, about, version = VERSION)]
struct Args {
    /// Database file path
    #[arg(short, long, default_value = "client.db")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let _client = Client::new(args.config).unwrap();
}
