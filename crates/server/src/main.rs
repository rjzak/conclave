// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::net::IpAddr;

use clap::Parser;

pub const VERSION: &str = concat!(env!("CONCLAVE_VERSION"), " ", env!("CONCLAVE_BUILD_DATE"));

/// Conclave Server
#[derive(Parser, Debug)]
#[command(author, about, version = VERSION)]
struct Args {
    /// IP Address to listen on
    #[arg(short, long)]
    ip: IpAddr,

    /// Advertised domain
    #[arg(short, long)]
    domain: Option<String>,

    /// Port to listen on
    #[arg(short, long)]
    port: u16,
}

fn main() {
    let _args = Args::parse();
    println!("Hello, server!");
}

#[test]
fn cli() {
    use clap::CommandFactory;

    Args::command().debug_assert();
}
