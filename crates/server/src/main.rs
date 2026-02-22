// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_server::{DEFAULT_DATABASE, State};

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dialoguer::Password;

pub const VERSION: &str = concat!(env!("CONCLAVE_VERSION"), " ", env!("CONCLAVE_BUILD_DATE"));

/// Conclave Server
#[derive(Parser, Debug)]
#[command(author, about, version = VERSION)]
enum Args {
    /// Administrative commands
    Admin(Admin),

    /// Run the server
    Run(Run),
}

#[derive(Parser, Debug)]
struct Admin {
    /// Database file path
    #[arg(short, long, default_value = DEFAULT_DATABASE)]
    config: PathBuf,

    /// Admin action
    #[clap(subcommand)]
    action: AdminActions,
}

#[derive(Subcommand, Clone, Debug)]
enum AdminActions {
    ResetAdminPassword,
}

#[derive(Parser, Debug)]
struct Run {
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
    #[arg(short, long, default_value = DEFAULT_DATABASE)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    conclave_common::init_tracing();

    let run = match Args::parse() {
        Args::Admin(admin) => {
            // These ports don't matter as we won't use them
            let state = State::load(IpAddr::V4(Ipv4Addr::LOCALHOST), 9998, 9999, &admin.config)?;
            match &admin.action {
                AdminActions::ResetAdminPassword => {
                    let password = Password::new()
                        .with_prompt("New Password")
                        .with_confirmation("Confirm password", "Passwords mismatching")
                        .interact()?;
                    state.reset_admin_password(&password).await?;
                }
            }
            return Ok(ExitCode::SUCCESS);
        }
        Args::Run(run) => run,
    };

    let enc_port = run.enc_port.unwrap_or(run.unc_port + 1);

    let state = if run.config.exists() {
        State::load(run.ip, enc_port, run.unc_port, &run.config)?
    } else {
        let (state, password) = State::new(
            "Conclave".into(),
            "Conclave server".into(),
            run.ip,
            enc_port,
            run.unc_port,
            run.config,
        )?;

        println!("Admin password: {password}\nThis will only appears this first time.");
        state
    };
    state.serve().await?;

    Ok(ExitCode::SUCCESS)
}

#[test]
fn cli() {
    use clap::CommandFactory;

    Args::command().debug_assert();
}
