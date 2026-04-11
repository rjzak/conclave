// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_server::{DEFAULT_DATABASE, State};

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dialoguer::Password;
use zeroize::Zeroize;

pub const VERSION: &str = concat!(
    "v",
    env!("CONCLAVE_VERSION"),
    " ",
    env!("CONCLAVE_BUILD_DATE")
);

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

    /// Advertise this server via Multicast DNS
    #[arg(short, long)]
    mdns: bool,
}

async fn common_main(args: Args) -> Result<State> {
    let run = match args {
        Args::Admin(admin) => {
            // These ports don't matter as we won't use them
            let state = State::load(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                9998,
                9999,
                false,
                &admin.config,
            )?;
            match &admin.action {
                AdminActions::ResetAdminPassword => {
                    let password = Password::new()
                        .with_prompt("New Password")
                        .with_confirmation("Confirm password", "Passwords mismatching")
                        .interact()?;
                    state.reset_admin_password(&password).await?;
                }
            }
            std::process::exit(0);
        }
        Args::Run(run) => run,
    };

    let enc_port = run.enc_port.unwrap_or(run.unc_port + 1);

    Ok(if run.config.exists() {
        State::load(run.ip, enc_port, run.unc_port, run.mdns, &run.config)?
    } else {
        let (state, mut password) = State::new(
            "Conclave".into(),
            "Conclave server".into(),
            run.ip,
            run.domain,
            enc_port,
            run.unc_port,
            run.mdns,
            run.config,
        )?;

        println!(
            "Admin password: {}\nThis will only appears this first time.",
            password.as_str()
        );
        password.zeroize();
        state
    })
}

#[cfg(not(feature = "gui"))]
#[tokio::main]
async fn main() -> Result<std::process::ExitCode> {
    conclave_common::init_tracing();
    let state = common_main(Args::parse()).await?;
    state.serve().await?;
    Ok(std::process::ExitCode::SUCCESS)
}

#[allow(unused_variables)]
#[cfg(feature = "gui")]
fn main() -> eframe::Result {
    conclave_common::init_tracing();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()
        .unwrap();

    let state = rt
        .block_on(common_main(Args::parse()))
        .expect("Failed to load server state from provided arguments or database file.");

    let state_copy = state.clone();
    rt.spawn(async move {
        if let Err(e) = state_copy.serve().await {
            eprintln!("Server error: {e}");
        }
    });

    let wgpu = wgpu::Instance::enabled_backend_features();
    #[cfg(debug_assertions)]
    eprintln!("WGPU Features: {wgpu:?}");

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([240.0, 97.0])
            .with_resizable(false),
        ..Default::default()
    };

    eframe::run_native(
        "Conclave Server",
        options,
        Box::new(|_cc| Ok(Box::new(state))),
    )
}

#[test]
fn cli() {
    use clap::CommandFactory;

    Args::command().debug_assert();
}
