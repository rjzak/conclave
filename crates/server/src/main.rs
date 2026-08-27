// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(
    all(not(debug_assertions), feature = "gui"),
    windows_subsystem = "windows"
)]
#![doc = include_str!("../README.md")]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_common::default_config_directory;
use conclave_server::{DEFAULT_DATABASE, ServerConfig, State};

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueHint};
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

    /// Run the server with configuration from a file (default)
    Run(Run),
}

impl Default for Args {
    fn default() -> Self {
        Args::Run(Run::default())
    }
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
    /// Reset the admin password
    ResetAdminPassword,
}

/// Get a file path and parse as configuration
#[derive(Parser, Debug, Default)]
struct Run {
    /// Database file path
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    database: Option<PathBuf>,

    /// Config file path
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    config: Option<PathBuf>,
}

async fn common_main(args: Args) -> Result<State> {
    let run = match args {
        Args::Admin(admin) => {
            // The IP, ports, and mdns options don't matter as we won't start the server.
            let state = State::load(IpAddr::V4(Ipv4Addr::LOCALHOST), 9998, false, &admin.config)?;
            match &admin.action {
                AdminActions::ResetAdminPassword => {
                    let password = Password::new()
                        .with_prompt("New Password")
                        .with_confirmation("Confirm password", "Passwords mismatch")
                        .interact()?;
                    state.reset_admin_password(&password).await?;
                }
            }
            std::process::exit(0);
        }
        Args::Run(run) => run,
    };

    let (state, share) = if let Some(config_file) = &run.config
        && let Some(database_path) = run.database
    {
        let config = ServerConfig::load(config_file)?;
        (
            State::load(config.ip, config.port, config.mdns, database_path)?,
            config.share,
        )
    } else if run.config.is_none() && run.database.is_none() {
        let mut config_file =
            default_config_directory().expect("Unable to determine default config directory");
        let mut database_file = config_file.clone();
        config_file.push("server.toml");
        database_file.push("server.db");
        let config = ServerConfig::load_or_save(config_file)?;
        let state = if database_file.exists() {
            State::load(config.ip, config.port, config.mdns, database_file)?
        } else {
            let (state, mut password) = State::new(
                "Conclave".into(),
                "Conclave server".into(),
                config.ip,
                config.domain,
                config.port,
                config.mdns,
                database_file,
            )?;
            println!(
                "Admin password: {}\nTake note, as this will not appear again.",
                password.as_str()
            );
            password.zeroize();
            state
        };
        (state, config.share)
    } else {
        anyhow::bail!("config and database must both be provided or both not provided");
    };

    Ok(state.with_share_directory(share))
}

#[cfg(not(feature = "gui"))]
#[tokio::main]
async fn main() -> Result<std::process::ExitCode> {
    conclave_common::init_tracing();
    let args = if std::env::args().collect::<Vec<String>>().len() > 1 {
        Args::parse()
    } else {
        Args::default()
    };
    let state = common_main(args).await?;
    state.serve().await?;
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(feature = "gui")]
fn main() -> eframe::Result {
    conclave_server::init_gui_tracing();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    let args = if std::env::args().collect::<Vec<String>>().len() > 1 {
        Args::parse()
    } else {
        Args::default()
    };

    let state = rt
        .block_on(common_main(args))
        .expect("Failed to load server state from provided arguments or database file.");

    let state_copy = state.clone();
    rt.spawn(async move {
        if let Err(e) = state_copy.serve().await {
            eprintln!("Server error: {e}");
        }
    });

    #[cfg(debug_assertions)]
    {
        let wgpu = wgpu::Instance::enabled_backend_features();
        eprintln!("WGPU Features: {wgpu:?}");
    }

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
