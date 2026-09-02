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

use conclave_server::{ServerConfig, State, default_config_paths};

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
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = default_config_paths().1.into_os_string())]
    db: PathBuf,

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
#[derive(Parser, Debug)]
struct Run {
    /// Database file path
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = default_config_paths().1.into_os_string())]
    database: PathBuf,

    /// Config file path
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = default_config_paths().0.into_os_string())]
    config: PathBuf,

    #[arg(long, hide = true, default_value_t = false, action)]
    gen_config: bool,
}

impl Default for Run {
    fn default() -> Self {
        let (config, database) = default_config_paths();
        Self {
            database,
            config,
            gen_config: false,
        }
    }
}

async fn common_main(args: Args) -> Result<State> {
    let run = match args {
        Args::Admin(admin) => {
            // The IP, ports, and mdns options don't matter as we won't start the server.
            let state = State::load(IpAddr::V4(Ipv4Addr::LOCALHOST), 9998, false, &admin.db)?;
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

    let config = ServerConfig::load_or_save(&run.config)?;
    let state = if run.database.exists() {
        let s = State::load(config.ip, config.port, config.mdns, &run.database)?;
        if run.gen_config {
            std::process::exit(0);
        }
        s
    } else {
        let (state, mut password) = State::new(
            "Conclave".into(),
            "Conclave server".into(),
            config.ip,
            config.domain,
            config.port,
            config.mdns,
            &run.database,
        )?;
        println!(
            "Admin password: {}\nTake note, as this will not appear again.",
            password.as_str()
        );
        password.zeroize();
        if run.gen_config {
            std::process::exit(0);
        }
        state
    };

    Ok(state.with_share_directory(config.share))
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
