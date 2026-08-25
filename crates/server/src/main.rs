// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

use conclave_server::{DEFAULT_DATABASE, State};

use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueHint};
use conclave_common::SERVER_DEFAULT_PORT;
use dialoguer::Password;
use serde::Deserialize;
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

    /// Run the server with configuration on the command line
    Run(Run),

    /// Run the server with configuration from a file
    Load(Load),
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

#[derive(Parser, Debug, Deserialize)]
struct Run {
    /// IP Address to listen on
    #[arg(short, long, default_value = "127.0.0.1")]
    ip: IpAddr,

    /// Advertised domain
    #[arg(short, long)]
    #[serde(default)]
    domain: Option<String>,

    /// Port to listen on for connections
    #[arg(short, long, default_value_t = default_port())]
    #[serde(default = "default_port")]
    port: u16,

    /// Database file path
    #[arg(short, long, default_value = DEFAULT_DATABASE, value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// Advertise this server via Multicast DNS
    #[arg(short, long)]
    #[serde(default)]
    mdns: bool,

    /// Directory to share with clients (enables file sharing)
    #[arg(short, long, value_hint = ValueHint::DirPath)]
    #[serde(default)]
    share: Option<PathBuf>,
}

#[inline]
const fn default_port() -> u16 {
    SERVER_DEFAULT_PORT
}

/// Get a file path and parse as configuration
#[derive(Parser, Debug)]
struct Load {
    /// Path to a JSON or TOML config file.
    #[arg(value_hint = ValueHint::FilePath)]
    config: PathBuf,
}

impl From<Load> for Run {
    fn from(load: Load) -> Self {
        let Some(ext) = load.config.as_path().extension().and_then(OsStr::to_str) else {
            panic!("Config file does not have a file extension");
        };

        let content = std::fs::read_to_string(&load.config).expect("Failed to read file");
        match ext {
            "toml" => toml::from_str(&content).expect("Failed to parse TOML"),
            "json" => serde_json::from_str(&content).expect("Failed to parse JSON"),
            x => panic!("Unknown file extension: {x}"),
        }
    }
}

async fn common_main(args: Args) -> Result<State> {
    let run = match args {
        Args::Admin(admin) => {
            // These ports don't matter as we won't use them
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
        Args::Load(load) => load.into(),
    };

    let state = if run.config.exists() {
        State::load(run.ip, run.port, run.mdns, &run.config)?
    } else {
        let (state, mut password) = State::new(
            "Conclave".into(),
            "Conclave server".into(),
            run.ip,
            run.domain,
            run.port,
            run.mdns,
            run.config,
        )?;

        println!(
            "Admin password: {}\nThis will only appears this first time.",
            password.as_str()
        );
        password.zeroize();
        state
    };

    Ok(state.with_share_directory(run.share))
}

#[cfg(not(feature = "gui"))]
#[tokio::main]
async fn main() -> Result<std::process::ExitCode> {
    conclave_common::init_tracing();
    let state = common_main(Args::parse()).await?;
    state.serve().await?;
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(feature = "gui")]
fn main() -> eframe::Result {
    conclave_server::init_gui_tracing();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
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
