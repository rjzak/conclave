// SPDX-License-Identifier: Apache-2.0

use conclave_client::conn::ConclaveConnection;
use conclave_client::{Client, DiscoveredServer, discover_servers};
use conclave_common::server::{UserAuthentication, VerifyingKey};
use conclave_common::tracker::{Advertise, Tracker, TrackerWithKey};

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use eframe::{Frame, egui};
use sha2::{Digest, Sha256};
use tracing::error;

fn do_start_discovery(
    servers_arc: Arc<RwLock<HashSet<DiscoveredServer>>>,
    running_arc: Arc<AtomicBool>,
    error_arc: Arc<RwLock<Option<String>>>,
) {
    if running_arc.load(Ordering::SeqCst) {
        return;
    }

    running_arc.store(true, Ordering::SeqCst);
    if let Ok(mut servers) = servers_arc.write() {
        servers.clear();
    }
    if let Ok(mut err) = error_arc.write() {
        *err = None;
    }

    std::thread::spawn(move || {
        match discover_servers() {
            Ok(found) => {
                if let Ok(mut servers) = servers_arc.write() {
                    servers.extend(found);
                } else {
                    error!("Failed to write mDNS discovered servers");
                }
            }
            Err(e) => {
                if let Ok(mut err) = error_arc.write() {
                    err.replace(e.to_string());
                } else {
                    error!("Failed to write mDNS error state");
                }
            }
        }
        running_arc.store(false, Ordering::SeqCst);
    });
}

fn format_uptime(d: chrono::Duration) -> String {
    let d = if d.num_seconds() < 0 {
        chrono::Duration::zero()
    } else {
        d
    };
    let hours = d.num_hours();
    let mins = d.num_minutes() % 60;
    let secs = d.num_seconds() % 60;
    if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

/// Parse host and port from a `"conclave://host:port"` URL.
fn parse_server_url(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("conclave://")?;
    let colon = rest.rfind(':')?;
    let host = rest[..colon].to_string();
    let port = rest[colon + 1..].parse().ok()?;
    Some((host, port))
}

/// Connect to a server in the background. On success the connection is registered
/// in `active_connections`; roster and server-info updates then arrive as pushes
/// from the server rather than by polling. When `clear_on_success` is provided,
/// that pending-server slot is cleared once the connection succeeds (used to
/// dismiss the login window).
#[allow(clippy::too_many_arguments)]
fn spawn_connect(
    client: Arc<Client>,
    active_connections: Arc<RwLock<Vec<ConclaveConnection>>>,
    connect_pending: Arc<AtomicBool>,
    connect_error: Arc<RwLock<Option<String>>>,
    clear_on_success: Option<Arc<RwLock<Option<PendingServer>>>>,
    host: String,
    port: u16,
    share_time: bool,
    display_name: String,
    auth: Option<UserAuthentication>,
    key: Option<VerifyingKey>,
) {
    connect_pending.store(true, Ordering::SeqCst);
    if let Ok(mut e) = connect_error.write() {
        *e = None;
    }

    tokio::spawn(async move {
        match client
            .connect(&host, port, share_time, display_name, auth, key)
            .await
        {
            Ok(conn) => {
                // The server pushes roster and server-info updates as they happen
                // (on connect/disconnect and on admin edits), so the client does
                // not poll for them.
                if let Ok(mut conns) = active_connections.write() {
                    conns.push(conn);
                }
                if let Some(p) = clear_on_success
                    && let Ok(mut g) = p.write()
                {
                    *g = None;
                }
            }
            Err(e) => {
                if let Ok(mut err) = connect_error.write() {
                    *err = Some(e.to_string());
                }
            }
        }
        connect_pending.store(false, Ordering::SeqCst);
    });
}

/// A server chosen by the user, awaiting login credentials.
#[derive(Clone, Debug)]
struct PendingServer {
    host: String,
    port: u16,
    /// Known key from discovery/tracker; `None` means the client will fetch it during connect.
    key: Option<VerifyingKey>,
    name: String,
    anonymous_allowed: bool,
}

/// GUI client state
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConclaveGUI {
    /// Conclave client
    client: Arc<Client>,

    /// Showing the window displaying local Conclave servers
    show_advertised_servers_list: bool,

    /// Showing the window displaying known Conclave trackers
    show_tracker_list: bool,

    /// Showing the window displaying servers advertised via trackers
    show_tracker_servers: bool,

    /// Discovered local Conclave servers
    discovered_servers: Arc<RwLock<HashSet<DiscoveredServer>>>,

    /// Whether we're searching for local Conclave servers via mDNS
    discovery_running: Arc<AtomicBool>,

    /// Any errors encountered during discovery
    discovery_error: Arc<RwLock<Option<String>>>,

    /// Local server discovery window closed
    discovery_viewport_closed: Arc<AtomicBool>,

    /// Tracker window closed
    tracker_viewport_closed: Arc<AtomicBool>,

    /// Any errors encountered trying to add a tracker
    tracker_error: Arc<RwLock<Option<String>>>,

    /// Tracker addition pending
    tracker_op_pending: Arc<AtomicBool>,

    /// Tracker fetched from network, awaiting user confirmation before adding
    pending_tracker_info: Arc<RwLock<Option<TrackerWithKey>>>,

    /// Tracker servers window closed
    tracker_servers_viewport_closed: Arc<AtomicBool>,

    /// Servers discovered via trackers
    tracker_servers: Arc<RwLock<Vec<Advertise>>>,

    /// Stop handle for the live tracker-server subscription; `Some` while the
    /// tracker-servers window is open. Dropping it stops the subscription.
    tracker_servers_watch: Option<tokio::sync::watch::Sender<bool>>,

    /// Server chosen by the user, pending authentication
    pending_server: Arc<RwLock<Option<PendingServer>>>,

    /// Async connect operation is in-flight
    connect_pending: Arc<AtomicBool>,

    /// Error from the most recent connect attempt
    connect_error: Arc<RwLock<Option<String>>>,

    /// Currently active server connections
    active_connections: Arc<RwLock<Vec<ConclaveConnection>>>,

    /// Default display name from config, seeds the login form
    default_display_name: String,

    /// Show the direct-connect host/port form in the central panel
    show_direct_connect: bool,

    /// Login window close flag (set when the user closes the login window)
    login_window_closed: Arc<AtomicBool>,

    /// Show the "Connected Servers" window
    show_servers_window: bool,

    /// Connected Servers window close flag
    servers_window_closed: Arc<AtomicBool>,

    /// Server keys (`host:port` hash) whose user-list window is open
    open_user_windows: Arc<RwLock<HashSet<String>>>,

    /// Servers already auto-opened once, so a manual close is not undone
    seen_servers: HashSet<String>,

    /// User-window close requests (server keys) emitted by viewport closures
    user_window_close_requests: Arc<RwLock<Vec<String>>>,

    /// Server keys whose administration window is open (admin connections only)
    open_admin_windows: Arc<RwLock<HashSet<String>>>,

    /// Admin-window close requests (server keys) emitted by viewport closures
    admin_window_close_requests: Arc<RwLock<Vec<String>>>,
}

impl ConclaveGUI {
    pub fn new(client: Client, _cc: &eframe::CreationContext<'_>) -> Self {
        let default_display_name = client.default_display_name();
        Self {
            client: Arc::new(client),
            show_advertised_servers_list: false,
            show_tracker_list: false,
            show_tracker_servers: false,
            discovered_servers: Arc::new(RwLock::new(HashSet::new())),
            discovery_running: Arc::new(AtomicBool::new(false)),
            discovery_error: Arc::new(RwLock::new(None)),
            discovery_viewport_closed: Arc::new(AtomicBool::new(false)),
            tracker_viewport_closed: Arc::new(AtomicBool::new(false)),
            tracker_error: Arc::new(RwLock::new(None)),
            tracker_op_pending: Arc::new(AtomicBool::new(false)),
            pending_tracker_info: Arc::new(RwLock::new(None)),
            tracker_servers_viewport_closed: Arc::new(AtomicBool::new(false)),
            tracker_servers: Arc::new(RwLock::new(Vec::new())),
            tracker_servers_watch: None,
            pending_server: Arc::new(RwLock::new(None)),
            connect_pending: Arc::new(AtomicBool::new(false)),
            connect_error: Arc::new(RwLock::new(None)),
            active_connections: Arc::new(RwLock::new(Vec::new())),
            default_display_name,
            show_direct_connect: false,
            login_window_closed: Arc::new(AtomicBool::new(false)),
            show_servers_window: false,
            servers_window_closed: Arc::new(AtomicBool::new(false)),
            open_user_windows: Arc::new(RwLock::new(HashSet::new())),
            open_admin_windows: Arc::new(RwLock::new(HashSet::new())),
            admin_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            seen_servers: HashSet::new(),
            user_window_close_requests: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl eframe::App for ConclaveGUI {
    #[allow(clippy::too_many_lines)]
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut Frame) {
        // ── Handle viewport close events ──────────────────────────────────
        if self.discovery_viewport_closed.swap(false, Ordering::SeqCst) {
            self.show_advertised_servers_list = false;
        }
        if self.tracker_viewport_closed.swap(false, Ordering::SeqCst) {
            self.show_tracker_list = false;
        }
        if self
            .tracker_servers_viewport_closed
            .swap(false, Ordering::SeqCst)
        {
            self.show_tracker_servers = false;
        }

        // Keep the live tracker-server subscription running exactly while the
        // window is open: start it on open, stop it (drop the handle) on close.
        if self.show_tracker_servers {
            if self.tracker_servers_watch.is_none() {
                if let Ok(mut servers) = self.tracker_servers.write() {
                    servers.clear();
                }
                self.tracker_servers_watch = Some(
                    self.client
                        .watch_servers_from_trackers(&self.tracker_servers),
                );
            }
        } else if self.tracker_servers_watch.take().is_some()
            && let Ok(mut servers) = self.tracker_servers.write()
        {
            servers.clear();
        }
        if self.login_window_closed.swap(false, Ordering::SeqCst) {
            if let Ok(mut p) = self.pending_server.write() {
                *p = None;
            }
            if let Ok(mut e) = self.connect_error.write() {
                *e = None;
            }
        }
        if self.servers_window_closed.swap(false, Ordering::SeqCst) {
            self.show_servers_window = false;
        }
        // Drain close requests from per-server user windows.
        let close_keys: Vec<String> = self
            .user_window_close_requests
            .write()
            .map(|mut r| r.drain(..).collect())
            .unwrap_or_default();
        if !close_keys.is_empty()
            && let Ok(mut open) = self.open_user_windows.write()
        {
            for k in close_keys {
                open.remove(&k);
            }
        }
        // Drain close requests from per-server admin windows.
        let admin_close_keys: Vec<String> = self
            .admin_window_close_requests
            .write()
            .map(|mut r| r.drain(..).collect())
            .unwrap_or_default();
        if !admin_close_keys.is_empty()
            && let Ok(mut open) = self.open_admin_windows.write()
        {
            for k in admin_close_keys {
                open.remove(&k);
            }
        }

        // ── Request repaint while async operations run ────────────────────
        if self.discovery_running.load(Ordering::SeqCst)
            || self.connect_pending.load(Ordering::SeqCst)
            || self.tracker_op_pending.load(Ordering::SeqCst)
        {
            ui.ctx().request_repaint();
        }

        // ── Top-bar menu ──────────────────────────────────────────────────
        egui::Panel::top("top_panel").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Quit").clicked() {
                        ui.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.checkbox(
                        &mut self.show_advertised_servers_list,
                        "Local Server Discovery",
                    );
                    ui.checkbox(&mut self.show_tracker_list, "Trackers");
                    ui.checkbox(&mut self.show_tracker_servers, "Servers Listing");
                    ui.checkbox(&mut self.show_servers_window, "Connected Servers");
                });
                ui.add_space(16.0);
                egui::widgets::global_theme_preference_buttons(ui);
            });
        });

        // ── Server Discovery viewport ─────────────────────────────────────
        if self.show_advertised_servers_list {
            let closed_arc = self.discovery_viewport_closed.clone();
            let running_arc = self.discovery_running.clone();
            let servers_arc = self.discovered_servers.clone();
            let error_arc = self.discovery_error.clone();
            let pending_server_arc = self.pending_server.clone();
            let connect_error_arc = self.connect_error.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("local_server_discovery"),
                egui::ViewportBuilder::default()
                    .with_title("Local Server Discovery")
                    .with_inner_size([480.0, 340.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed_arc.store(true, Ordering::SeqCst);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if running_arc.load(Ordering::SeqCst) {
                        ctx.request_repaint();
                    }

                    let is_running = running_arc.load(Ordering::SeqCst);
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.heading("Local Servers");
                            ui.add_space(8.0);
                            if is_running {
                                ui.add(egui::Spinner::new());
                            } else if ui.button("Refresh").clicked() {
                                do_start_discovery(
                                    servers_arc.clone(),
                                    running_arc.clone(),
                                    error_arc.clone(),
                                );
                            }
                        });
                        ui.separator();
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            let Ok(servers) = servers_arc.read() else {
                                error!("Failed to read mDNS discovered servers");
                                return;
                            };
                            let Ok(error) = error_arc.read() else {
                                error!("Failed to read mDNS error state");
                                return;
                            };
                            if is_running {
                                ui.label("Searching for local Conclave servers...");
                            } else if let Some(err) = error.as_ref() {
                                ui.colored_label(
                                    egui::Color32::RED,
                                    format!("Discovery failed: {err}"),
                                );
                            } else if servers.is_empty() {
                                ui.label("No local Conclave servers found.");
                            } else {
                                for server in servers.iter() {
                                    ui.group(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(&server.name).strong());
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if ui.button("Connect").clicked() {
                                                        if let Ok(mut p) =
                                                            pending_server_arc.write()
                                                        {
                                                            *p = Some(PendingServer {
                                                                host: server.host.clone(),
                                                                port: server.port,
                                                                key: Some(server.key),
                                                                name: server.name.clone(),
                                                                anonymous_allowed: server
                                                                    .anonymous_allowed,
                                                            });
                                                        }
                                                        if let Ok(mut e) = connect_error_arc.write()
                                                        {
                                                            *e = None;
                                                        }
                                                    }
                                                    ui.label(
                                                        egui::RichText::new(format!(
                                                            "v{}",
                                                            server.version
                                                        ))
                                                        .weak(),
                                                    );
                                                },
                                            );
                                        });
                                        if !server.description.is_empty() {
                                            ui.label(&server.description);
                                        }
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}:{}",
                                                server.host, server.port
                                            ))
                                            .monospace(),
                                        );
                                    });
                                }
                            }
                        });
                    });
                },
            );
        }

        // ── Tracker List viewport ─────────────────────────────────────────
        if self.show_tracker_list {
            let closed_arc = self.tracker_viewport_closed.clone();
            let error_arc = self.tracker_error.clone();
            let op_pending_arc = self.tracker_op_pending.clone();
            let client_arc = self.client.clone();
            let pending_info_arc = self.pending_tracker_info.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("tracker_list"),
                egui::ViewportBuilder::default()
                    .with_title("Trackers")
                    .with_inner_size([450.0, 320.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed_arc.store(true, Ordering::SeqCst);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if op_pending_arc.load(Ordering::SeqCst) {
                        ctx.request_repaint();
                    }

                    let is_pending = op_pending_arc.load(Ordering::SeqCst);
                    let trackers = client_arc.list_trackers();

                    let form_host_id = egui::Id::new("tracker_form_host");
                    let form_port_id = egui::Id::new("tracker_form_port");
                    let mut form_host =
                        ctx.data(|d| d.get_temp::<String>(form_host_id).unwrap_or_default());
                    let mut form_port =
                        ctx.data(|d| d.get_temp::<String>(form_port_id).unwrap_or_default());

                    let mut remove_request: Option<(String, u16)> = None;
                    let mut add_request = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        if is_pending {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new());
                                ui.label("Operation in progress...");
                            });
                        } else {
                            let Ok(error_msg) = error_arc.read() else {
                                error!("Failed to read tracker list error state");
                                return;
                            };
                            if let Some(err) = error_msg.clone() {
                                ui.colored_label(egui::Color32::RED, err);
                            }
                        }

                        ui.separator();

                        egui::ScrollArea::vertical()
                            .max_height(160.0)
                            .show(ui, |ui| {
                                if trackers.is_empty() {
                                    ui.label("No trackers configured.");
                                } else {
                                    for tracker in &trackers {
                                        ui.group(|ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    egui::RichText::new(format!(
                                                        "{}:{}",
                                                        tracker.host, tracker.port
                                                    ))
                                                    .monospace(),
                                                );
                                                ui.with_layout(
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        if !is_pending
                                                            && ui.button("Remove").clicked()
                                                        {
                                                            remove_request = Some((
                                                                tracker.host.clone(),
                                                                tracker.port,
                                                            ));
                                                        }
                                                    },
                                                );
                                            });
                                        });
                                    }
                                }
                            });

                        ui.separator();
                        ui.label(egui::RichText::new("Add Tracker").strong());
                        ui.horizontal(|ui| {
                            ui.label("Host:");
                            ui.text_edit_singleline(&mut form_host);
                            ui.label("Port:");
                            ui.add(egui::TextEdit::singleline(&mut form_port).desired_width(60.0));
                        });
                        let has_pending_info =
                            pending_info_arc.read().ok().is_some_and(|g| g.is_some());
                        let can_add = !is_pending
                            && !has_pending_info
                            && !form_host.is_empty()
                            && form_port.parse::<u16>().is_ok();
                        ui.add_space(4.0);
                        if ui.add_enabled(can_add, egui::Button::new("Add")).clicked() {
                            add_request = true;
                        }
                    });

                    // Confirmation dialog
                    let maybe_tracker = pending_info_arc.read().ok().and_then(|g| g.clone());
                    if let Some(ref tracker) = maybe_tracker {
                        use base64::Engine as _;
                        use pqcrypto_traits::sign::PublicKey as _;
                        let key_b64 = base64::engine::general_purpose::STANDARD
                            .encode(tracker.key.as_bytes());
                        let key_sha256 = hex::encode(Sha256::digest(tracker.key.as_bytes()));

                        let mut confirmed = false;
                        let mut cancelled = false;

                        egui::Window::new("Confirm Tracker")
                            .collapsible(false)
                            .resizable(true)
                            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                            .show(ctx, |ui| {
                                ui.label(format!("Add tracker {}:{}?", tracker.host, tracker.port));
                                ui.separator();
                                ui.label(egui::RichText::new("Public Key (SHA256):").strong());
                                ui.label(key_sha256);
                                ui.label(egui::RichText::new("Public Key (base64):").strong());
                                egui::ScrollArea::vertical()
                                    .id_salt("tracker_key_scroll")
                                    .max_height(120.0)
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&key_b64)
                                                    .monospace()
                                                    .size(10.0),
                                            )
                                            .wrap(),
                                        );
                                    });
                                ui.separator();
                                ui.horizontal(|ui| {
                                    if ui.button("Add").clicked() {
                                        confirmed = true;
                                    }
                                    if ui.button("Cancel").clicked() {
                                        cancelled = true;
                                    }
                                });
                            });

                        if confirmed {
                            if let Some(tracker) = maybe_tracker {
                                let client = client_arc.clone();
                                let err_arc = error_arc.clone();
                                let pending = op_pending_arc.clone();
                                let info_arc = pending_info_arc.clone();
                                pending.store(true, Ordering::SeqCst);
                                tokio::spawn(async move {
                                    if let Err(e) = client.add_tracker_with_key(tracker).await
                                        && let Ok(mut err) = err_arc.write()
                                    {
                                        *err = Some(e.to_string());
                                    }
                                    if let Ok(mut info) = info_arc.write() {
                                        *info = None;
                                    }
                                    pending.store(false, Ordering::SeqCst);
                                });
                            }
                        } else if cancelled && let Ok(mut info) = pending_info_arc.write() {
                            *info = None;
                        }
                    }

                    if let Some((name, port)) = remove_request {
                        let client = client_arc.clone();
                        let err_arc = error_arc.clone();
                        let pending = op_pending_arc.clone();
                        pending.store(true, Ordering::SeqCst);
                        tokio::spawn(async move {
                            if let Err(e) = client.remove_tracker(&name, port).await
                                && let Ok(mut err) = err_arc.write()
                            {
                                *err = Some(e.to_string());
                            }
                            pending.store(false, Ordering::SeqCst);
                        });
                    }

                    if add_request {
                        let err_arc = error_arc.clone();
                        let pending = op_pending_arc.clone();
                        let info_arc = pending_info_arc.clone();
                        pending.store(true, Ordering::SeqCst);
                        if let Ok(mut err) = err_arc.write() {
                            *err = None;
                        }

                        let name = std::mem::take(&mut form_host);
                        let port_str = std::mem::take(&mut form_port);
                        let Ok(port) = port_str.parse::<u16>() else {
                            error!("Invalid port: {port_str}");
                            if let Ok(mut err) = err_arc.write() {
                                *err = Some(format!("Invalid port: {port_str}"));
                            }
                            pending.store(false, Ordering::SeqCst);
                            ctx.data_mut(|d| {
                                d.insert_temp(form_host_id, name);
                                d.insert_temp(form_port_id, port_str);
                            });
                            return;
                        };

                        tokio::spawn(async move {
                            let tracker = Tracker { host: name, port };
                            match tracker.as_with_key().await {
                                Ok(tracker) => {
                                    if let Ok(mut info) = info_arc.write() {
                                        *info = Some(tracker);
                                    }
                                }
                                Err(e) => {
                                    if let Ok(mut err) = err_arc.write() {
                                        *err = Some(format!("Failed to get tracker key: {e}"));
                                    }
                                }
                            }
                            pending.store(false, Ordering::SeqCst);
                        });
                    }

                    ctx.data_mut(|d| {
                        d.insert_temp(form_host_id, form_host);
                        d.insert_temp(form_port_id, form_port);
                    });
                },
            );
        }

        // ── Tracker Servers viewport ──────────────────────────────────────
        if self.show_tracker_servers {
            let closed_arc = self.tracker_servers_viewport_closed.clone();
            let servers_arc = self.tracker_servers.clone();
            let pending_server_arc = self.pending_server.clone();
            let connect_error_arc = self.connect_error.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("tracker_servers"),
                egui::ViewportBuilder::default()
                    .with_title("Tracker Servers")
                    .with_inner_size([780.0, 400.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed_arc.store(true, Ordering::SeqCst);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    // The listing is pushed by the trackers; repaint periodically
                    // so those updates show up promptly.
                    ctx.request_repaint_after(std::time::Duration::from_millis(500));

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.heading("Servers via Trackers");
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new("live")
                                    .small()
                                    .color(egui::Color32::from_rgb(0x4c, 0xaf, 0x50)),
                            );
                        });
                        ui.separator();

                        let Ok(servers) = servers_arc.read() else {
                            error!("Failed to read tracker servers");
                            return;
                        };

                        if servers.is_empty() {
                            ui.label(
                                "No servers found. Make sure trackers are configured and reachable.",
                            );
                        } else {
                            egui::ScrollArea::both().show(ui, |ui| {
                                egui::Grid::new("tracker_servers_grid")
                                    .striped(true)
                                    .spacing([12.0, 4.0])
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new("Name").strong());
                                        ui.label(egui::RichText::new("Version").strong());
                                        ui.label(egui::RichText::new("Address").strong());
                                        ui.label(egui::RichText::new("Users").strong());
                                        ui.label(egui::RichText::new("Guests").strong());
                                        ui.label(egui::RichText::new("Uptime").strong());
                                        ui.label(egui::RichText::new("Description").strong());
                                        ui.label(egui::RichText::new("").strong());
                                        ui.end_row();

                                        for server in servers.iter() {
                                            ui.label(
                                                egui::RichText::new(&server.name).strong(),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "v{}",
                                                    server.version
                                                ))
                                                .monospace(),
                                            );
                                            ui.label(
                                                egui::RichText::new(&server.url).monospace(),
                                            );
                                            ui.label(server.users_connected.to_string());
                                            ui.label(if server.anonymous {
                                                "Yes"
                                            } else {
                                                "No"
                                            });
                                            ui.label(format_uptime(server.uptime));
                                            ui.label(&server.description);
                                            if let Some((host, port)) =
                                                parse_server_url(&server.url)
                                            {
                                                if ui.button("Connect").clicked() {
                                                    if let Ok(mut p) =
                                                        pending_server_arc.write()
                                                    {
                                                        *p = Some(PendingServer {
                                                            host,
                                                            port,
                                                            key: Some(server.key),
                                                            name: server.name.clone(),
                                                            anonymous_allowed: server.anonymous,
                                                        });
                                                    }
                                                    if let Ok(mut e) =
                                                        connect_error_arc.write()
                                                    {
                                                        *e = None;
                                                    }
                                                }
                                            } else {
                                                ui.label("—");
                                            }
                                            ui.end_row();
                                        }
                                    });
                            });
                        }
                    });
                },
            );
        }

        // ── Login window ──────────────────────────────────────────────────
        let pending_info: Option<PendingServer> =
            self.pending_server.read().ok().and_then(|p| p.clone());

        if let Some(server) = pending_info {
            let closed_arc = self.login_window_closed.clone();
            let pending_arc = self.pending_server.clone();
            let connect_pending = self.connect_pending.clone();
            let connect_error = self.connect_error.clone();
            let active_conns = self.active_connections.clone();
            let client = self.client.clone();
            let default_name = self.default_display_name.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("login_window"),
                egui::ViewportBuilder::default()
                    .with_title(format!("Connect to {}", server.name))
                    .with_inner_size([360.0, 250.0])
                    .with_resizable(false),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed_arc.store(true, Ordering::SeqCst);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if connect_pending.load(Ordering::SeqCst) {
                        ctx.request_repaint();
                    }

                    let login_name_id = egui::Id::new("login_display_name");
                    let login_user_id = egui::Id::new("login_username");
                    let login_pass_id = egui::Id::new("login_password");
                    let login_share_id = egui::Id::new("login_share_time");

                    let mut display_name: String = ctx.data(|d| {
                        d.get_temp(login_name_id)
                            .unwrap_or_else(|| default_name.clone())
                    });
                    let mut username: String =
                        ctx.data(|d| d.get_temp(login_user_id).unwrap_or_default());
                    let mut password: String =
                        ctx.data(|d| d.get_temp(login_pass_id).unwrap_or_default());
                    let mut share_time: bool =
                        ctx.data(|d| d.get_temp(login_share_id).unwrap_or(false));

                    let is_pending = connect_pending.load(Ordering::SeqCst);
                    let conn_error: Option<String> =
                        connect_error.read().ok().and_then(|e| e.clone());

                    let mut connect_clicked = false;
                    let mut cancel_clicked = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.label(format!(
                            "{}  ({}:{})",
                            server.name, server.host, server.port
                        ));
                        ui.separator();

                        if is_pending {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new());
                                ui.label("Connecting…");
                            });
                            return;
                        }

                        if let Some(ref err) = conn_error {
                            ui.colored_label(egui::Color32::RED, err);
                            ui.separator();
                        }

                        // Servers that don't allow guests require credentials.
                        let credentials_required = !server.anonymous_allowed;
                        if credentials_required {
                            ui.label(
                                egui::RichText::new(
                                    "This server does not allow anonymous users — a username and \
                                     password are required.",
                                )
                                .small()
                                .color(egui::Color32::from_rgb(0xff, 0xa5, 0x00)),
                            );
                            ui.add_space(4.0);
                        }

                        egui::Grid::new("login_form_grid")
                            .num_columns(2)
                            .spacing([8.0, 6.0])
                            .show(ui, |ui| {
                                ui.label("Display name:");
                                ui.text_edit_singleline(&mut display_name);
                                ui.end_row();

                                ui.label("Share local time:");
                                ui.checkbox(&mut share_time, "");
                                ui.end_row();

                                ui.label("Username:");
                                ui.text_edit_singleline(&mut username);
                                ui.end_row();

                                ui.label("Password:");
                                ui.add(egui::TextEdit::singleline(&mut password).password(true));
                                ui.end_row();
                            });

                        ui.add_space(8.0);

                        // A display name is always needed; guests-disallowed
                        // servers additionally require a username and password.
                        let has_credentials = !username.is_empty() && !password.is_empty();
                        let can_connect =
                            !display_name.is_empty() && (!credentials_required || has_credentials);

                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(can_connect, egui::Button::new("Connect"))
                                .clicked()
                            {
                                connect_clicked = true;
                            }
                            if ui.button("Cancel").clicked() {
                                cancel_clicked = true;
                            }
                        });
                    });

                    ctx.data_mut(|d| {
                        d.insert_temp(login_name_id, display_name.clone());
                        d.insert_temp(login_user_id, username.clone());
                        d.insert_temp(login_pass_id, password.clone());
                        d.insert_temp(login_share_id, share_time);
                    });

                    if cancel_clicked {
                        if let Ok(mut p) = pending_arc.write() {
                            *p = None;
                        }
                        if let Ok(mut e) = connect_error.write() {
                            *e = None;
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    } else if connect_clicked {
                        let auth = (!username.is_empty()).then_some(UserAuthentication {
                            username: username.clone(),
                            password: password.clone(),
                        });
                        spawn_connect(
                            client.clone(),
                            active_conns.clone(),
                            connect_pending.clone(),
                            connect_error.clone(),
                            Some(pending_arc.clone()),
                            server.host.clone(),
                            server.port,
                            share_time,
                            display_name,
                            auth,
                            server.key,
                        );
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }
                },
            );
        }

        // ── Snapshot active connections ───────────────────────────────────
        // (stable key = hash of the server's public key, display name,
        //  still-connected flag, and a clone of the connection).
        // Clone the handles out from under the std RwLock first so the guard is
        // released before building the snapshot. server_info()/connected_users()
        // are synchronous reads, so no async runtime is touched on this thread.
        let conns: Vec<ConclaveConnection> = self
            .active_connections
            .read()
            .map(|c| c.clone())
            .unwrap_or_default();

        let conn_snapshots: Vec<(String, String, bool, ConclaveConnection)> = conns
            .into_iter()
            .map(|conn| {
                let info = conn.server_info();
                let active = conn.connected_since().is_some();
                (hex::encode(info.key.as_bytes()), info.name, active, conn)
            })
            .collect();

        let has_connections = !conn_snapshots.is_empty();

        // Auto-open a user window once per newly-seen server and surface the
        // Connected Servers window when the first connection appears.
        for (key, _, _, _) in &conn_snapshots {
            if self.seen_servers.insert(key.clone()) {
                if let Ok(mut open) = self.open_user_windows.write() {
                    open.insert(key.clone());
                }
                self.show_servers_window = true;
            }
        }

        // Forget servers that are no longer connected so their windows close and
        // a later reconnect re-opens them.
        {
            let live: HashSet<String> = conn_snapshots.iter().map(|(k, ..)| k.clone()).collect();
            self.seen_servers.retain(|k| live.contains(k));
            if let Ok(mut open) = self.open_user_windows.write() {
                open.retain(|k| live.contains(k));
            }
            if let Ok(mut open) = self.open_admin_windows.write() {
                open.retain(|k| live.contains(k));
            }
        }

        // ── Connected Servers window ──────────────────────────────────────
        if self.show_servers_window {
            let closed_arc = self.servers_window_closed.clone();
            let active_conns = self.active_connections.clone();
            let open_windows = self.open_user_windows.clone();
            let open_admin = self.open_admin_windows.clone();
            // (key, name, active, is_admin)
            let servers: Vec<(String, String, bool, bool)> = conn_snapshots
                .iter()
                .map(|(k, n, a, c)| (k.clone(), n.clone(), *a, c.is_admin()))
                .collect();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("connected_servers"),
                egui::ViewportBuilder::default()
                    .with_title("Connected Servers")
                    .with_inner_size([300.0, 360.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed_arc.store(true, Ordering::SeqCst);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    let mut disconnect_key: Option<String> = None;
                    let mut repaint_root = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.heading("Servers");
                        ui.separator();

                        if servers.is_empty() {
                            ui.label(egui::RichText::new("Not connected to any server.").weak());
                        }

                        for (key, name, active, is_admin) in &servers {
                            ui.group(|ui| {
                                let label = if *active {
                                    name.clone()
                                } else {
                                    format!("{name} (disconnected)")
                                };
                                ui.label(egui::RichText::new(label).strong());
                                ui.horizontal(|ui| {
                                    let mut shown =
                                        open_windows.read().is_ok_and(|o| o.contains(key));
                                    if ui.checkbox(&mut shown, "Users").changed() {
                                        if let Ok(mut o) = open_windows.write() {
                                            if shown {
                                                o.insert(key.clone());
                                            } else {
                                                o.remove(key);
                                            }
                                        }
                                        repaint_root = true;
                                    }
                                    // The admin panel is offered only for connections
                                    // whose authenticated user holds admin rights.
                                    if *is_admin {
                                        let mut admin_shown =
                                            open_admin.read().is_ok_and(|o| o.contains(key));
                                        if ui.checkbox(&mut admin_shown, "Admin").changed() {
                                            if let Ok(mut o) = open_admin.write() {
                                                if admin_shown {
                                                    o.insert(key.clone());
                                                } else {
                                                    o.remove(key);
                                                }
                                            }
                                            repaint_root = true;
                                        }
                                    }
                                    if ui.small_button("Disconnect").clicked() {
                                        disconnect_key = Some(key.clone());
                                    }
                                });
                            });
                        }
                    });

                    if repaint_root {
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }

                    if let Some(key) = disconnect_key {
                        // server_info() is a synchronous (std-lock) read, so it is safe
                        // to match on it while briefly holding the connections write lock.
                        let removed = active_conns.write().ok().and_then(|mut c| {
                            let idx = c
                                .iter()
                                .position(|conn| hex::encode(conn.server_info().key) == key);
                            idx.map(|i| c.remove(i))
                        });
                        if let Some(conn) = removed {
                            if let Ok(mut o) = open_windows.write() {
                                o.remove(&key);
                            }
                            tokio::spawn(async move {
                                let _ = conn.disconnect().await;
                            });
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }
                },
            );
        }

        // ── Per-server user windows ───────────────────────────────────────
        let open_keys: HashSet<String> = self
            .open_user_windows
            .read()
            .map(|o| o.clone())
            .unwrap_or_default();

        for (key, name, _active, conn) in &conn_snapshots {
            if !open_keys.contains(key) {
                continue;
            }
            let conn = conn.clone();
            let key_owned = key.clone();
            let title = format!("Users — {name}");
            let close_reqs = self.user_window_close_requests.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("server_users:{key}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([420.0, 360.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push(key_owned.clone());
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    let server_info = conn.server_info();
                    let users = conn.get_connected_users();

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.heading(format!("Users on {}", server_info.name));
                        ui.separator();

                        if users.is_empty() {
                            ui.label(egui::RichText::new("No users connected yet.").weak());
                        } else {
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                egui::Grid::new(format!("users_grid:{key_owned}"))
                                    .striped(true)
                                    .spacing([12.0, 4.0])
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new("Name").strong());
                                        ui.label(egui::RichText::new("Connected").strong());
                                        ui.end_row();

                                        for user in &users {
                                            // Administrators are shown with a red name.
                                            let mut name = egui::RichText::new(&user.display_name);
                                            if user.admin {
                                                name = name.color(egui::Color32::RED);
                                            }
                                            ui.label(name);
                                            ui.label(format_uptime(user.connected_since));
                                            ui.end_row();
                                        }
                                    });
                            });
                        }
                    });

                    // The server pushes roster changes automatically; repaint
                    // periodically so those updates are picked up promptly.
                    ctx.request_repaint_after(std::time::Duration::from_secs(2));
                },
            );
        }

        // ── Per-server admin windows (admin connections only) ─────────────
        let admin_open_keys: HashSet<String> = self
            .open_admin_windows
            .read()
            .map(|o| o.clone())
            .unwrap_or_default();

        for (key, name, _active, conn) in &conn_snapshots {
            if !admin_open_keys.contains(key) || !conn.is_admin() {
                continue;
            }
            let conn = conn.clone();
            let key_owned = key.clone();
            let title = format!("Admin — {name}");
            let close_reqs = self.admin_window_close_requests.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("server_admin:{key}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([540.0, 600.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push(key_owned.clone());
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    // Load the user/tracker lists once when the window first opens.
                    let loaded_id = egui::Id::new(format!("admin_loaded:{key_owned}"));
                    if !ctx.data(|d| d.get_temp::<bool>(loaded_id).unwrap_or(false)) {
                        ctx.data_mut(|d| d.insert_temp(loaded_id, true));
                        let c = conn.clone();
                        tokio::spawn(async move {
                            let _ = c.admin_list_users().await;
                            let _ = c.admin_list_groups().await;
                            let _ = c.admin_list_trackers().await;
                        });
                    }

                    let info = conn.server_info();
                    let users = conn.admin_users();
                    let groups = conn.admin_groups();
                    let trackers = conn.admin_trackers();
                    let admin_error = conn.admin_error();

                    // Form fields persisted in egui temp data, keyed per server.
                    let name_id = egui::Id::new(format!("admin_name:{key_owned}"));
                    let desc_id = egui::Id::new(format!("admin_desc:{key_owned}"));
                    let new_user_id = egui::Id::new(format!("admin_nu:{key_owned}"));
                    let new_pass_id = egui::Id::new(format!("admin_np:{key_owned}"));
                    let new_groups_id = egui::Id::new(format!("admin_ng:{key_owned}"));
                    let tracker_host_id = egui::Id::new(format!("admin_th:{key_owned}"));
                    let tracker_port_id = egui::Id::new(format!("admin_tp:{key_owned}"));

                    let mut server_name: String =
                        ctx.data(|d| d.get_temp(name_id).unwrap_or_else(|| info.name.clone()));
                    let mut server_desc: String = ctx.data(|d| {
                        d.get_temp(desc_id)
                            .unwrap_or_else(|| info.description.clone())
                    });
                    let mut new_user: String =
                        ctx.data(|d| d.get_temp(new_user_id).unwrap_or_default());
                    let mut new_pass: String =
                        ctx.data(|d| d.get_temp(new_pass_id).unwrap_or_default());
                    let mut new_groups: HashSet<String> =
                        ctx.data(|d| d.get_temp(new_groups_id).unwrap_or_default());
                    let mut tracker_host: String =
                        ctx.data(|d| d.get_temp(tracker_host_id).unwrap_or_default());
                    let mut tracker_port: String = ctx.data(|d| {
                        d.get_temp(tracker_port_id)
                            .unwrap_or_else(|| "9100".to_string())
                    });

                    // Actions are flagged during rendering and performed afterwards.
                    let mut save_server = false;
                    let mut create_user = false;
                    let mut delete_user: Option<u32> = None;
                    // (uid, gid, add?) membership toggles queued this frame.
                    let mut group_changes: Vec<(u32, u32, bool)> = Vec::new();
                    let mut add_tracker = false;
                    let mut remove_tracker: Option<(String, u16)> = None;
                    let mut refresh = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.heading(format!("Administer {}", info.name));
                        if let Some(err) = &admin_error {
                            ui.colored_label(egui::Color32::RED, err);
                        }
                        ui.separator();

                        egui::CollapsingHeader::new("Server")
                            .default_open(true)
                            .show(ui, |ui| {
                                egui::Grid::new(format!("admin_server_grid:{key_owned}"))
                                    .num_columns(2)
                                    .spacing([8.0, 6.0])
                                    .show(ui, |ui| {
                                        ui.label("Name:");
                                        ui.text_edit_singleline(&mut server_name);
                                        ui.end_row();
                                        ui.label("Description:");
                                        ui.text_edit_singleline(&mut server_desc);
                                        ui.end_row();
                                    });
                                if ui.button("Save").clicked() {
                                    save_server = true;
                                }
                            });

                        egui::CollapsingHeader::new("User accounts")
                            .default_open(true)
                            .show(ui, |ui| {
                                // ── Create a new account ──────────────────────
                                ui.horizontal(|ui| {
                                    ui.label("New:");
                                    ui.text_edit_singleline(&mut new_user);
                                    ui.add(
                                        egui::TextEdit::singleline(&mut new_pass)
                                            .password(true)
                                            .desired_width(120.0)
                                            .hint_text("password"),
                                    );
                                    let can = !new_user.is_empty() && !new_pass.is_empty();
                                    if ui.add_enabled(can, egui::Button::new("Create")).clicked() {
                                        create_user = true;
                                    }
                                });
                                // Initial group memberships for the new account.
                                if groups.is_empty() {
                                    ui.label(egui::RichText::new("No groups available.").weak());
                                } else {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label("Groups:");
                                        for g in &groups {
                                            let mut member = new_groups.contains(&g.name);
                                            let mut check = ui.checkbox(&mut member, &g.name);
                                            if let Some(desc) = &g.description {
                                                check = check.on_hover_text(desc);
                                            }
                                            if check.changed() {
                                                if member {
                                                    new_groups.insert(g.name.clone());
                                                } else {
                                                    new_groups.remove(&g.name);
                                                }
                                            }
                                        }
                                    });
                                }

                                ui.separator();

                                // ── Existing accounts ─────────────────────────
                                if users.is_empty() {
                                    ui.label(egui::RichText::new("No user accounts.").weak());
                                }
                                for u in &users {
                                    let title = if u.admin {
                                        format!("{} (admin)", u.username)
                                    } else {
                                        u.username.clone()
                                    };
                                    egui::CollapsingHeader::new(title)
                                        .id_salt(format!("admin_user:{key_owned}:{}", u.id))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(if u.enabled {
                                                    "Enabled"
                                                } else {
                                                    "Disabled"
                                                });
                                                // The built-in admin (id 0) cannot be deleted.
                                                if u.id != 0 && ui.small_button("Delete").clicked()
                                                {
                                                    delete_user = Some(u.id);
                                                }
                                            });
                                            if groups.is_empty() {
                                                ui.label(
                                                    egui::RichText::new("No groups available.")
                                                        .weak(),
                                                );
                                            } else {
                                                ui.horizontal_wrapped(|ui| {
                                                    ui.label("Groups:");
                                                    for g in &groups {
                                                        let mut member = u.groups.contains(&g.name);
                                                        // The built-in admin can't leave admin.
                                                        let locked = u.id == 0 && g.name == "admin";
                                                        let mut check = ui.add_enabled(
                                                            !locked,
                                                            egui::Checkbox::new(
                                                                &mut member,
                                                                &g.name,
                                                            ),
                                                        );
                                                        if let Some(desc) = &g.description {
                                                            check = check.on_hover_text(desc);
                                                        }
                                                        if check.changed() {
                                                            group_changes
                                                                .push((u.id, g.id, member));
                                                        }
                                                    }
                                                });
                                            }
                                        });
                                }
                            });

                        egui::CollapsingHeader::new("Trackers")
                            .default_open(true)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("Add:");
                                    ui.text_edit_singleline(&mut tracker_host);
                                    ui.add(
                                        egui::TextEdit::singleline(&mut tracker_port)
                                            .desired_width(60.0)
                                            .hint_text("port"),
                                    );
                                    let can = !tracker_host.is_empty()
                                        && tracker_port.parse::<u16>().is_ok();
                                    if ui.add_enabled(can, egui::Button::new("Add")).clicked() {
                                        add_tracker = true;
                                    }
                                });
                                ui.separator();
                                if trackers.is_empty() {
                                    ui.label(egui::RichText::new("No trackers configured.").weak());
                                }
                                for tracker in &trackers {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}:{}",
                                                tracker.host, tracker.port
                                            ))
                                            .monospace(),
                                        );
                                        if ui.small_button("Remove").clicked() {
                                            remove_tracker =
                                                Some((tracker.host.clone(), tracker.port));
                                        }
                                    });
                                }
                            });

                        ui.separator();
                        if ui.button("Refresh").clicked() {
                            refresh = true;
                        }
                    });

                    // Perform queued actions; each re-requests the relevant list.
                    if save_server {
                        let c = conn.clone();
                        let (n, d) = (server_name.clone(), server_desc.clone());
                        tokio::spawn(async move {
                            let _ = c.admin_set_server_name(n).await;
                            let _ = c.admin_set_server_description(d).await;
                        });
                    }
                    if create_user {
                        let c = conn.clone();
                        let (u, p) = (new_user.clone(), new_pass.clone());
                        let selected: Vec<String> = new_groups.iter().cloned().collect();
                        new_user.clear();
                        new_pass.clear();
                        new_groups.clear();
                        tokio::spawn(async move {
                            let _ = c.admin_create_user(u, p, selected).await;
                            let _ = c.admin_list_users().await;
                        });
                    }
                    if let Some(username) = delete_user {
                        let c = conn.clone();
                        tokio::spawn(async move {
                            let _ = c.admin_delete_user(username).await;
                            let _ = c.admin_list_users().await;
                        });
                    }
                    for (uid, gid, add) in group_changes {
                        let c = conn.clone();
                        tokio::spawn(async move {
                            if add {
                                let _ = c.admin_add_user_to_group(uid, gid).await;
                            } else {
                                let _ = c.admin_remove_user_from_group(uid, gid).await;
                            }
                            let _ = c.admin_list_users().await;
                        });
                    }
                    if add_tracker && let Ok(port) = tracker_port.parse::<u16>() {
                        let c = conn.clone();
                        let host = tracker_host.clone();
                        tracker_host.clear();
                        tokio::spawn(async move {
                            let _ = c.admin_add_tracker(host, port).await;
                            let _ = c.admin_list_trackers().await;
                        });
                    }
                    if let Some((host, port)) = remove_tracker {
                        let c = conn.clone();
                        tokio::spawn(async move {
                            let _ = c.admin_remove_tracker(host, port).await;
                            let _ = c.admin_list_trackers().await;
                        });
                    }
                    if refresh {
                        let c = conn.clone();
                        tokio::spawn(async move {
                            let _ = c.admin_list_users().await;
                            let _ = c.admin_list_groups().await;
                            let _ = c.admin_list_trackers().await;
                        });
                    }

                    // Persist the form fields for the next frame.
                    ctx.data_mut(|d| {
                        d.insert_temp(name_id, server_name);
                        d.insert_temp(desc_id, server_desc);
                        d.insert_temp(new_user_id, new_user);
                        d.insert_temp(new_pass_id, new_pass);
                        d.insert_temp(new_groups_id, new_groups);
                        d.insert_temp(tracker_host_id, tracker_host);
                        d.insert_temp(tracker_port_id, tracker_port);
                    });

                    ctx.request_repaint_after(std::time::Duration::from_secs(2));
                },
            );
        }

        // ── Root window: connection launcher ──────────────────────────────
        egui::CentralPanel::default().show(ui, |ui| {
            if has_connections {
                ui.horizontal(|ui| {
                    ui.label(format!("Connected to {} server(s).", conn_snapshots.len()));
                    if ui.small_button("Show Servers").clicked() {
                        self.show_servers_window = true;
                    }
                });
                ui.separator();
            }

            {
                // ── Connect options ───────────────────────────────────────
                ui.vertical_centered(|ui| {
                    ui.add_space(24.0);
                    ui.heading("Connect to a Conclave Server");
                    ui.add_space(16.0);

                    ui.horizontal(|ui| {
                        if ui.button("Discover Local Servers").clicked() {
                            self.show_advertised_servers_list = true;
                            do_start_discovery(
                                self.discovered_servers.clone(),
                                self.discovery_running.clone(),
                                self.discovery_error.clone(),
                            );
                        }

                        if ui.button("Find via Trackers").clicked() {
                            // Opening the window starts a live subscription that
                            // keeps the listing updated (see the reconcile logic
                            // at the top of `update`).
                            self.show_tracker_servers = true;
                        }

                        if ui.button("Direct Connect").clicked() {
                            self.show_direct_connect = !self.show_direct_connect;
                        }
                    });

                    // ── Connection status (bookmark or in-flight connect) ─────
                    let bm_is_pending = self.connect_pending.load(Ordering::SeqCst);
                    let bm_error: Option<String> =
                        self.connect_error.read().ok().and_then(|e| e.clone());

                    if bm_is_pending {
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new());
                            ui.label("Connecting…");
                        });
                    }
                    if let Some(ref err) = bm_error {
                        ui.add_space(4.0);
                        ui.colored_label(egui::Color32::RED, err);
                    }

                    // ── Direct Connect form ───────────────────────────────────
                    if self.show_direct_connect {
                        ui.add_space(16.0);
                        ui.separator();
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Direct Connect").strong());

                        let host_id = egui::Id::new("direct_connect_host");
                        let port_id = egui::Id::new("direct_connect_port");
                        let mut host: String =
                            ui.ctx().data(|d| d.get_temp(host_id).unwrap_or_default());
                        let mut port_str: String = ui
                            .ctx()
                            .data(|d| d.get_temp(port_id).unwrap_or_else(|| "9101".to_string()));

                        ui.horizontal(|ui| {
                            ui.label("Host:");
                            ui.text_edit_singleline(&mut host);
                            ui.label("Port:");
                            ui.add(egui::TextEdit::singleline(&mut port_str).desired_width(60.0));
                        });

                        let port_ok = port_str.parse::<u16>().is_ok();
                        let can_connect = !host.is_empty() && port_ok && !bm_is_pending;

                        ui.add_space(4.0);
                        if ui
                            .add_enabled(can_connect, egui::Button::new("Connect"))
                            .clicked()
                        {
                            let port = port_str.parse::<u16>().unwrap_or(9101);
                            if let Ok(mut p) = self.pending_server.write() {
                                *p = Some(PendingServer {
                                    host: host.clone(),
                                    port,
                                    key: None,
                                    name: format!("{host}:{port}"),
                                    anonymous_allowed: true,
                                });
                            }
                            if let Ok(mut e) = self.connect_error.write() {
                                *e = None;
                            }
                        }

                        ui.ctx().data_mut(|d| {
                            d.insert_temp(host_id, host);
                            d.insert_temp(port_id, port_str);
                        });
                    }

                    // ── Bookmarks ─────────────────────────────────────────────
                    let bookmarks = self.client.bookmarks();
                    if !bookmarks.is_empty() {
                        ui.add_space(16.0);
                        ui.separator();
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Bookmarks").strong());
                        ui.add_space(4.0);

                        for bookmark in bookmarks {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(&bookmark.name).strong());
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{}:{}",
                                            bookmark.server.host, bookmark.server.port
                                        ))
                                        .monospace()
                                        .weak(),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .add_enabled(
                                                    !bm_is_pending,
                                                    egui::Button::new("Connect"),
                                                )
                                                .clicked()
                                            {
                                                let auth = bookmark.auth.as_ref().map(|a| {
                                                    UserAuthentication {
                                                        username: a.username.clone(),
                                                        password: a.password.clone(),
                                                    }
                                                });
                                                spawn_connect(
                                                    self.client.clone(),
                                                    self.active_connections.clone(),
                                                    self.connect_pending.clone(),
                                                    self.connect_error.clone(),
                                                    None,
                                                    bookmark.server.host.clone(),
                                                    bookmark.server.port,
                                                    bookmark.share_time,
                                                    bookmark.display_name.clone(),
                                                    auth,
                                                    Some(bookmark.server.key),
                                                );
                                            }
                                        },
                                    );
                                });
                                if !bookmark.display_name.is_empty() {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "as {}",
                                            bookmark.display_name
                                        ))
                                        .weak(),
                                    );
                                }
                            });
                        }
                    } else if !self.show_direct_connect {
                        ui.add_space(24.0);
                        ui.label(
                            egui::RichText::new(
                                "Use the buttons above to find and connect to a server.",
                            )
                            .weak(),
                        );
                    }
                });

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    egui::warn_if_debug_build(ui);
                });
            }
        });
    }
}
