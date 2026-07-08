// SPDX-License-Identifier: Apache-2.0

use conclave_client::config::{BookmarkEntry, KnownHost, UserAuth};
use conclave_client::conn::{ChatLine, ConclaveConnection};
use conclave_client::{Client, DiscoveredServer, discover_servers};
use conclave_common::server::{
    ConnectedUser, IDLE_TIMEOUT_MINUTES, UserAuthentication, VerifyingKey,
};
use conclave_common::tracker::{Advertise, Tracker, TrackerWithKey};

use std::collections::{HashMap, HashSet};
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

/// Whether a user counts as idle (inactive for longer than the timeout), in
/// which case their name is shown dulled.
#[inline]
fn is_idle(idle: chrono::Duration) -> bool {
    idle >= IDLE_TIMEOUT_MINUTES
}

/// The base name colour for a user: the mix of their groups' colours, falling
/// back to red for administrators with no colour of their own.
fn base_name_color(user: &ConnectedUser) -> Option<egui::Color32> {
    user.color
        .map(|[r, g, b]| egui::Color32::from_rgb(r, g, b))
        .or_else(|| user.admin.then_some(egui::Color32::RED))
}

/// A muted version of a colour: shifted toward its own grey so an idle user's
/// name dims without becoming a flat grey.
fn dull(color: egui::Color32) -> egui::Color32 {
    let (r, g, b) = (
        u16::from(color.r()),
        u16::from(color.g()),
        u16::from(color.b()),
    );
    let lum = (r * 3 + g * 6 + b) / 10; // approximate luminance
    // 40% of the original colour, 60% of its luminance grey.
    let mix = |c: u16| u8::try_from((c * 2 + lum * 3) / 5).unwrap_or(u8::MAX);
    egui::Color32::from_rgb(mix(r), mix(g), mix(b))
}

/// Style a name with its colour and idle state: idle colours are dulled, and an
/// idle user with no colour is greyed.
fn styled_name(text: &str, color: Option<egui::Color32>, idle: bool) -> egui::RichText {
    let text = egui::RichText::new(text);
    match (color, idle) {
        (Some(c), true) => text.color(dull(c)),
        (Some(c), false) => text.color(c),
        (None, true) => text.color(egui::Color32::GRAY),
        (None, false) => text,
    }
}

/// Describe a user's timezone relative to ours, rounded to whole hours. `None`
/// means the user did not share their local time.
fn timezone_offset_text(tz: Option<chrono::DateTime<chrono::Local>>) -> String {
    use chrono::Offset;

    let Some(tz) = tz else {
        return "Timezone: not shared".to_string();
    };

    let theirs = tz.offset().fix().local_minus_utc();
    let ours = chrono::Local::now().offset().fix().local_minus_utc();
    // Difference in seconds, rounded to the nearest whole hour (halves away
    // from zero) without floating point.
    let diff_secs = i64::from(theirs - ours);
    let hours = (diff_secs + if diff_secs >= 0 { 1800 } else { -1800 }) / 3600;

    match hours.cmp(&0) {
        std::cmp::Ordering::Greater => format!("Timezone: {hours}h ahead of you"),
        std::cmp::Ordering::Less => format!("Timezone: {}h behind you", hours.abs()),
        std::cmp::Ordering::Equal => "Timezone: same as yours".to_string(),
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

    /// Open chatroom windows, keyed by (server key, room id)
    open_chats: Arc<RwLock<HashSet<(String, u16)>>>,

    /// Chat-window close requests emitted by viewport closures
    chat_window_close_requests: Arc<RwLock<Vec<(String, u16)>>>,

    /// Show the bookmarks management window
    show_bookmarks_window: bool,

    /// Bookmarks window close flag
    bookmarks_viewport_closed: Arc<AtomicBool>,

    /// Any error from a bookmark add/edit operation
    bookmarks_error: Arc<RwLock<Option<String>>>,

    /// A bookmark add/edit is in progress (fetching the server key)
    bookmarks_op_pending: Arc<AtomicBool>,
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
            open_chats: Arc::new(RwLock::new(HashSet::new())),
            chat_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            seen_servers: HashSet::new(),
            user_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            show_bookmarks_window: false,
            bookmarks_viewport_closed: Arc::new(AtomicBool::new(false)),
            bookmarks_error: Arc::new(RwLock::new(None)),
            bookmarks_op_pending: Arc::new(AtomicBool::new(false)),
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
        if self.bookmarks_viewport_closed.swap(false, Ordering::SeqCst) {
            self.show_bookmarks_window = false;
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
            || self.bookmarks_op_pending.load(Ordering::SeqCst)
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
                    ui.checkbox(&mut self.show_bookmarks_window, "Bookmarks");
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

        // ── Bookmarks viewport ────────────────────────────────────────────
        if self.show_bookmarks_window {
            let closed_arc = self.bookmarks_viewport_closed.clone();
            let error_arc = self.bookmarks_error.clone();
            let op_pending_arc = self.bookmarks_op_pending.clone();
            let client_arc = self.client.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("bookmarks"),
                egui::ViewportBuilder::default()
                    .with_title("Bookmarks")
                    .with_inner_size([460.0, 520.0])
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
                    let bookmarks = client_arc.bookmarks();

                    // Form fields live in egui temp data, keyed once here.
                    let name_id = egui::Id::new("bm_form_name");
                    let host_id = egui::Id::new("bm_form_host");
                    let port_id = egui::Id::new("bm_form_port");
                    let display_id = egui::Id::new("bm_form_display");
                    let user_id = egui::Id::new("bm_form_user");
                    let pass_id = egui::Id::new("bm_form_pass");
                    let share_id = egui::Id::new("bm_form_share");
                    let edit_id = egui::Id::new("bm_form_edit_index");

                    let mut f_name =
                        ctx.data(|d| d.get_temp::<String>(name_id).unwrap_or_default());
                    let mut f_host =
                        ctx.data(|d| d.get_temp::<String>(host_id).unwrap_or_default());
                    let mut f_port =
                        ctx.data(|d| d.get_temp::<String>(port_id).unwrap_or_default());
                    let mut f_display =
                        ctx.data(|d| d.get_temp::<String>(display_id).unwrap_or_default());
                    let mut f_user =
                        ctx.data(|d| d.get_temp::<String>(user_id).unwrap_or_default());
                    let mut f_pass =
                        ctx.data(|d| d.get_temp::<String>(pass_id).unwrap_or_default());
                    let mut f_share = ctx.data(|d| d.get_temp::<bool>(share_id).unwrap_or(false));
                    let mut edit_index =
                        ctx.data(|d| d.get_temp::<Option<usize>>(edit_id)).flatten();

                    let mut delete_request: Option<usize> = None;
                    let mut edit_request: Option<usize> = None;
                    let mut save_request = false;
                    let mut cancel_request = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        if is_pending {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new());
                                ui.label("Working...");
                            });
                        } else {
                            let Ok(error_msg) = error_arc.read() else {
                                error!("Failed to read bookmarks error state");
                                return;
                            };
                            if let Some(err) = error_msg.clone() {
                                ui.colored_label(egui::Color32::RED, err);
                            }
                        }

                        ui.separator();

                        egui::ScrollArea::vertical()
                            .max_height(240.0)
                            .show(ui, |ui| {
                                if bookmarks.is_empty() {
                                    ui.label(egui::RichText::new("No bookmarks yet.").weak());
                                }
                                for (i, bookmark) in bookmarks.iter().enumerate() {
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
                                                    if !is_pending && ui.button("Delete").clicked()
                                                    {
                                                        delete_request = Some(i);
                                                    }
                                                    if !is_pending && ui.button("Edit").clicked() {
                                                        edit_request = Some(i);
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
                                        if let Some(auth) = &bookmark.auth {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "Username: {}",
                                                    auth.username
                                                ))
                                                .weak(),
                                            );
                                        }

                                        // The server key is hidden until asked for.
                                        let show_key_id = egui::Id::new(("bm_show_key", i));
                                        let mut show_key = ui
                                            .data(|d| d.get_temp::<bool>(show_key_id))
                                            .unwrap_or(false);
                                        if ui
                                            .button(if show_key { "Hide key" } else { "Show key" })
                                            .clicked()
                                        {
                                            show_key = !show_key;
                                            ui.data_mut(|d| {
                                                d.insert_temp(show_key_id, show_key);
                                            });
                                        }
                                        if show_key {
                                            let key_hex =
                                                hex::encode(bookmark.server.key.as_bytes());
                                            let key_sha256 = hex::encode(Sha256::digest(
                                                bookmark.server.key.as_bytes(),
                                            ));
                                            ui.label(egui::RichText::new("Key (hex):").strong());
                                            egui::ScrollArea::vertical()
                                                .id_salt(("bm_key_hex", i))
                                                .max_height(48.0)
                                                .show(ui, |ui| {
                                                    ui.add(
                                                        egui::Label::new(
                                                            egui::RichText::new(&key_hex)
                                                                .monospace()
                                                                .size(10.0),
                                                        )
                                                        .wrap(),
                                                    );
                                                });
                                            ui.label(
                                                egui::RichText::new("Key (SHA-256):").strong(),
                                            );
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(&key_sha256)
                                                        .monospace()
                                                        .size(10.0),
                                                )
                                                .wrap(),
                                            );
                                        }
                                    });
                                }
                            });

                        ui.separator();
                        ui.label(
                            egui::RichText::new(if edit_index.is_some() {
                                "Edit Bookmark"
                            } else {
                                "Add Bookmark"
                            })
                            .strong(),
                        );
                        egui::Grid::new("bookmark_form_grid")
                            .num_columns(2)
                            .spacing([8.0, 6.0])
                            .show(ui, |ui| {
                                ui.label("Server name:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut f_name)
                                        .hint_text("fetched from server if blank"),
                                );
                                ui.end_row();
                                ui.label("Host:");
                                ui.text_edit_singleline(&mut f_host);
                                ui.end_row();
                                ui.label("Port:");
                                ui.add(egui::TextEdit::singleline(&mut f_port).desired_width(60.0));
                                ui.end_row();
                                ui.label("Display name:");
                                ui.text_edit_singleline(&mut f_display);
                                ui.end_row();
                                ui.label("Username:");
                                ui.text_edit_singleline(&mut f_user);
                                ui.end_row();
                                ui.label("Password:");
                                ui.add(egui::TextEdit::singleline(&mut f_pass).password(true));
                                ui.end_row();
                                ui.label("Share local time:");
                                ui.checkbox(&mut f_share, "");
                                ui.end_row();
                            });

                        ui.add_space(4.0);
                        // The server name may be left blank; it is fetched from
                        // the server when the bookmark is saved.
                        let can_save =
                            !is_pending && !f_host.is_empty() && f_port.parse::<u16>().is_ok();
                        ui.horizontal(|ui| {
                            let save_label = if edit_index.is_some() { "Save" } else { "Add" };
                            if ui
                                .add_enabled(can_save, egui::Button::new(save_label))
                                .clicked()
                            {
                                save_request = true;
                            }
                            if edit_index.is_some() && ui.button("Cancel").clicked() {
                                cancel_request = true;
                            }
                        });
                    });

                    // Load a bookmark into the form for editing.
                    if let Some(i) = edit_request
                        && let Some(bookmark) = bookmarks.get(i)
                    {
                        f_name.clone_from(&bookmark.name);
                        f_host.clone_from(&bookmark.server.host);
                        f_port = bookmark.server.port.to_string();
                        f_display.clone_from(&bookmark.display_name);
                        f_user = bookmark
                            .auth
                            .as_ref()
                            .map(|a| a.username.clone())
                            .unwrap_or_default();
                        f_pass = bookmark
                            .auth
                            .as_ref()
                            .map(|a| a.password.clone())
                            .unwrap_or_default();
                        f_share = bookmark.share_time;
                        edit_index = Some(i);
                    }

                    if cancel_request {
                        f_name.clear();
                        f_host.clear();
                        f_port.clear();
                        f_display.clear();
                        f_user.clear();
                        f_pass.clear();
                        f_share = false;
                        edit_index = None;
                    }

                    if let Some(i) = delete_request {
                        // If the deleted entry was being edited, leave edit mode.
                        if edit_index == Some(i) {
                            f_name.clear();
                            f_host.clear();
                            f_port.clear();
                            f_display.clear();
                            f_user.clear();
                            f_pass.clear();
                            f_share = false;
                            edit_index = None;
                        }
                        let client = client_arc.clone();
                        let err_arc = error_arc.clone();
                        let pending = op_pending_arc.clone();
                        pending.store(true, Ordering::SeqCst);
                        tokio::spawn(async move {
                            if let Err(e) = client.remove_bookmark_by_index(i).await
                                && let Ok(mut err) = err_arc.write()
                            {
                                *err = Some(e.to_string());
                            }
                            pending.store(false, Ordering::SeqCst);
                        });
                    }

                    if save_request && let Ok(port) = f_port.parse::<u16>() {
                        // Reuse the stored key when the address is unchanged;
                        // otherwise fetch the server's key.
                        let key_reuse = edit_index
                            .and_then(|i| bookmarks.get(i))
                            .filter(|b| b.server.host == f_host && b.server.port == port)
                            .map(|b| b.server.key);

                        let name = std::mem::take(&mut f_name);
                        let host = std::mem::take(&mut f_host);
                        let display = std::mem::take(&mut f_display);
                        let user = std::mem::take(&mut f_user);
                        let pass = std::mem::take(&mut f_pass);
                        let share = f_share;
                        let index = edit_index;

                        // Reset the form back to add mode.
                        f_port.clear();
                        f_share = false;
                        edit_index = None;

                        let client = client_arc.clone();
                        let err_arc = error_arc.clone();
                        let pending = op_pending_arc.clone();
                        pending.store(true, Ordering::SeqCst);
                        if let Ok(mut err) = err_arc.write() {
                            *err = None;
                        }

                        tokio::spawn(async move {
                            let key = match key_reuse {
                                Some(key) => Ok(key),
                                None => Client::fetch_server_key(&host, port).await,
                            };
                            let key = match key {
                                Ok(key) => key,
                                Err(e) => {
                                    if let Ok(mut err) = err_arc.write() {
                                        *err = Some(format!("Failed to get server key: {e}"));
                                    }
                                    pending.store(false, Ordering::SeqCst);
                                    return;
                                }
                            };

                            // Fetch the server's name when the user left it blank.
                            let name = if name.is_empty() {
                                let handshake_auth =
                                    (!user.is_empty() || !pass.is_empty()).then(|| {
                                        UserAuthentication {
                                            username: user.clone(),
                                            password: pass.clone(),
                                        }
                                    });
                                match Client::fetch_server_info(
                                    &host,
                                    port,
                                    key,
                                    &display,
                                    handshake_auth,
                                )
                                .await
                                {
                                    Ok(info) => info.name,
                                    Err(e) => {
                                        if let Ok(mut err) = err_arc.write() {
                                            *err =
                                                Some(format!("Failed to fetch server name: {e}"));
                                        }
                                        pending.store(false, Ordering::SeqCst);
                                        return;
                                    }
                                }
                            } else {
                                name
                            };

                            let auth = (!user.is_empty() || !pass.is_empty()).then(|| UserAuth {
                                username: user,
                                password: pass,
                            });
                            let entry = BookmarkEntry {
                                server: KnownHost { host, port, key },
                                name,
                                display_name: display,
                                auth,
                                share_time: share,
                            };
                            let result = if let Some(i) = index {
                                client.update_bookmark(i, &entry).await
                            } else {
                                client.add_bookmark(&entry).await
                            };
                            if let Err(e) = result
                                && let Ok(mut err) = err_arc.write()
                            {
                                *err = Some(e.to_string());
                            }
                            pending.store(false, Ordering::SeqCst);
                        });
                    }

                    ctx.data_mut(|d| {
                        d.insert_temp(name_id, f_name);
                        d.insert_temp(host_id, f_host);
                        d.insert_temp(port_id, f_port);
                        d.insert_temp(display_id, f_display);
                        d.insert_temp(user_id, f_user);
                        d.insert_temp(pass_id, f_pass);
                        d.insert_temp(share_id, f_share);
                        d.insert_temp(edit_id, edit_index);
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

        // ── Prune dead connections ────────────────────────────────────────
        // A connection whose listener has ended (the server closed it or kicked
        // us) is removed so it no longer appears in the servers list, as if we
        // had never connected. Its socket is released here and, asynchronously,
        // from the client's own connection list.
        {
            let mut removed_any = false;
            if let Ok(mut conns) = self.active_connections.write() {
                let before = conns.len();
                conns.retain(|conn| conn.connected_since().is_some());
                removed_any = conns.len() != before;
            }
            if removed_any {
                let client = self.client.clone();
                tokio::spawn(async move {
                    client.prune_disconnected().await;
                });
            }
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

        // Server public keys shared by more than one connection, so those
        // windows can be disambiguated by the user's display name.
        let mut server_counts: HashMap<String, usize> = HashMap::new();
        for conn in &conns {
            *server_counts
                .entry(hex::encode(conn.server_info().key.as_bytes()))
                .or_default() += 1;
        }

        // Each snapshot is keyed uniquely per connection (server key + a
        // process-unique connection id) so two connections to the same server
        // don't collide on egui window/viewport ids or temp state.
        let conn_snapshots: Vec<(String, String, bool, ConclaveConnection)> = conns
            .into_iter()
            .map(|conn| {
                let info = conn.server_info();
                let server_key = hex::encode(info.key.as_bytes());
                let active = conn.connected_since().is_some();
                let key = format!("{server_key}:{}", conn.local_id());
                let name = if server_counts.get(&server_key).is_some_and(|&n| n > 1) {
                    format!("{} ({})", info.name, conn.display_name())
                } else {
                    info.name
                };
                (key, name, active, conn)
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
                        // The window key is `{server_key}:{local_id}`, so reconstruct
                        // it per connection to find the exact one to disconnect.
                        let removed = active_conns.write().ok().and_then(|mut c| {
                            let idx = c.iter().position(|conn| {
                                format!(
                                    "{}:{}",
                                    hex::encode(conn.server_info().key),
                                    conn.local_id()
                                ) == key
                            });
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
            let open_chats = self.open_chats.clone();

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
                    let is_admin = conn.is_admin();
                    let details = conn.user_details();
                    // The server pushes the accessible chatrooms on connect and
                    // whenever chat config changes, so no request is needed here.
                    let chatrooms = conn.chatrooms_available();

                    // Which user's detail panel is expanded (by connection id).
                    let selected_id = egui::Id::new(format!("user_details_sel:{key_owned}"));
                    let selected: Option<u16> = ctx
                        .data(|d| d.get_temp::<Option<u16>>(selected_id))
                        .flatten();

                    let mut details_request: Option<u16> = None;
                    let mut kick_request: Option<u16> = None;
                    let mut clear_selection = false;
                    let mut open_chat_request: Option<u16> = None;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.heading(format!("Users on {}", server_info.name));
                        ui.separator();

                        if users.is_empty() {
                            ui.label(egui::RichText::new("No users connected yet.").weak());
                        } else {
                            egui::ScrollArea::vertical()
                                .id_salt(format!("users_scroll:{key_owned}"))
                                .max_height(160.0)
                                .show(ui, |ui| {
                                    egui::Grid::new(format!("users_grid:{key_owned}"))
                                        .striped(true)
                                        .spacing([12.0, 4.0])
                                        .show(ui, |ui| {
                                            ui.label(egui::RichText::new("Name").strong());
                                            ui.label(egui::RichText::new("Connected").strong());
                                            ui.label("");
                                            ui.end_row();

                                            for user in &users {
                                                // Names are tinted their groups'
                                                // colour, dulled when idle.
                                                ui.label(styled_name(
                                                    &user.display_name,
                                                    base_name_color(user),
                                                    is_idle(user.idle),
                                                ));
                                                ui.label(format_uptime(user.connected_since));
                                                if ui.small_button("Details").clicked() {
                                                    details_request = Some(user.id);
                                                }
                                                ui.end_row();
                                            }
                                        });
                                });
                        }

                        // ── Selected user's detail panel ──────────────────────
                        if let Some(sel) = selected {
                            if let Some(user) = users.iter().find(|u| u.id == sel) {
                                ui.separator();
                                ui.horizontal(|ui| {
                                    ui.heading(&user.display_name);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("Close").clicked() {
                                                clear_selection = true;
                                            }
                                        },
                                    );
                                });
                                ui.label(format!(
                                    "Connected: {}",
                                    format_uptime(user.connected_since)
                                ));
                                ui.label(format!("Idle: {}", format_uptime(user.idle)));
                                ui.label(timezone_offset_text(user.timezone));

                                match details.as_ref().filter(|d| d.connection_id == sel) {
                                    Some(d) => {
                                        if d.groups.is_empty() {
                                            ui.label("Groups: none");
                                        } else {
                                            ui.label(format!("Groups: {}", d.groups.join(", ")));
                                        }
                                        // Administrator-only fields.
                                        if let Some(username) = &d.username {
                                            ui.label(format!("Username: {username}"));
                                        }
                                        if let Some(ip) = &d.ip {
                                            ui.label(format!("IP: {ip}"));
                                        }
                                        if is_admin && ui.button("Kick").clicked() {
                                            kick_request = Some(sel);
                                        }
                                    }
                                    None => {
                                        ui.label(egui::RichText::new("Loading details…").weak());
                                    }
                                }
                            } else {
                                // The selected user is no longer connected.
                                clear_selection = true;
                            }
                        }

                        // ── Chatrooms ─────────────────────────────────────
                        ui.separator();
                        ui.heading("Chatrooms");
                        if !server_info.chat_enabled {
                            ui.label(
                                egui::RichText::new("Chat is disabled on this server.").weak(),
                            );
                            if is_admin {
                                ui.label(
                                    egui::RichText::new("Enable it in the server's Admin window.")
                                        .weak()
                                        .small(),
                                );
                            }
                        } else if chatrooms.is_empty() {
                            ui.label(egui::RichText::new("No chatrooms available.").weak());
                        } else {
                            for room in &chatrooms {
                                ui.horizontal(|ui| {
                                    ui.label(&room.name);
                                    let is_open = open_chats
                                        .read()
                                        .is_ok_and(|o| o.contains(&(key_owned.clone(), room.id)));
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if is_open {
                                                ui.label(egui::RichText::new("open").weak());
                                            } else if ui.small_button("Open").clicked() {
                                                open_chat_request = Some(room.id);
                                            }
                                        },
                                    );
                                });
                            }
                        }
                    });

                    // Perform queued actions outside the panel closure.
                    if let Some(room) = open_chat_request {
                        if let Ok(mut open) = open_chats.write() {
                            open.insert((key_owned.clone(), room));
                        }
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.chat_join(room).await;
                        });
                    }
                    if let Some(id) = details_request {
                        ctx.data_mut(|d| d.insert_temp(selected_id, Some(id)));
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.request_user_details(id).await;
                        });
                    }
                    if let Some(id) = kick_request {
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.admin_kick_user(id).await;
                        });
                        ctx.data_mut(|d| d.insert_temp(selected_id, Option::<u16>::None));
                    }
                    if clear_selection {
                        ctx.data_mut(|d| d.insert_temp(selected_id, Option::<u16>::None));
                    }

                    // The server pushes roster changes automatically, and detail
                    // replies arrive asynchronously; repaint frequently so both
                    // are picked up promptly.
                    ctx.request_repaint_after(std::time::Duration::from_millis(200));
                },
            );
        }

        // ── Chatroom windows ──────────────────────────────────────────────
        // Drain close requests (leaving the room) and drop chats whose server
        // has disconnected.
        {
            let live: HashSet<String> = conn_snapshots.iter().map(|(k, ..)| k.clone()).collect();
            let closed: Vec<(String, u16)> = self
                .chat_window_close_requests
                .write()
                .map(|mut r| r.drain(..).collect())
                .unwrap_or_default();
            if let Ok(mut open) = self.open_chats.write() {
                for entry in &closed {
                    open.remove(entry);
                }
                open.retain(|(k, _)| live.contains(k));
            }
            for (k, room) in closed {
                if let Some((.., conn)) = conn_snapshots.iter().find(|(key, ..)| *key == k) {
                    let conn = conn.clone();
                    tokio::spawn(async move {
                        let _ = conn.chat_leave(room).await;
                    });
                }
            }
        }

        let open_chats: Vec<(String, u16)> = self
            .open_chats
            .read()
            .map(|o| o.iter().cloned().collect())
            .unwrap_or_default();

        for (key, room) in open_chats {
            let Some((_, server_name, _, conn)) = conn_snapshots.iter().find(|(k, ..)| *k == key)
            else {
                continue;
            };
            let conn = conn.clone();
            let key_owned = key.clone();
            let room_name = conn
                .chatrooms_available()
                .into_iter()
                .find(|r| r.id == room)
                .map_or_else(|| format!("Room {room}"), |r| r.name);
            let title = format!("{room_name} — {server_name}");
            let close_reqs = self.chat_window_close_requests.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("chat:{key}:{room}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([640.0, 460.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push((key_owned.clone(), room));
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    let state = conn.chat_room(room).unwrap_or_default();
                    // Name colour and idle state per connected user, so chat
                    // names can be tinted (and dulled when idle) to match.
                    let user_styles: HashMap<String, (Option<egui::Color32>, bool)> = conn
                        .get_connected_users()
                        .into_iter()
                        .map(|u| {
                            let style = (base_name_color(&u), is_idle(u.idle));
                            (u.display_name, style)
                        })
                        .collect();

                    let input_id = egui::Id::new(format!("chat_input:{key_owned}:{room}"));
                    let mut input: String = ctx.data(|d| d.get_temp(input_id).unwrap_or_default());
                    let mut send = false;

                    // Bottom: message composer.
                    egui::Panel::bottom(format!("chat_compose:{key_owned}:{room}")).show(
                        ctx,
                        |ui| {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                let response = ui.add(
                                    egui::TextEdit::singleline(&mut input)
                                        .desired_width(ui.available_width() - 60.0)
                                        .hint_text("Message"),
                                );
                                let entered = response.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                if (ui.button("Send").clicked() || entered)
                                    && !input.trim().is_empty()
                                {
                                    send = true;
                                }
                            });
                            ui.add_space(4.0);
                        },
                    );

                    // Right: the room's user list.
                    egui::Panel::right(format!("chat_users:{key_owned}:{room}"))
                        .resizable(true)
                        .default_size(140.0)
                        .show(ctx, |ui| {
                            ui.heading("Users");
                            ui.separator();
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                for user in &state.users {
                                    let (color, idle) =
                                        user_styles.get(user).copied().unwrap_or((None, false));
                                    ui.label(styled_name(user, color, idle));
                                }
                            });
                        });

                    // Center: the conversation.
                    egui::CentralPanel::default().show(ctx, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                for line in &state.lines {
                                    match line {
                                        ChatLine::System(text) => {
                                            ui.label(egui::RichText::new(text).weak().italics());
                                        }
                                        ChatLine::Message {
                                            time,
                                            display_name,
                                            message,
                                        } => {
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(
                                                    egui::RichText::new(
                                                        time.format("%H:%M:%S").to_string(),
                                                    )
                                                    .weak()
                                                    .monospace(),
                                                );
                                                ui.label(
                                                    egui::RichText::new(format!("{display_name}:"))
                                                        .strong(),
                                                );
                                                ui.label(message);
                                            });
                                        }
                                    }
                                }
                            });
                    });

                    if send {
                        let message = std::mem::take(&mut input);
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.chat_send(room, message).await;
                        });
                    }
                    ctx.data_mut(|d| d.insert_temp(input_id, input));
                    // Messages arrive asynchronously; repaint so they show promptly.
                    ctx.request_repaint_after(std::time::Duration::from_millis(150));
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
                    .with_inner_size([500.0, 300.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push(key_owned.clone());
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    conclave_client::adminui::admin_ui(ctx, &conn, &key_owned);
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
