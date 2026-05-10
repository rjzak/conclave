// SPDX-License-Identifier: Apache-2.0

use conclave_client::{Client, DiscoveredServer, discover_servers};

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use eframe::{Frame, egui};
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

/// GUI client state
#[derive(Debug, Default)]
pub struct ConclaveClient {
    client: Arc<Client>,
    show_advertised_servers_list: bool,
    show_tracker_list: bool,
    discovered_servers: Arc<RwLock<HashSet<DiscoveredServer>>>,
    discovery_running: Arc<AtomicBool>,
    discovery_error: Arc<RwLock<Option<String>>>,
    discovery_viewport_closed: Arc<AtomicBool>,
    tracker_viewport_closed: Arc<AtomicBool>,
    tracker_error: Arc<RwLock<Option<String>>>,
    tracker_op_pending: Arc<AtomicBool>,
}

impl ConclaveClient {
    pub fn new(client: Client, _cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            client: Arc::new(client),
            ..Default::default()
        }
    }
}

impl eframe::App for ConclaveClient {
    #[allow(clippy::too_many_lines)]
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut Frame) {
        if self.discovery_viewport_closed.swap(false, Ordering::SeqCst) {
            self.show_advertised_servers_list = false;
        }
        if self.tracker_viewport_closed.swap(false, Ordering::SeqCst) {
            self.show_tracker_list = false;
        }

        if self.discovery_running.load(Ordering::SeqCst) {
            ui.ctx().request_repaint();
        }

        egui::Panel::top("top_panel").show_inside(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Quit").clicked() {
                        ui.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.show_advertised_servers_list, "Server Discovery");
                    ui.checkbox(&mut self.show_tracker_list, "Trackers");
                });
                ui.add_space(16.0);
                egui::widgets::global_theme_preference_buttons(ui);
            });
        });

        // Server Discovery viewport
        if self.show_advertised_servers_list {
            let closed_arc = self.discovery_viewport_closed.clone();
            let running_arc = self.discovery_running.clone();
            let servers_arc = self.discovered_servers.clone();
            let error_arc = self.discovery_error.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("local_server_discovery"),
                egui::ViewportBuilder::default()
                    .with_title("Local Server Discovery")
                    .with_inner_size([420.0, 300.0])
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
                    egui::CentralPanel::default().show_inside(ctx, |ui| {
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

        // Tracker List viewport
        if self.show_tracker_list {
            // Capture the tokio handle here, in fn ui(), which is called from the main
            // thread inside tokio's block_on. The deferred closure may run on a different
            // thread without a tokio context, so Handle::current() must not be called there.
            let closed_arc = self.tracker_viewport_closed.clone();
            let error_arc = self.tracker_error.clone();
            let op_pending_arc = self.tracker_op_pending.clone();
            let client_arc = self.client.clone();

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

                    egui::CentralPanel::default().show_inside(ctx, |ui| {
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
                                                        tracker.name, tracker.port
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
                                                                tracker.name.clone(),
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
                        let can_add = !is_pending
                            && !form_host.is_empty()
                            && form_port.parse::<u16>().is_ok();
                        ui.add_space(4.0);
                        if ui.add_enabled(can_add, egui::Button::new("Add")).clicked() {
                            add_request = true;
                        }
                    });

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
                        let client = client_arc.clone();
                        let err_arc = error_arc.clone();
                        let pending = op_pending_arc.clone();
                        pending.store(true, Ordering::SeqCst);
                        {
                            // Can't hold the lock for too long.
                            if let Ok(mut err) = err_arc.write() {
                                *err = None;
                            }
                        }

                        let name = std::mem::take(&mut form_host);
                        let Ok(port) = form_port.parse::<u16>() else {
                            error!("Invalid port: {form_port}");
                            if let Ok(mut err) = err_arc.write() {
                                *err = Some(format!("Invalid port: {form_port}"));
                            }
                            return;
                        };
                        form_port.clear();

                        tokio::spawn(async move {
                            if let Err(e) = client.add_tracker(&name, port).await
                                && let Ok(mut err) = err_arc.write()
                            {
                                *err = Some(e.to_string());
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

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("Conclave something goes here");
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                egui::warn_if_debug_build(ui);
            });
        });
    }
}
