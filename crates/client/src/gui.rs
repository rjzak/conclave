// SPDX-License-Identifier: Apache-2.0

use eframe::Frame;
use eframe::egui::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ConclaveClient {
    show_trackers_list: bool,
    show_server_bookmarks_list: bool,
    show_advertised_servers_list: bool,
}

impl Default for ConclaveClient {
    fn default() -> Self {
        Self {
            show_trackers_list: true,
            show_server_bookmarks_list: true,
            show_advertised_servers_list: false,
        }
    }
}

impl ConclaveClient {
    pub fn new(__cc: &eframe::CreationContext<'_>) -> Self {
        ConclaveClient::default()
    }
}

impl eframe::App for ConclaveClient {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        ctx.request_repaint();
        // Put your widgets into a `SidePanel`, `TopBottomPanel`, `CentralPanel`, `Window` or `Area`.
        // For inspiration and more examples, go to https://emilk.github.io/egui

        eframe::egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            eframe::egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Close);
                    }
                });
                ui.add_space(16.0);

                eframe::egui::widgets::global_theme_preference_buttons(ui);
            });
        });

        eframe::egui::CentralPanel::default().show(ctx, |ui| {
            // The central panel the region left after adding TopPanel's and SidePanel's
            ui.heading("eframe template");

            ui.separator();

            ui.add(eframe::egui::github_link_file!(
                "https://github.com/emilk/eframe_template/blob/main/",
                "Source code."
            ));

            ui.with_layout(
                eframe::egui::Layout::bottom_up(eframe::egui::Align::LEFT),
                |ui| {
                    eframe::egui::warn_if_debug_build(ui);
                },
            );
        });
    }
}
