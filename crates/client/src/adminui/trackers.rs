// SPDX-License-Identifier: Apache-2.0

//! Trackers tab: add and remove the trackers this server advertises to.

use crate::conn::ConclaveConnection;

use eframe::egui;

/// Render the trackers tab.
pub fn ui(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    let trackers = conn.admin_trackers();

    let host_id = egui::Id::new(format!("admin_th:{key}"));
    let port_id = egui::Id::new(format!("admin_tp:{key}"));
    let mut host: String = ui.data(|d| d.get_temp(host_id).unwrap_or_default());
    let mut port: String = ui.data(|d| d.get_temp(port_id).unwrap_or_else(|| "9100".to_string()));

    let mut add_tracker = false;
    let mut remove_tracker: Option<(String, u16)> = None;

    ui.horizontal(|ui| {
        ui.label("Add:");
        ui.text_edit_singleline(&mut host);
        ui.add(
            egui::TextEdit::singleline(&mut port)
                .desired_width(60.0)
                .hint_text("port"),
        );
        let can = !host.is_empty() && port.parse::<u16>().is_ok();
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
            ui.label(egui::RichText::new(format!("{}:{}", tracker.host, tracker.port)).monospace());
            if ui.small_button("Remove").clicked() {
                remove_tracker = Some((tracker.host.clone(), tracker.port));
            }
        });
    }

    // ── Perform queued actions ────────────────────────────────────────────
    if add_tracker && let Ok(parsed) = port.parse::<u16>() {
        let conn = conn.clone();
        let host_value = std::mem::take(&mut host);
        tokio::spawn(async move {
            let _ = conn.admin_add_tracker(host_value, parsed).await;
            let _ = conn.admin_list_trackers().await;
        });
    }
    if let Some((host_value, port_value)) = remove_tracker {
        let conn = conn.clone();
        tokio::spawn(async move {
            let _ = conn.admin_remove_tracker(host_value, port_value).await;
            let _ = conn.admin_list_trackers().await;
        });
    }

    ui.data_mut(|d| {
        d.insert_temp(host_id, host);
        d.insert_temp(port_id, port);
    });
}
