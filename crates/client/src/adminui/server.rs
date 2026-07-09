// SPDX-License-Identifier: Apache-2.0

//! Server settings tab: edit the server's name and description.

use crate::conn::ConclaveConnection;

use eframe::egui;

/// Render the server-settings tab.
pub fn ui(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    let info = conn.server_info();

    ui.horizontal(|ui| {
        ui.label("Server version:");
        ui.label(egui::RichText::new(info.version.to_string()).monospace());
    });
    ui.separator();

    let name_id = egui::Id::new(format!("admin_name:{key}"));
    let desc_id = egui::Id::new(format!("admin_desc:{key}"));
    let mut server_name: String =
        ui.data(|d| d.get_temp(name_id).unwrap_or_else(|| info.name.clone()));
    let mut server_desc: String = ui.data(|d| {
        d.get_temp(desc_id)
            .unwrap_or_else(|| info.description.clone())
    });

    egui::Grid::new(format!("admin_server_grid:{key}"))
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
        let conn = conn.clone();
        let (name, description) = (server_name.clone(), server_desc.clone());
        tokio::spawn(async move {
            let _ = conn.admin_set_server_name(name).await;
            let _ = conn.admin_set_server_description(description).await;
        });
    }

    // Read-only file-sharing status.
    ui.separator();
    ui.label(egui::RichText::new("File sharing").strong());
    if let Some(share) = conn.admin_share_info() {
        let used = share.total_bytes.saturating_sub(share.available_bytes);
        egui::Grid::new(format!("admin_share_grid:{key}"))
            .num_columns(2)
            .spacing([8.0, 4.0])
            .show(ui, |ui| {
                ui.label("Directory:");
                ui.label(egui::RichText::new(&share.path).monospace());
                ui.end_row();
                ui.label("Disk used:");
                ui.label(format!(
                    "{} of {}",
                    human_size(used),
                    human_size(share.total_bytes)
                ));
                ui.end_row();
                ui.label("Disk free:");
                ui.label(human_size(share.available_bytes));
                ui.end_row();
            });
    } else {
        ui.label(egui::RichText::new("Not sharing a directory.").weak());
    }

    // ── Editable server limits ────────────────────────────────────────────
    limits_editor(ui, conn, key);

    ui.data_mut(|d| {
        d.insert_temp(name_id, server_name);
        d.insert_temp(desc_id, server_desc);
    });
}

/// The editable "Limits" section: set, change, or remove the maximum upload
/// size and the maximum concurrent connection count.
#[allow(clippy::too_many_lines)]
fn limits_editor(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    ui.separator();
    ui.label(egui::RichText::new("Limits").strong());

    let cap_upload_id = egui::Id::new(format!("admin_cap_upload:{key}"));
    let upload_val_id = egui::Id::new(format!("admin_upload_val:{key}"));
    let cap_conns_id = egui::Id::new(format!("admin_cap_conns:{key}"));
    let conns_val_id = egui::Id::new(format!("admin_conns_val:{key}"));
    let seeded_id = egui::Id::new(format!("admin_limits_seeded:{key}"));

    let mut cap_upload: bool = ui.data(|d| d.get_temp(cap_upload_id).unwrap_or(false));
    let mut upload_val: String = ui.data(|d| d.get_temp(upload_val_id).unwrap_or_default());
    let mut cap_conns: bool = ui.data(|d| d.get_temp(cap_conns_id).unwrap_or(false));
    let mut conns_val: String = ui.data(|d| d.get_temp(conns_val_id).unwrap_or_default());

    // Seed the form once from the server's reported limits (re-seeds after a
    // save, which clears the flag).
    let seeded: bool = ui.data(|d| d.get_temp(seeded_id).unwrap_or(false));
    if !seeded && let Some(limits) = conn.admin_limits() {
        cap_upload = limits.max_upload_size.is_some();
        upload_val = limits
            .max_upload_size
            .map_or_else(String::new, |v| v.to_string());
        cap_conns = limits.max_connections.is_some();
        conns_val = limits
            .max_connections
            .map_or_else(String::new, |v| v.to_string());
        ui.data_mut(|d| d.insert_temp(seeded_id, true));
    }

    egui::Grid::new(format!("admin_limits_grid:{key}"))
        .num_columns(2)
        .spacing([8.0, 6.0])
        .show(ui, |ui| {
            ui.label("Max upload size:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut cap_upload, "")
                    .on_hover_text("Cap the size of uploaded files");
                ui.add_enabled(
                    cap_upload,
                    egui::TextEdit::singleline(&mut upload_val)
                        .desired_width(120.0)
                        .hint_text("bytes"),
                );
                if cap_upload && let Ok(bytes) = upload_val.trim().parse::<u64>() {
                    ui.label(egui::RichText::new(human_size(bytes)).weak().small());
                }
            });
            ui.end_row();

            ui.label("Max connections:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut cap_conns, "")
                    .on_hover_text("Limit the number of concurrent connections");
                ui.add_enabled(
                    cap_conns,
                    egui::TextEdit::singleline(&mut conns_val).desired_width(80.0),
                );
            });
            ui.end_row();
        });

    // Only allow saving when enabled fields parse; unchecking removes the limit.
    let upload_ok = !cap_upload || upload_val.trim().parse::<u64>().is_ok();
    let conns_ok = !cap_conns || conns_val.trim().parse::<u16>().is_ok();
    if ui
        .add_enabled(upload_ok && conns_ok, egui::Button::new("Save limits"))
        .clicked()
    {
        let max_upload = cap_upload
            .then(|| upload_val.trim().parse::<u64>().ok())
            .flatten();
        let max_conns = cap_conns
            .then(|| conns_val.trim().parse::<u16>().ok())
            .flatten();
        let conn = conn.clone();
        tokio::spawn(async move {
            let _ = conn.admin_set_max_upload_size(max_upload).await;
            let _ = conn.admin_set_max_connections(max_conns).await;
            let _ = conn.admin_get_server_limits().await;
        });
        // Re-seed from the confirmed values on the next frames.
        ui.data_mut(|d| d.insert_temp(seeded_id, false));
    }

    ui.data_mut(|d| {
        d.insert_temp(cap_upload_id, cap_upload);
        d.insert_temp(upload_val_id, upload_val);
        d.insert_temp(cap_conns_id, cap_conns);
        d.insert_temp(conns_val_id, conns_val);
    });
}

/// A human-readable byte size.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)]
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}
