// SPDX-License-Identifier: Apache-2.0

//! Server settings tab: edit the server's name and description.

use crate::conn::ConclaveConnection;

use eframe::egui;

/// Render the server-settings tab.
pub fn ui(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    let info = conn.server_info();

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

    ui.data_mut(|d| {
        d.insert_temp(name_id, server_name);
        d.insert_temp(desc_id, server_desc);
    });
}
