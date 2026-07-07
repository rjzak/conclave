// SPDX-License-Identifier: Apache-2.0

//! Groups tab: create, edit, and delete groups, including their colour. A
//! member's name is tinted a mix of their groups' colours; red is reserved for
//! the built-in admin group.

use crate::conn::ConclaveConnection;
use conclave_common::admin::server::is_reserved_red;
use eframe::egui;

/// Render the groups-administration tab.
#[allow(clippy::too_many_lines)]
pub fn ui(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    let groups = conn.admin_groups();

    let name_id = egui::Id::new(format!("admin_gn:{key}"));
    let desc_id = egui::Id::new(format!("admin_gd:{key}"));
    let colored_id = egui::Id::new(format!("admin_gcol:{key}"));
    let color_id = egui::Id::new(format!("admin_gc:{key}"));
    let edit_id = egui::Id::new(format!("admin_ge:{key}"));
    let mut name: String = ui.data(|d| d.get_temp(name_id).unwrap_or_default());
    let mut desc: String = ui.data(|d| d.get_temp(desc_id).unwrap_or_default());
    let mut colored: bool = ui.data(|d| d.get_temp(colored_id).unwrap_or(false));
    let mut color: [u8; 3] = ui.data(|d| d.get_temp(color_id).unwrap_or([120, 120, 200]));
    let mut edit: Option<u32> = ui.data(|d| d.get_temp::<Option<u32>>(edit_id)).flatten();

    // Actions flagged during rendering and performed afterwards.
    let mut save = false;
    let mut delete: Option<u32> = None;
    let mut edit_load: Option<u32> = None;
    let mut cancel = false;

    // ── Existing groups ───────────────────────────────────────────────────
    for group in &groups {
        ui.horizontal(|ui| {
            // Show the name in the group's colour as a preview.
            let mut label = egui::RichText::new(&group.name).strong();
            if let Some([r, g, b]) = group.color {
                label = label.color(egui::Color32::from_rgb(r, g, b));
            }
            ui.label(label);
            if let Some(d) = &group.description {
                ui.label(egui::RichText::new(d).weak());
            }
            if group.color.is_none() {
                ui.label(egui::RichText::new("(no colour)").weak().small());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // The built-in admin group (id 0) cannot be deleted.
                if group.id != 0 && ui.small_button("Delete").clicked() {
                    delete = Some(group.id);
                }
                if ui.small_button("Edit").clicked() {
                    edit_load = Some(group.id);
                }
            });
        });
    }

    ui.separator();
    // ── Create / edit form ────────────────────────────────────────────────
    let editing_admin = edit == Some(0);
    ui.label(
        egui::RichText::new(if edit.is_some() {
            "Edit group"
        } else {
            "New group"
        })
        .strong(),
    );
    egui::Grid::new(format!("admin_group_form:{key}"))
        .num_columns(2)
        .spacing([8.0, 6.0])
        .show(ui, |ui| {
            ui.label("Name:");
            // The admin group's name is fixed.
            ui.add_enabled(!editing_admin, egui::TextEdit::singleline(&mut name));
            ui.end_row();
            ui.label("Description:");
            ui.text_edit_singleline(&mut desc);
            ui.end_row();
            ui.label("Colour:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut colored, "");
                if colored {
                    ui.color_edit_button_srgb(&mut color);
                }
            });
            ui.end_row();
        });

    // Red is reserved for the admin group.
    let red_conflict = colored && !editing_admin && is_reserved_red(color);
    if red_conflict {
        ui.colored_label(
            egui::Color32::from_rgb(0xff, 0xa5, 0x00),
            "Red is reserved for the admin group; pick another colour.",
        );
    }

    ui.horizontal(|ui| {
        let can = !name.trim().is_empty() && !red_conflict;
        let label = if edit.is_some() { "Save" } else { "Create" };
        if ui.add_enabled(can, egui::Button::new(label)).clicked() {
            save = true;
        }
        if edit.is_some() && ui.button("Cancel").clicked() {
            cancel = true;
        }
    });

    // ── Perform queued actions ────────────────────────────────────────────
    if let Some(id) = edit_load
        && let Some(group) = groups.iter().find(|g| g.id == id)
    {
        name.clone_from(&group.name);
        desc = group.description.clone().unwrap_or_default();
        colored = group.color.is_some();
        if let Some(existing) = group.color {
            color = existing;
        }
        edit = Some(id);
    }
    if cancel {
        name.clear();
        desc.clear();
        colored = false;
        edit = None;
    }
    if save {
        let conn = conn.clone();
        let group_name = std::mem::take(&mut name);
        let description = (!desc.trim().is_empty()).then(|| std::mem::take(&mut desc));
        let chosen = colored.then_some(color);
        let editing = edit;
        colored = false;
        edit = None;
        tokio::spawn(async move {
            if let Some(id) = editing {
                let _ = conn
                    .admin_edit_group(id, group_name, description, chosen)
                    .await;
            } else {
                let _ = conn
                    .admin_create_group(group_name, description, chosen)
                    .await;
            }
            let _ = conn.admin_list_groups().await;
        });
    }
    if let Some(id) = delete {
        let conn = conn.clone();
        if edit == Some(id) {
            name.clear();
            desc.clear();
            colored = false;
            edit = None;
        }
        tokio::spawn(async move {
            let _ = conn.admin_delete_group(id).await;
            let _ = conn.admin_list_groups().await;
        });
    }

    ui.data_mut(|d| {
        d.insert_temp(name_id, name);
        d.insert_temp(desc_id, desc);
        d.insert_temp(colored_id, colored);
        d.insert_temp(color_id, color);
        d.insert_temp(edit_id, edit);
    });
}
