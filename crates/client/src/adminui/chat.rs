// SPDX-License-Identifier: Apache-2.0

//! Chat tab: enable/disable chat and manage chatrooms and their group
//! restrictions.

use std::collections::HashSet;

use crate::conn::ConclaveConnection;
use eframe::egui;

/// Render the chat-administration tab.
#[allow(clippy::too_many_lines)]
pub fn ui(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    let info = conn.server_info();
    let chatrooms = conn.admin_chatrooms();
    let groups = conn.admin_groups();

    let name_id = egui::Id::new(format!("admin_cn:{key}"));
    let groups_id = egui::Id::new(format!("admin_cg:{key}"));
    let edit_id = egui::Id::new(format!("admin_ce:{key}"));
    let mut chat_name: String = ui.data(|d| d.get_temp(name_id).unwrap_or_default());
    let mut chat_groups: HashSet<u32> = ui.data(|d| d.get_temp(groups_id).unwrap_or_default());
    let mut chat_edit: Option<u32> = ui.data(|d| d.get_temp::<Option<u32>>(edit_id)).flatten();

    // Actions are flagged during rendering and performed afterwards.
    let mut chat_toggle: Option<bool> = None;
    let mut chat_save = false;
    let mut chat_delete: Option<u32> = None;
    let mut chat_edit_load: Option<u32> = None;
    let mut chat_cancel = false;

    let mut enabled = info.chat_enabled;
    if ui.checkbox(&mut enabled, "Enable chat").changed() {
        chat_toggle = Some(enabled);
    }
    ui.separator();

    // ── Existing chatrooms ────────────────────────────────────────────────
    for room in &chatrooms {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(&room.name).strong());
            // Show which groups it is restricted to.
            let restriction = if room.groups.is_empty() {
                "everyone".to_string()
            } else {
                room.groups
                    .iter()
                    .map(|gid| {
                        groups
                            .iter()
                            .find(|g| g.id == *gid)
                            .map_or_else(|| format!("#{gid}"), |g| g.name.clone())
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            ui.label(egui::RichText::new(format!("({restriction})")).weak());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // The Public room (id 0) can't be deleted.
                if room.id != 0 && ui.small_button("Delete").clicked() {
                    chat_delete = Some(room.id);
                }
                if ui.small_button("Edit").clicked() {
                    chat_edit_load = Some(room.id);
                }
            });
        });
    }

    ui.separator();
    // ── Create / edit form ────────────────────────────────────────────────
    ui.label(
        egui::RichText::new(if chat_edit.is_some() {
            "Edit chatroom"
        } else {
            "New chatroom"
        })
        .strong(),
    );
    ui.horizontal(|ui| {
        ui.label("Name:");
        ui.text_edit_singleline(&mut chat_name);
    });
    if groups.is_empty() {
        ui.label(egui::RichText::new("No groups to restrict to.").weak());
    } else {
        ui.horizontal_wrapped(|ui| {
            ui.label("Restrict to groups:");
            for g in &groups {
                let mut on = chat_groups.contains(&g.id);
                if ui.checkbox(&mut on, &g.name).changed() {
                    if on {
                        chat_groups.insert(g.id);
                    } else {
                        chat_groups.remove(&g.id);
                    }
                }
            }
        });
        ui.label(
            egui::RichText::new("No groups selected means open to everyone.")
                .weak()
                .small(),
        );
    }
    ui.horizontal(|ui| {
        let can = !chat_name.trim().is_empty();
        let label = if chat_edit.is_some() {
            "Save"
        } else {
            "Create"
        };
        if ui.add_enabled(can, egui::Button::new(label)).clicked() {
            chat_save = true;
        }
        if chat_edit.is_some() && ui.button("Cancel").clicked() {
            chat_cancel = true;
        }
    });

    // ── Perform queued actions ────────────────────────────────────────────
    if let Some(enabled) = chat_toggle {
        let conn = conn.clone();
        tokio::spawn(async move {
            let _ = conn.admin_set_chat_enabled(enabled).await;
        });
    }
    // Load an existing room into the edit form.
    if let Some(id) = chat_edit_load
        && let Some(room) = chatrooms.iter().find(|r| r.id == id)
    {
        chat_name.clone_from(&room.name);
        chat_groups = room.groups.iter().copied().collect();
        chat_edit = Some(id);
    }
    if chat_cancel {
        chat_name.clear();
        chat_groups.clear();
        chat_edit = None;
    }
    if chat_save {
        let conn = conn.clone();
        let name = std::mem::take(&mut chat_name);
        let selected: Vec<u32> = chat_groups.iter().copied().collect();
        let edit = chat_edit;
        chat_groups.clear();
        chat_edit = None;
        tokio::spawn(async move {
            if let Some(id) = edit {
                let _ = conn.admin_edit_chatroom(id, name, selected).await;
            } else {
                let _ = conn.admin_create_chatroom(name, selected).await;
            }
            let _ = conn.admin_list_chatrooms().await;
        });
    }
    if let Some(id) = chat_delete {
        let conn = conn.clone();
        if chat_edit == Some(id) {
            chat_name.clear();
            chat_groups.clear();
            chat_edit = None;
        }
        tokio::spawn(async move {
            let _ = conn.admin_delete_chatroom(id).await;
            let _ = conn.admin_list_chatrooms().await;
        });
    }

    ui.data_mut(|d| {
        d.insert_temp(name_id, chat_name);
        d.insert_temp(groups_id, chat_groups);
        d.insert_temp(edit_id, chat_edit);
    });
}
