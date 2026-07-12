// SPDX-License-Identifier: Apache-2.0

//! Forums tab: enable/disable forums and manage topics and their group
//! restrictions.

use std::collections::HashSet;

use crate::conn::ConclaveConnection;
use eframe::egui;

/// Render the forum-administration tab.
#[allow(clippy::too_many_lines)]
pub fn ui(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    let info = conn.server_info();
    let topics = conn.admin_forum_topics();
    let groups = conn.admin_groups();

    let name_id = egui::Id::new(format!("admin_fn:{key}"));
    let desc_id = egui::Id::new(format!("admin_fd:{key}"));
    let groups_id = egui::Id::new(format!("admin_fg:{key}"));
    let edit_id = egui::Id::new(format!("admin_fe:{key}"));
    let mut topic_name: String = ui.data(|d| d.get_temp(name_id).unwrap_or_default());
    let mut topic_desc: String = ui.data(|d| d.get_temp(desc_id).unwrap_or_default());
    let mut topic_groups: HashSet<u32> = ui.data(|d| d.get_temp(groups_id).unwrap_or_default());
    let mut topic_edit: Option<u32> = ui.data(|d| d.get_temp::<Option<u32>>(edit_id)).flatten();

    // Actions are flagged during rendering and performed afterwards.
    let mut forums_toggle: Option<bool> = None;
    let mut topic_save = false;
    let mut topic_delete: Option<u32> = None;
    let mut topic_edit_load: Option<u32> = None;
    let mut topic_cancel = false;

    let mut enabled = info.forums_enabled;
    if ui.checkbox(&mut enabled, "Enable forums").changed() {
        forums_toggle = Some(enabled);
    }
    ui.separator();

    // ── Existing topics ───────────────────────────────────────────────────
    for topic in &topics {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(&topic.name).strong());
            let restriction = if topic.groups.is_empty() {
                "everyone".to_string()
            } else {
                topic
                    .groups
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
                if ui.small_button("Delete").clicked() {
                    topic_delete = Some(topic.id);
                }
                if ui.small_button("Edit").clicked() {
                    topic_edit_load = Some(topic.id);
                }
            });
        });
        if !topic.description.is_empty() {
            ui.label(egui::RichText::new(&topic.description).weak().small());
        }
    }

    ui.separator();
    // ── Create / edit form ────────────────────────────────────────────────
    ui.label(
        egui::RichText::new(if topic_edit.is_some() {
            "Edit topic"
        } else {
            "New topic"
        })
        .strong(),
    );
    ui.horizontal(|ui| {
        ui.label("Name:");
        ui.text_edit_singleline(&mut topic_name);
    });
    ui.horizontal(|ui| {
        ui.label("Description:");
        ui.text_edit_singleline(&mut topic_desc);
    });
    if groups.is_empty() {
        ui.label(egui::RichText::new("No groups to restrict to.").weak());
    } else {
        ui.horizontal_wrapped(|ui| {
            ui.label("Restrict to groups:");
            for g in &groups {
                let mut on = topic_groups.contains(&g.id);
                if ui.checkbox(&mut on, &g.name).changed() {
                    if on {
                        topic_groups.insert(g.id);
                    } else {
                        topic_groups.remove(&g.id);
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
        let can = !topic_name.trim().is_empty();
        let label = if topic_edit.is_some() {
            "Save"
        } else {
            "Create"
        };
        if ui.add_enabled(can, egui::Button::new(label)).clicked() {
            topic_save = true;
        }
        if topic_edit.is_some() && ui.button("Cancel").clicked() {
            topic_cancel = true;
        }
    });

    // ── Perform queued actions ────────────────────────────────────────────
    if let Some(enabled) = forums_toggle {
        let conn = conn.clone();
        tokio::spawn(async move {
            let _ = conn.admin_set_forums_enabled(enabled).await;
        });
    }
    if let Some(id) = topic_edit_load
        && let Some(topic) = topics.iter().find(|t| t.id == id)
    {
        topic_name.clone_from(&topic.name);
        topic_desc.clone_from(&topic.description);
        topic_groups = topic.groups.iter().copied().collect();
        topic_edit = Some(id);
    }
    if topic_cancel {
        topic_name.clear();
        topic_desc.clear();
        topic_groups.clear();
        topic_edit = None;
    }
    if topic_save {
        let conn = conn.clone();
        let name = std::mem::take(&mut topic_name);
        let description = std::mem::take(&mut topic_desc);
        let selected: Vec<u32> = topic_groups.iter().copied().collect();
        let edit = topic_edit;
        topic_groups.clear();
        topic_edit = None;
        tokio::spawn(async move {
            if let Some(id) = edit {
                let _ = conn
                    .admin_edit_forum_topic(id, name, description, selected)
                    .await;
            } else {
                let _ = conn
                    .admin_create_forum_topic(name, description, selected)
                    .await;
            }
            let _ = conn.admin_list_forum_topics().await;
        });
    }
    if let Some(id) = topic_delete {
        let conn = conn.clone();
        if topic_edit == Some(id) {
            topic_name.clear();
            topic_desc.clear();
            topic_groups.clear();
            topic_edit = None;
        }
        tokio::spawn(async move {
            let _ = conn.admin_delete_forum_topic(id).await;
            let _ = conn.admin_list_forum_topics().await;
        });
    }

    ui.data_mut(|d| {
        d.insert_temp(name_id, topic_name);
        d.insert_temp(desc_id, topic_desc);
        d.insert_temp(groups_id, topic_groups);
        d.insert_temp(edit_id, topic_edit);
    });
}
