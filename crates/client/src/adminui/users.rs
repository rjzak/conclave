// SPDX-License-Identifier: Apache-2.0

//! User accounts tab: create accounts, delete them, and manage group
//! memberships.

use std::collections::HashSet;

use crate::conn::ConclaveConnection;

use eframe::egui;

/// Render the user-accounts tab.
#[allow(clippy::too_many_lines)]
pub fn ui(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    let users = conn.admin_users();
    let groups = conn.admin_groups();

    let new_user_id = egui::Id::new(format!("admin_nu:{key}"));
    let new_pass_id = egui::Id::new(format!("admin_np:{key}"));
    let new_groups_id = egui::Id::new(format!("admin_ng:{key}"));
    let mut new_user: String = ui.data(|d| d.get_temp(new_user_id).unwrap_or_default());
    let mut new_pass: String = ui.data(|d| d.get_temp(new_pass_id).unwrap_or_default());
    let mut new_groups: HashSet<String> =
        ui.data(|d| d.get_temp(new_groups_id).unwrap_or_default());

    // Actions are flagged during rendering and performed afterwards.
    let mut create_user = false;
    let mut delete_user: Option<u32> = None;
    // (uid, gid, add?) membership toggles queued this frame.
    let mut group_changes: Vec<(u32, u32, bool)> = Vec::new();

    // ── Create a new account ──────────────────────────────────────────────
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

    // ── Existing accounts ─────────────────────────────────────────────────
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
            .id_salt(format!("admin_user:{key}:{}", u.id))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(if u.enabled { "Enabled" } else { "Disabled" });
                    // The built-in admin (id 0) cannot be deleted.
                    if u.id != 0 && ui.small_button("Delete").clicked() {
                        delete_user = Some(u.id);
                    }
                });
                if groups.is_empty() {
                    ui.label(egui::RichText::new("No groups available.").weak());
                } else {
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Groups:");
                        for g in &groups {
                            let mut member = u.groups.contains(&g.name);
                            // The built-in admin can't leave admin.
                            let locked = u.id == 0 && g.name == "admin";
                            let mut check =
                                ui.add_enabled(!locked, egui::Checkbox::new(&mut member, &g.name));
                            if let Some(desc) = &g.description {
                                check = check.on_hover_text(desc);
                            }
                            if check.changed() {
                                group_changes.push((u.id, g.id, member));
                            }
                        }
                    });
                }
            });
    }

    // ── Perform queued actions ────────────────────────────────────────────
    if create_user {
        let conn = conn.clone();
        let (username, password) = (new_user.clone(), new_pass.clone());
        let selected: Vec<String> = new_groups.iter().cloned().collect();
        new_user.clear();
        new_pass.clear();
        new_groups.clear();
        tokio::spawn(async move {
            let _ = conn.admin_create_user(username, password, selected).await;
            let _ = conn.admin_list_users().await;
        });
    }
    if let Some(uid) = delete_user {
        let conn = conn.clone();
        tokio::spawn(async move {
            let _ = conn.admin_delete_user(uid).await;
            let _ = conn.admin_list_users().await;
        });
    }
    for (uid, gid, add) in group_changes {
        let conn = conn.clone();
        tokio::spawn(async move {
            if add {
                let _ = conn.admin_add_user_to_group(uid, gid).await;
            } else {
                let _ = conn.admin_remove_user_from_group(uid, gid).await;
            }
            let _ = conn.admin_list_users().await;
        });
    }

    ui.data_mut(|d| {
        d.insert_temp(new_user_id, new_user);
        d.insert_temp(new_pass_id, new_pass);
        d.insert_temp(new_groups_id, new_groups);
    });
}
