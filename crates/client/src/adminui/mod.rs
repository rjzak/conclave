// SPDX-License-Identifier: Apache-2.0

//! The per-server administration window, split into one tab per area of
//! administration. [`admin_ui`] renders the tab bar and dispatches to the
//! relevant tab module; each submodule owns the UI and actions for its area so
//! new areas can be added without growing a single giant function or file.

mod chat;
mod server;
mod trackers;
mod users;

use crate::conn::ConclaveConnection;
use eframe::egui;

/// The areas of administration, one per tab.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AdminTab {
    /// Server name and description.
    #[default]
    Server,

    /// User accounts and group memberships.
    Users,

    /// Configured trackers.
    Trackers,

    /// Chat enablement and chatrooms.
    Chat,
}

impl AdminTab {
    /// All tabs in display order.
    const ALL: [Self; 4] = [Self::Server, Self::Users, Self::Trackers, Self::Chat];

    /// The tab's label for the tab bar.
    const fn title(self) -> &'static str {
        match self {
            Self::Server => "Server",
            Self::Users => "Users",
            Self::Trackers => "Trackers",
            Self::Chat => "Chat",
        }
    }
}

/// Re-request every administered list. Called when the window opens and on
/// Refresh so newly opened tabs have current data.
fn refresh_all(conn: &ConclaveConnection) {
    let conn = conn.clone();
    tokio::spawn(async move {
        let _ = conn.admin_list_users().await;
        let _ = conn.admin_list_groups().await;
        let _ = conn.admin_list_trackers().await;
        let _ = conn.admin_list_chatrooms().await;
    });
}

/// Render the administration window for `conn`. `key` is a per-server id used to
/// namespace the window's egui temp state (form fields, selected tab).
pub fn admin_ui(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str) {
    // Load the administered lists once when the window first opens.
    let loaded_id = egui::Id::new(format!("admin_loaded:{key}"));
    if !ui.data(|d| d.get_temp::<bool>(loaded_id).unwrap_or(false)) {
        ui.data_mut(|d| d.insert_temp(loaded_id, true));
        refresh_all(conn);
    }

    let info = conn.server_info();
    let admin_error = conn.admin_error();

    let tab_id = egui::Id::new(format!("admin_tab:{key}"));
    let mut tab: AdminTab = ui.data(|d| d.get_temp(tab_id).unwrap_or_default());

    egui::CentralPanel::default().show(ui, |ui| {
        ui.heading(format!("Administer {}", info.name));
        if let Some(err) = &admin_error {
            ui.colored_label(egui::Color32::RED, err);
        }
        ui.separator();

        ui.horizontal(|ui| {
            for candidate in AdminTab::ALL {
                ui.selectable_value(&mut tab, candidate, candidate.title());
            }
        });
        ui.separator();

        match tab {
            AdminTab::Server => server::ui(ui, conn, key),
            AdminTab::Users => users::ui(ui, conn, key),
            AdminTab::Trackers => trackers::ui(ui, conn, key),
            AdminTab::Chat => chat::ui(ui, conn, key),
        }

        ui.separator();
        if ui.button("Refresh").clicked() {
            refresh_all(conn);
        }
    });

    ui.data_mut(|d| d.insert_temp(tab_id, tab));
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_secs(2));
}
