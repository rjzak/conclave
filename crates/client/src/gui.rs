// SPDX-License-Identifier: Apache-2.0

use conclave_client::config::{BookmarkEntry, KnownHost, UserAuth};
use conclave_client::conn::{ChatLine, ConclaveConnection};
use conclave_client::{Client, DiscoveredServer, discover_servers};
use conclave_common::forum::ForumPost;
use conclave_common::server::{
    ChatroomInfo, ConnectedUser, IDLE_TIMEOUT_MINUTES, UserAuthentication, VerifyingKey,
};
use conclave_common::tracker::{Advertise, Tracker, TrackerWithKey};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use eframe::{Frame, egui};
use sha2::{Digest, Sha256};
use tracing::error;

/// A per-frame snapshot of one active connection: (window key, display
/// label, still-connected flag, connection handle).
type ConnSnapshot = (String, String, bool, ConclaveConnection);

/// Logical (point) size of the main launcher window, and its intended aspect
/// ratio. The window is fixed and non-resizable; on the first frame
/// [`ConclaveGUI::fit_main_window`] scales this down to fit the monitor while
/// preserving the aspect ratio, so it stays proportional on small displays or
/// where the scale factor is mis-reported (e.g. KDE under X11, where the fixed
/// logical size could otherwise render as a huge window).
pub const MAIN_WINDOW_SIZE: [f32; 2] = [460.0, 200.0];

/// The main window is never allowed to occupy more than this fraction of the
/// monitor in either dimension.
const MAIN_WINDOW_MAX_SCREEN_FRACTION: f32 = 0.9;

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

fn format_uptime(d: chrono::Duration) -> String {
    let d = if d.num_seconds() < 0 {
        chrono::Duration::zero()
    } else {
        d
    };
    let hours = d.num_hours();
    let mins = d.num_minutes() % 60;
    let secs = d.num_seconds() % 60;
    if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

/// Whether a user counts as idle (inactive for longer than the timeout), in
/// which case their name is shown dulled.
#[inline]
fn is_idle(idle: chrono::Duration) -> bool {
    idle >= IDLE_TIMEOUT_MINUTES
}

/// Save a downloaded file under a `conclave-downloads` folder in the current
/// directory, returning the path written.
fn save_download(name: &str, data: &[u8]) -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::current_dir()
        .unwrap_or_default()
        .join("conclave-downloads");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    std::fs::write(&path, data)?;
    Ok(path)
}

/// Toggleable List/Download checkboxes for one principal in the ACL grid.
/// Returns whether anything changed.
fn acl_row(
    ui: &mut egui::Ui,
    label: &str,
    perms: &mut Vec<conclave_common::files::FilePermission>,
) {
    ui.label(label);
    for perm in conclave_common::files::FilePermission::ALL {
        let mut has = perms.contains(&perm);
        if ui.checkbox(&mut has, "").changed() {
            if has {
                perms.push(perm);
            } else {
                perms.retain(|held| *held != perm);
            }
        }
    }
}

/// Collapsible upload panel. Reads a local file and uploads it to a destination
/// folder on the server (which enforces the Write permission).
fn file_upload_panel(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str, path: &str) {
    let local_id = egui::Id::new(format!("file_upload_local:{key}"));
    let dest_id = egui::Id::new(format!("file_upload_dest:{key}"));
    let dest_seed_id = egui::Id::new(format!("file_upload_dest_seed:{key}"));

    // Default the destination to the folder currently open; reseed on navigation.
    let seeded: String = ui.data(|d| d.get_temp(dest_seed_id).unwrap_or_default());
    if seeded != path {
        ui.data_mut(|d| {
            d.insert_temp(dest_id, path.to_string());
            d.insert_temp(dest_seed_id, path.to_string());
        });
    }
    let mut local: String = ui.data(|d| d.get_temp(local_id).unwrap_or_default());
    let mut dest: String = ui.data(|d| d.get_temp(dest_id).unwrap_or_default());

    ui.collapsing("Upload", |ui| {
        egui::Grid::new(format!("upload_grid:{key}"))
            .num_columns(2)
            .show(ui, |ui| {
                ui.label("Local file:");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut local);
                    if ui.button("Browse…").clicked()
                        && let Some(picked) = rfd::FileDialog::new().pick_file()
                    {
                        local = picked.display().to_string();
                    }
                });
                ui.end_row();
                ui.label("Destination folder:");
                ui.text_edit_singleline(&mut dest);
                ui.end_row();
            });

        if ui
            .add_enabled(!local.trim().is_empty(), egui::Button::new("⬆ Upload"))
            .on_hover_text("Upload the selected file")
            .clicked()
        {
            match std::fs::read(local.trim()) {
                Ok(data) => {
                    let name = std::path::Path::new(local.trim()).file_name().map_or_else(
                        || "upload".to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    );
                    let target = if dest.trim().is_empty() {
                        name
                    } else {
                        format!("{}/{name}", dest.trim().trim_matches('/'))
                    };
                    let c = conn.clone();
                    tokio::spawn(async move {
                        let _ = c.upload_file(target, data).await;
                    });
                }
                Err(e) => {
                    conn.set_file_notice(format!("Cannot read {}: {e}", local.trim()));
                }
            }
        }

        if let Some(notice) = conn.file_notice() {
            ui.label(egui::RichText::new(notice).weak());
        }
    });

    ui.data_mut(|d| {
        d.insert_temp(local_id, local);
        d.insert_temp(dest_id, dest);
    });
}

/// Admin sub-panel to view and edit the ACL of the current shared directory.
fn file_acl_editor(ui: &mut egui::Ui, conn: &ConclaveConnection, key: &str, path: &str) {
    use conclave_common::files::DirAcl;

    let edit_id = egui::Id::new(format!("file_acl_edit:{key}"));
    let seeded_id = egui::Id::new(format!("file_acl_seeded:{key}"));

    ui.collapsing("Permissions (admin)", |ui| {
        if ui.button("Load / refresh").clicked() {
            let c = conn.clone();
            let p = path.to_string();
            tokio::spawn(async move {
                let _ = c.admin_list_groups().await;
                let _ = c.admin_get_file_acl(p).await;
            });
            // A sentinel that no real path equals, forcing the reply to reseed.
            ui.data_mut(|d| d.insert_temp(seeded_id, "\u{0}".to_string()));
        }

        // Seed the editor when the ACL for this path arrives.
        let seeded: String = ui.data(|d| d.get_temp(seeded_id).unwrap_or_default());
        if seeded != path
            && let Some((loaded_path, acl)) = conn.file_acl()
            && loaded_path == path
        {
            ui.data_mut(|d| {
                d.insert_temp(edit_id, acl);
                d.insert_temp(seeded_id, path.to_string());
            });
        }

        let current_seed: String = ui.data(|d| d.get_temp(seeded_id).unwrap_or_default());
        let Some(mut acl): Option<DirAcl> = ui.data(|d| d.get_temp(edit_id)) else {
            ui.label(egui::RichText::new("Load to view or edit permissions.").weak());
            return;
        };
        if current_seed != path {
            ui.label(egui::RichText::new("Load to view or edit permissions.").weak());
            return;
        }

        egui::Grid::new(format!("acl_grid:{key}"))
            .num_columns(1 + conclave_common::files::FilePermission::ALL.len())
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Principal").strong());
                for perm in conclave_common::files::FilePermission::ALL {
                    ui.label(egui::RichText::new(perm.label()).strong());
                }
                ui.end_row();

                acl_row(ui, "guests (anyone)", &mut acl.guests);
                ui.end_row();

                for group in conn.admin_groups() {
                    let perms = acl.groups.entry(group.name.clone()).or_default();
                    acl_row(ui, &group.name, perms);
                    ui.end_row();
                }
            });
        // Keep the stored ACL tidy: drop groups with no permissions.
        acl.groups.retain(|_, perms| !perms.is_empty());

        if ui.button("Save").clicked() {
            let c = conn.clone();
            let p = path.to_string();
            let to_save = acl.clone();
            tokio::spawn(async move {
                let _ = c.admin_set_file_acl(p, to_save).await;
            });
        }

        ui.data_mut(|d| d.insert_temp(edit_id, acl));
    });
}

/// A human-readable byte size.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "XiB"];

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

/// The base name colour for a user: the mix of their groups' colours, falling
/// back to red for administrators with no colour of their own.
fn base_name_color(user: &ConnectedUser) -> Option<egui::Color32> {
    user.color
        .map(|[r, g, b]| egui::Color32::from_rgb(r, g, b))
        .or_else(|| user.admin.then_some(egui::Color32::RED))
}

/// A muted version of a colour: shifted toward its own grey so an idle user's
/// name dims without becoming a flat grey.
fn dull(color: egui::Color32) -> egui::Color32 {
    let (r, g, b) = (
        u16::from(color.r()),
        u16::from(color.g()),
        u16::from(color.b()),
    );
    let lum = (r * 3 + g * 6 + b) / 10; // approximate luminance
    // 40% of the original colour, 60% of its luminance grey.
    let mix = |c: u16| u8::try_from((c * 2 + lum * 3) / 5).unwrap_or(u8::MAX);
    egui::Color32::from_rgb(mix(r), mix(g), mix(b))
}

/// Style a name with its colour and idle state: idle colours are dulled, and an
/// idle user with no colour is greyed.
fn styled_name(text: &str, color: Option<egui::Color32>, idle: bool) -> egui::RichText {
    let text = egui::RichText::new(text);
    match (color, idle) {
        (Some(c), true) => text.color(dull(c)),
        (Some(c), false) => text.color(c),
        (None, true) => text.color(egui::Color32::GRAY),
        (None, false) => text,
    }
}

/// Decode an avatar PNG into an egui texture, caching it in the context's data
/// store keyed by content hash so each distinct avatar is decoded and uploaded
/// only once. Returns `None` if the bytes cannot be decoded.
fn avatar_texture(ctx: &egui::Context, png: &[u8]) -> Option<egui::TextureHandle> {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    png.hash(&mut hasher);
    let hash = hasher.finish();
    let id = egui::Id::new(("avatar_tex", hash));

    if let Some(texture) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return Some(texture);
    }

    let (rgba, edge) = conclave_client::avatar::decode_rgba(png).ok()?;
    let image = egui::ColorImage::from_rgba_unmultiplied([edge, edge], &rgba);
    let texture = ctx.load_texture(
        format!("avatar_{hash:x}"),
        image,
        egui::TextureOptions::LINEAR,
    );
    ctx.data_mut(|d| d.insert_temp(id, texture.clone()));
    Some(texture)
}

/// Decode a banner PNG into an egui texture, caching it by content hash (like
/// [`avatar_texture`] but for non-square images).
fn banner_texture(ctx: &egui::Context, png: &[u8]) -> Option<egui::TextureHandle> {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    png.hash(&mut hasher);
    let hash = hasher.finish();
    let id = egui::Id::new(("banner_tex", hash));

    if let Some(texture) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return Some(texture);
    }

    let (rgba, width, height) = conclave_client::avatar::decode_rgba_dims(png).ok()?;
    let image = egui::ColorImage::from_rgba_unmultiplied([width, height], &rgba);
    let texture = ctx.load_texture(
        format!("banner_{hash:x}"),
        image,
        egui::TextureOptions::LINEAR,
    );
    ctx.data_mut(|d| d.insert_temp(id, texture.clone()));
    Some(texture)
}

/// Draw the active server's banner across the top of the main window. Banners
/// are a fixed 512×128 (4:1) image, shown filling the window width at that ratio
/// — so it is never distorted and is consistent across servers. With no banner,
/// a plain "Conclave" placeholder is shown instead.
fn render_banner(ui: &mut egui::Ui, banner: Option<&[u8]>) {
    if let Some(bytes) = banner
        && let Some(texture) = banner_texture(ui.ctx(), bytes)
    {
        // Height follows the banner's fixed aspect ratio, so filling the width
        // scales it proportionally (no distortion).
        let aspect =
            f32::from(u16::try_from(conclave_client::avatar::BANNER_HEIGHT).unwrap_or(128))
                / f32::from(u16::try_from(conclave_client::avatar::BANNER_WIDTH).unwrap_or(512));
        let width = ui.available_width();
        ui.vertical_centered(|ui| {
            ui.add(egui::Image::new(&texture).fit_to_exact_size(egui::vec2(width, width * aspect)));
        });
    } else {
        ui.vertical_centered(|ui| {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Conclave").size(48.0).weak());
            ui.add_space(12.0);
        });
    }
}

/// Record `key` as the active server when its viewport currently has focus, so
/// the root window can show that server's banner.
fn note_active_server(active: &RwLock<Option<String>>, ctx: &egui::Context, key: &str) {
    if ctx.input(|i| i.viewport().focused) != Some(true) {
        return;
    }
    let already = active.read().is_ok_and(|a| a.as_deref() == Some(key));
    if !already && let Ok(mut a) = active.write() {
        *a = Some(key.to_string());
    }
}

/// Draw a user's avatar at the standard display size. Users without an avatar
/// (or whose avatar fails to decode) get nothing, so their row keeps its natural
/// text height rather than being padded to the avatar size. Idle users' avatars
/// are dimmed to match their dulled name.
fn show_avatar(ui: &mut egui::Ui, avatar: Option<&[u8]>, idle: bool) {
    let edge = f32::from(u16::try_from(conclave_client::avatar::DISPLAY_SIZE).unwrap_or(32));
    if let Some(bytes) = avatar
        && let Some(texture) = avatar_texture(ui.ctx(), bytes)
    {
        // A grey tint multiplies the image toward darkness, dimming it the way
        // `dull` dims a name.
        let tint = if idle {
            egui::Color32::from_gray(128)
        } else {
            egui::Color32::WHITE
        };
        ui.add(
            egui::Image::new(&texture)
                .fit_to_exact_size(egui::vec2(edge, edge))
                .tint(tint),
        );
    }
}

/// Grab the current clipboard image and normalise it to a canonical avatar PNG.
fn load_clipboard_avatar() -> anyhow::Result<Vec<u8>> {
    let mut clipboard = arboard::Clipboard::new()?;
    let image = clipboard.get_image()?;
    let width = u32::try_from(image.width)?;
    let height = u32::try_from(image.height)?;
    conclave_client::avatar::normalize_rgba(image.bytes.as_ref(), width, height)
}

/// Prompt for an image file and normalise it to a canonical avatar PNG. Returns
/// `Ok(None)` when the user cancels the dialog.
fn load_file_avatar() -> anyhow::Result<Option<Vec<u8>>> {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("Images", &["png", "jpg", "jpeg"])
        .pick_file()
    else {
        return Ok(None);
    };
    let data = std::fs::read(path)?;
    Ok(Some(conclave_client::avatar::normalize_encoded(&data)?))
}

/// Persist the avatar to the config off the UI thread, recording any error.
fn spawn_set_avatar(
    client: &Arc<Client>,
    pending: &Arc<AtomicBool>,
    error: &Arc<RwLock<Option<String>>>,
    avatar: Option<Vec<u8>>,
) {
    let client = client.clone();
    let pending = pending.clone();
    let error = error.clone();
    pending.store(true, Ordering::SeqCst);
    tokio::spawn(async move {
        if let Err(e) = client.set_avatar(avatar).await
            && let Ok(mut err) = error.write()
        {
            *err = Some(e.to_string());
        }
        pending.store(false, Ordering::SeqCst);
    });
}

/// Describe another user's timezone relative to the viewing user's, in whole
/// hours. Both are the hours-east-of-GMT the two users shared with the server
/// (the viewer's `ours`, the other user's `theirs`); the server's own timezone
/// is never involved. `None` for either means it was not shared.
#[inline]
fn timezone_offset_text(theirs: Option<i16>, ours: Option<i16>) -> String {
    let Some(theirs) = theirs else {
        return "Timezone: not shared".to_string();
    };

    let Some(ours) = ours else {
        // We don't know our own timezone, so show the other user's absolute
        // offset from GMT instead of a difference.
        return match theirs.cmp(&0) {
            std::cmp::Ordering::Greater => format!("Timezone: GMT+{theirs}"),
            std::cmp::Ordering::Less => format!("Timezone: GMT{theirs}"),
            std::cmp::Ordering::Equal => "Timezone: GMT".to_string(),
        };
    };

    let diff = theirs - ours;
    match diff.cmp(&0) {
        std::cmp::Ordering::Greater => format!("Timezone: {diff}h ahead of you"),
        std::cmp::Ordering::Less => format!("Timezone: {}h behind you", diff.abs()),
        std::cmp::Ordering::Equal => "Timezone: same as yours".to_string(),
    }
}

/// Parse host and port from a `"conclave://host:port"` URL.
fn parse_server_url(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix(conclave_common::URL_PROTOCOL)?;
    let colon = rest.rfind(':')?;
    let host = rest[..colon].to_string();
    let port = rest[colon + 1..].parse().ok()?;
    Some((host, port))
}

/// Flatten a description → URL map into an ordered list of pairs for editing.
/// Editing keys in place is impossible with a map, so the GUI works on a `Vec`
/// and converts back on save with [`pairs_to_map`].
fn map_to_pairs(map: &BTreeMap<String, String>) -> Vec<(String, String)> {
    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Collapse edited pairs back into a map, dropping entries whose description is
/// blank (a partially-filled or just-added row).
fn pairs_to_map(pairs: &[(String, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .filter(|(desc, _)| !desc.trim().is_empty())
        .map(|(desc, url)| (desc.trim().to_string(), url.trim().to_string()))
        .collect()
}

/// Render an editor for a list of description/URL pairs. Rows can be edited,
/// removed, or appended; the caller persists the result. Returns `true` if any
/// row changed this frame (edit, add, or delete).
fn urls_editor(ui: &mut egui::Ui, id_salt: &str, pairs: &mut Vec<(String, String)>) -> bool {
    let mut changed = false;
    let mut remove: Option<usize> = None;
    for (i, (desc, url)) in pairs.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            changed |= ui
                .add(
                    egui::TextEdit::singleline(desc)
                        .id_salt(format!("{id_salt}_desc_{i}"))
                        .hint_text("Description")
                        .desired_width(120.0),
                )
                .changed();
            changed |= ui
                .add(
                    egui::TextEdit::singleline(url)
                        .id_salt(format!("{id_salt}_url_{i}"))
                        .hint_text("https://…")
                        .desired_width(220.0),
                )
                .changed();
            if ui.small_button("🗑").on_hover_text("Remove link").clicked() {
                remove = Some(i);
            }
        });
    }
    if let Some(i) = remove {
        pairs.remove(i);
        changed = true;
    }
    if ui.button("➕ Add link").clicked() {
        pairs.push((String::new(), String::new()));
        changed = true;
    }
    changed
}

/// Render a read-only view of another user's profile text and links, used in the
/// user-details panel. Links are shown as clickable hyperlinks.
fn profile_view(ui: &mut egui::Ui, profile: &str, urls: &BTreeMap<String, String>) {
    if !profile.trim().is_empty() {
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Profile").strong());
        ui.label(profile);
    }
    if !urls.is_empty() {
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Links").strong());
        for (desc, url) in urls {
            ui.horizontal(|ui| {
                ui.label(format!("{desc}:"));
                ui.hyperlink(url);
            });
        }
    }
}

/// Connect to a server in the background. On success the connection is registered
/// in `active_connections`; roster and server-info updates then arrive as pushes
/// from the server rather than by polling. When `clear_on_success` is provided,
/// that pending-server slot is cleared once the connection succeeds (used to
/// dismiss the login window).
#[allow(clippy::too_many_arguments)]
fn spawn_connect(
    client: Arc<Client>,
    active_connections: Arc<RwLock<Vec<ConclaveConnection>>>,
    connect_pending: Arc<AtomicBool>,
    connect_error: Arc<RwLock<Option<String>>>,
    clear_on_success: Option<Arc<RwLock<Option<PendingServer>>>>,
    host: String,
    port: u16,
    share_time: bool,
    display_name: String,
    auth: Option<UserAuthentication>,
    key: Option<VerifyingKey>,
    avatar: Option<Vec<u8>>,
    profile: String,
    urls: BTreeMap<String, String>,
) {
    connect_pending.store(true, Ordering::SeqCst);
    if let Ok(mut e) = connect_error.write() {
        *e = None;
    }

    tokio::spawn(async move {
        match client
            .connect(
                &host,
                port,
                share_time,
                display_name,
                auth,
                key,
                avatar,
                profile,
                urls,
            )
            .await
        {
            Ok(conn) => {
                // The server pushes roster and server-info updates as they happen
                // (on connect/disconnect and on admin edits), so the client does
                // not poll for them.
                if let Ok(mut conns) = active_connections.write() {
                    conns.push(conn);
                }
                if let Some(p) = clear_on_success
                    && let Ok(mut g) = p.write()
                {
                    *g = None;
                }
            }
            Err(e) => {
                if let Ok(mut err) = connect_error.write() {
                    *err = Some(e.to_string());
                }
            }
        }
        connect_pending.store(false, Ordering::SeqCst);
    });
}

/// An action requested while rendering the forum post tree, applied after the
/// tree is drawn (so the borrow of the post list has ended).
enum ForumAction {
    /// Reply to the given post id.
    Reply(u32),
    /// Delete the given post id (administrators only).
    Delete(u32),
}

/// One inline span of minimal markdown.
enum MdSpan {
    /// Styled text run.
    Styled {
        /// The text.
        text: String,
        /// Rendered bold.
        bold: bool,
        /// Rendered italic.
        italic: bool,
        /// Rendered as inline code (monospace).
        code: bool,
    },
    /// A `[label](url)` hyperlink.
    Link {
        /// Visible label.
        label: String,
        /// Target URL.
        url: String,
    },
}

/// Index of the next `needle` in `chars` at or after `from`, if any.
fn find_char(chars: &[char], from: usize, needle: char) -> Option<usize> {
    (from..chars.len()).find(|&i| chars[i] == needle)
}

/// Index of the first of two consecutive `needle`s at or after `from`, if any.
fn find_double(chars: &[char], from: usize, needle: char) -> Option<usize> {
    (from..chars.len().saturating_sub(1)).find(|&i| chars[i] == needle && chars[i + 1] == needle)
}

/// Parse a single line of text into minimal-markdown inline spans: `**bold**`,
/// `*italic*`/`_italic_`, `` `code` ``, and `[label](url)` links. Anything not
/// recognised is left as plain text.
fn parse_inline(text: &str) -> Vec<MdSpan> {
    let chars: Vec<char> = text.chars().collect();
    let mut spans = Vec::new();
    let mut buf = String::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        // `code`
        if c == '`'
            && let Some(end) = find_char(&chars, i + 1, '`')
        {
            push_plain(&mut spans, &mut buf);
            spans.push(MdSpan::Styled {
                text: chars[i + 1..end].iter().collect(),
                bold: false,
                italic: false,
                code: true,
            });
            i = end + 1;
            continue;
        }

        // **bold**
        if c == '*'
            && i + 1 < chars.len()
            && chars[i + 1] == '*'
            && let Some(end) = find_double(&chars, i + 2, '*')
        {
            push_plain(&mut spans, &mut buf);
            spans.push(MdSpan::Styled {
                text: chars[i + 2..end].iter().collect(),
                bold: true,
                italic: false,
                code: false,
            });
            i = end + 2;
            continue;
        }

        // *italic* or _italic_
        if (c == '*' || c == '_')
            && let Some(end) = find_char(&chars, i + 1, c)
            && end > i + 1
        {
            push_plain(&mut spans, &mut buf);
            spans.push(MdSpan::Styled {
                text: chars[i + 1..end].iter().collect(),
                bold: false,
                italic: true,
                code: false,
            });
            i = end + 1;
            continue;
        }

        // [label](url)
        if c == '['
            && let Some(close) = find_char(&chars, i + 1, ']')
            && close + 1 < chars.len()
            && chars[close + 1] == '('
            && let Some(paren) = find_char(&chars, close + 2, ')')
        {
            push_plain(&mut spans, &mut buf);
            spans.push(MdSpan::Link {
                label: chars[i + 1..close].iter().collect(),
                url: chars[close + 2..paren].iter().collect(),
            });
            i = paren + 1;
            continue;
        }

        buf.push(c);
        i += 1;
    }

    push_plain(&mut spans, &mut buf);
    spans
}

/// Flush any buffered plain text into a span.
fn push_plain(spans: &mut Vec<MdSpan>, buf: &mut String) {
    if !buf.is_empty() {
        spans.push(MdSpan::Styled {
            text: std::mem::take(buf),
            bold: false,
            italic: false,
            code: false,
        });
    }
}

/// Render one line's inline spans within a wrapping horizontal layout.
fn render_inline_line(ui: &mut egui::Ui, line: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for span in parse_inline(line) {
            match span {
                MdSpan::Styled {
                    text,
                    bold,
                    italic,
                    code,
                } => {
                    let mut rich = egui::RichText::new(text);
                    if bold {
                        rich = rich.strong();
                    }
                    if italic {
                        rich = rich.italics();
                    }
                    if code {
                        rich = rich
                            .monospace()
                            .background_color(ui.visuals().extreme_bg_color);
                    }
                    ui.label(rich);
                }
                MdSpan::Link { label, url } => {
                    ui.hyperlink_to(label, url);
                }
            }
        }
    });
}

/// Render text with the minimal markdown subset: `#`/`##`/`###` headings,
/// `-`/`*` bullets, blank-line spacing, and inline styling. Embedded content
/// (images, HTML) is intentionally not supported.
fn render_markdown(ui: &mut egui::Ui, text: &str) {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("### ") {
            ui.label(egui::RichText::new(rest).strong().size(14.0));
        } else if let Some(rest) = line.strip_prefix("## ") {
            ui.label(egui::RichText::new(rest).strong().size(16.0));
        } else if let Some(rest) = line.strip_prefix("# ") {
            ui.label(egui::RichText::new(rest).strong().size(18.0));
        } else if let Some(rest) = line.strip_prefix("- ").or_else(|| line.strip_prefix("* ")) {
            ui.horizontal_wrapped(|ui| {
                ui.label("  •  ");
                render_inline_line(ui, rest);
            });
        } else if line.trim().is_empty() {
            ui.add_space(4.0);
        } else {
            render_inline_line(ui, line);
        }
    }
}

/// Render a post's body, as markdown when the author chose it, otherwise plain.
fn render_post_body(ui: &mut egui::Ui, post: &ForumPost) {
    if post.markdown {
        render_markdown(ui, &post.body);
    } else {
        ui.label(&post.body);
    }
}

/// Recursively render the replies to `parent` within a thread, indenting each
/// level. Requested actions are collected into `actions` and applied by the
/// caller.
fn render_forum_posts(
    ui: &mut egui::Ui,
    key: &str,
    posts: &[ForumPost],
    parent: Option<u32>,
    depth: usize,
    is_admin: bool,
    actions: &mut Vec<ForumAction>,
) {
    for post in posts.iter().filter(|p| p.reply_to == parent) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&post.author_name).strong());
                ui.label(
                    egui::RichText::new(post.created_at.format("%Y-%m-%d %H:%M").to_string())
                        .weak()
                        .monospace(),
                );
                if let Some(signature) = &post.signature {
                    let valid = signature.verify(&post.body);
                    let (glyph, color) = if valid {
                        ("🔒 signed", egui::Color32::from_rgb(0x2e, 0xa0, 0x43))
                    } else {
                        ("⚠ bad signature", egui::Color32::from_rgb(0xd0, 0x45, 0x37))
                    };
                    let sig_id = egui::Id::new(("forum_sig", key, post.id));
                    let mut shown = ui.data(|d| d.get_temp::<bool>(sig_id)).unwrap_or(false);
                    if ui
                        .selectable_label(shown, egui::RichText::new(glyph).color(color).small())
                        .clicked()
                    {
                        shown = !shown;
                        ui.data_mut(|d| d.insert_temp(sig_id, shown));
                    }
                }
            });

            // Expanded signature details.
            if let Some(signature) = &post.signature {
                let sig_id = egui::Id::new(("forum_sig", key, post.id));
                if ui.data(|d| d.get_temp::<bool>(sig_id)).unwrap_or(false) {
                    ui.label(
                        egui::RichText::new(format!(
                            "public key: {}",
                            hex::encode(signature.public_key)
                        ))
                        .monospace()
                        .size(10.0),
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "signature: {}",
                            hex::encode(&signature.signature)
                        ))
                        .monospace()
                        .size(10.0),
                    );
                }
            }

            render_post_body(ui, post);

            ui.horizontal(|ui| {
                if ui.small_button("Reply").clicked() {
                    actions.push(ForumAction::Reply(post.id));
                }
                if is_admin && ui.small_button("🗑 Delete").clicked() {
                    actions.push(ForumAction::Delete(post.id));
                }
            });
        });

        // Replies to this post, indented one level (bounded to keep very deep
        // threads readable).
        if depth < 16 {
            ui.indent(("forum_indent", key, post.id), |ui| {
                render_forum_posts(ui, key, posts, Some(post.id), depth + 1, is_admin, actions);
            });
        } else {
            render_forum_posts(ui, key, posts, Some(post.id), depth + 1, is_admin, actions);
        }
    }
}

/// A server chosen by the user, awaiting login credentials.
#[derive(Clone, Debug)]
struct PendingServer {
    host: String,
    port: u16,
    /// Known key from discovery/tracker; `None` means the client will fetch it during connect.
    key: Option<VerifyingKey>,
    name: String,
    anonymous_allowed: bool,
}

/// A per-server entry for the Servers menu, snapshotted each frame.
#[allow(clippy::struct_excessive_bools)]
struct MenuServer {
    /// Composite window key (`{server_key}:{local_id}`), matching the windows.
    key: String,
    /// Display label: the server name, plus the display name when the server
    /// has more than one connection.
    label: String,
    /// Whether the server shares a file directory.
    sharing: bool,
    /// Whether this connection holds admin rights.
    is_admin: bool,
    /// Whether chat is enabled on the server.
    chat_enabled: bool,
    /// Whether forums are enabled on the server.
    forums_enabled: bool,
    /// Chatrooms this user may access on the server.
    rooms: Vec<ChatroomInfo>,
}

/// GUI client state
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConclaveGUI {
    /// Conclave client
    client: Arc<Client>,

    /// Showing the window displaying local Conclave servers
    show_advertised_servers_list: bool,

    /// Showing the window displaying known Conclave trackers
    show_tracker_list: bool,

    /// Showing the window displaying servers advertised via trackers
    show_tracker_servers: bool,

    /// Discovered local Conclave servers
    discovered_servers: Arc<RwLock<HashSet<DiscoveredServer>>>,

    /// Whether we're searching for local Conclave servers via mDNS
    discovery_running: Arc<AtomicBool>,

    /// Any errors encountered during discovery
    discovery_error: Arc<RwLock<Option<String>>>,

    /// Local server discovery window closed
    discovery_viewport_closed: Arc<AtomicBool>,

    /// Tracker window closed
    tracker_viewport_closed: Arc<AtomicBool>,

    /// Any errors encountered trying to add a tracker
    tracker_error: Arc<RwLock<Option<String>>>,

    /// Tracker addition pending
    tracker_op_pending: Arc<AtomicBool>,

    /// Tracker fetched from network, awaiting user confirmation before adding
    pending_tracker_info: Arc<RwLock<Option<TrackerWithKey>>>,

    /// Tracker servers window closed
    tracker_servers_viewport_closed: Arc<AtomicBool>,

    /// Servers discovered via trackers
    tracker_servers: Arc<RwLock<Vec<Advertise>>>,

    /// Stop handle for the live tracker-server subscription; `Some` while the
    /// tracker-servers window is open. Dropping it stops the subscription.
    tracker_servers_watch: Option<tokio::sync::watch::Sender<bool>>,

    /// Server chosen by the user, pending authentication
    pending_server: Arc<RwLock<Option<PendingServer>>>,

    /// Async connect operation is in-flight
    connect_pending: Arc<AtomicBool>,

    /// A successful SRV lookup `(host, port)` to apply to the Direct Connect form
    srv_result: Arc<RwLock<Option<(String, u16)>>>,

    /// An SRV lookup for the Direct Connect form is in-flight
    srv_pending: Arc<AtomicBool>,

    /// Error from the most recent connect attempt
    connect_error: Arc<RwLock<Option<String>>>,

    /// Currently active server connections
    active_connections: Arc<RwLock<Vec<ConclaveConnection>>>,

    /// Default display name from config, seeds the login form
    default_display_name: String,

    /// Whether the config enables sharing the local timezone by default; seeds
    /// the login form's "Share local time" checkbox.
    default_share_timezone: bool,

    /// Show the direct-connect host/port form in the central panel
    show_direct_connect: bool,

    /// Login window close flag (set when the user closes the login window)
    login_window_closed: Arc<AtomicBool>,

    /// Show the "Connected Servers" window
    show_servers_window: bool,

    /// Show the About window
    show_about: bool,

    /// About window close flag, set by its viewport closure
    about_closed: Arc<AtomicBool>,

    /// Show the Settings window
    show_settings: bool,

    /// Settings window close flag, set by its viewport closure
    settings_closed: Arc<AtomicBool>,

    /// A settings operation (saving the avatar) is in flight
    settings_pending: Arc<AtomicBool>,

    /// Any error from the most recent settings operation
    settings_error: Arc<RwLock<Option<String>>>,

    /// Working copy of the user's avatar (a 512×512 PNG), edited in the Settings
    /// window and persisted to the config on change.
    settings_avatar: Arc<RwLock<Option<Vec<u8>>>>,

    /// Connected Servers window close flag
    servers_window_closed: Arc<AtomicBool>,

    /// Server keys (`host:port` hash) whose user-list window is open
    open_user_windows: Arc<RwLock<HashSet<String>>>,

    /// Servers already auto-opened once, so a manual close is not undone
    seen_servers: HashSet<String>,

    /// User-window close requests (server keys) emitted by viewport closures
    user_window_close_requests: Arc<RwLock<Vec<String>>>,

    /// Server keys whose administration window is open (admin connections only)
    open_admin_windows: Arc<RwLock<HashSet<String>>>,

    /// Admin-window close requests (server keys) emitted by viewport closures
    admin_window_close_requests: Arc<RwLock<Vec<String>>>,

    /// Open chatroom windows, keyed by (server key, room id)
    open_chats: Arc<RwLock<HashSet<(String, u16)>>>,

    /// Chat-window close requests emitted by viewport closures
    chat_window_close_requests: Arc<RwLock<Vec<(String, u16)>>>,

    /// Open direct-message windows, keyed by (server key, peer connection id)
    open_dms: Arc<RwLock<HashSet<(String, u16)>>>,

    /// Direct-message-window close requests emitted by viewport closures
    dm_window_close_requests: Arc<RwLock<Vec<(String, u16)>>>,

    /// Open file-browser windows, keyed by server key
    open_file_windows: Arc<RwLock<HashSet<String>>>,

    /// File-window close requests emitted by viewport closures
    file_window_close_requests: Arc<RwLock<Vec<String>>>,

    /// Open forum windows, keyed by server key
    open_forum_windows: Arc<RwLock<HashSet<String>>>,

    /// Forum-window close requests emitted by viewport closures
    forum_window_close_requests: Arc<RwLock<Vec<String>>>,

    /// Server key of the most recently focused per-server window, whose banner
    /// the root window displays. `None` shows the default placeholder.
    active_server: Arc<RwLock<Option<String>>>,

    /// Show the bookmarks management window
    show_bookmarks_window: bool,

    /// Bookmarks window close flag
    bookmarks_viewport_closed: Arc<AtomicBool>,

    /// Any error from a bookmark add/edit operation
    bookmarks_error: Arc<RwLock<Option<String>>>,

    /// A bookmark add/edit is in progress (fetching the server key)
    bookmarks_op_pending: Arc<AtomicBool>,

    /// Whether the main window has been fitted to the monitor yet. The fit runs
    /// once, on the first frame the monitor size is known.
    window_fitted: bool,
}

impl ConclaveGUI {
    pub fn new(client: Client, _cc: &eframe::CreationContext<'_>) -> Self {
        let default_display_name = client.default_display_name();
        let default_share_timezone = client.default_share_timezone();
        let avatar = client.avatar();
        Self {
            client: Arc::new(client),
            show_advertised_servers_list: false,
            show_tracker_list: false,
            show_tracker_servers: false,
            discovered_servers: Arc::new(RwLock::new(HashSet::new())),
            discovery_running: Arc::new(AtomicBool::new(false)),
            discovery_error: Arc::new(RwLock::new(None)),
            discovery_viewport_closed: Arc::new(AtomicBool::new(false)),
            tracker_viewport_closed: Arc::new(AtomicBool::new(false)),
            tracker_error: Arc::new(RwLock::new(None)),
            tracker_op_pending: Arc::new(AtomicBool::new(false)),
            pending_tracker_info: Arc::new(RwLock::new(None)),
            tracker_servers_viewport_closed: Arc::new(AtomicBool::new(false)),
            tracker_servers: Arc::new(RwLock::new(Vec::new())),
            tracker_servers_watch: None,
            pending_server: Arc::new(RwLock::new(None)),
            connect_pending: Arc::new(AtomicBool::new(false)),
            srv_result: Arc::new(RwLock::new(None)),
            srv_pending: Arc::new(AtomicBool::new(false)),
            connect_error: Arc::new(RwLock::new(None)),
            active_connections: Arc::new(RwLock::new(Vec::new())),
            default_display_name,
            default_share_timezone,
            show_direct_connect: false,
            login_window_closed: Arc::new(AtomicBool::new(false)),
            show_servers_window: false,
            show_about: false,
            about_closed: Arc::new(AtomicBool::new(false)),
            show_settings: false,
            settings_closed: Arc::new(AtomicBool::new(false)),
            settings_pending: Arc::new(AtomicBool::new(false)),
            settings_error: Arc::new(RwLock::new(None)),
            settings_avatar: Arc::new(RwLock::new(avatar)),
            servers_window_closed: Arc::new(AtomicBool::new(false)),
            open_user_windows: Arc::new(RwLock::new(HashSet::new())),
            open_admin_windows: Arc::new(RwLock::new(HashSet::new())),
            admin_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            open_chats: Arc::new(RwLock::new(HashSet::new())),
            chat_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            open_dms: Arc::new(RwLock::new(HashSet::new())),
            dm_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            open_file_windows: Arc::new(RwLock::new(HashSet::new())),
            file_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            open_forum_windows: Arc::new(RwLock::new(HashSet::new())),
            active_server: Arc::new(RwLock::new(None)),
            forum_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            seen_servers: HashSet::new(),
            user_window_close_requests: Arc::new(RwLock::new(Vec::new())),
            show_bookmarks_window: false,
            bookmarks_viewport_closed: Arc::new(AtomicBool::new(false)),
            bookmarks_error: Arc::new(RwLock::new(None)),
            bookmarks_op_pending: Arc::new(AtomicBool::new(false)),
            window_fitted: false,
        }
    }
}

impl eframe::App for ConclaveGUI {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut Frame) {
        self.fit_main_window(ui.ctx());
        self.begin_frame(ui);
        self.top_bar_menu(ui);
        self.about_window(ui);
        self.settings_window(ui);
        self.server_discovery_window(ui);
        self.tracker_list_window(ui);
        self.bookmarks_window(ui);
        self.tracker_servers_window(ui);
        self.login_window(ui);
        self.prune_dead_connections();
        let conn_snapshots = self.snapshot_connections();
        self.connected_servers_window(ui, &conn_snapshots);
        self.user_windows(ui, &conn_snapshots);
        self.chatroom_windows(ui, &conn_snapshots);
        self.dm_windows(ui, &conn_snapshots);
        self.file_windows(ui, &conn_snapshots);
        self.forum_windows(ui, &conn_snapshots);
        self.admin_windows(ui, &conn_snapshots);
        self.root_window(ui, &conn_snapshots);
    }
}

impl ConclaveGUI {
    /// Fix the main window to a size that fits the monitor while keeping its
    /// aspect ratio, then lock it so it stays fixed. Runs once, on the first
    /// frame the monitor size is reported.
    ///
    /// [`MAIN_WINDOW_SIZE`] is an absolute logical size that looks right on a
    /// well-behaved display, but the reported scale factor is unreliable on some
    /// platforms (notably KDE under X11), which can turn that logical size into a
    /// window far larger than the screen. Scaling both dimensions by a single
    /// factor keeps the window proportional and always on-screen.
    fn fit_main_window(&mut self, ctx: &egui::Context) {
        if self.window_fitted {
            return;
        }
        // The monitor size is not always known on the very first frame; keep
        // repainting until it is, then apply the fit exactly once.
        let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) else {
            ctx.request_repaint();
            return;
        };
        if monitor.x < 1.0 || monitor.y < 1.0 {
            ctx.request_repaint();
            return;
        }

        let base = egui::Vec2::from(MAIN_WINDOW_SIZE);
        let max = monitor * MAIN_WINDOW_MAX_SCREEN_FRACTION;
        // A single scale factor for both axes preserves the aspect ratio; never
        // scale up past the intended size.
        let scale = (max.x / base.x).min(max.y / base.y).min(1.0);
        let size = base * scale;

        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(size));
        ctx.send_viewport_cmd(egui::ViewportCommand::MaxInnerSize(size));
        self.window_fitted = true;
    }

    /// Per-frame housekeeping: drain viewport close flags, keep the
    /// tracker-server subscription in sync, and repaint while async work runs.
    #[inline]
    fn begin_frame(&mut self, ui: &mut egui::Ui) {
        // ── Handle viewport close events ──────────────────────────────────
        if self.discovery_viewport_closed.swap(false, Ordering::SeqCst) {
            self.show_advertised_servers_list = false;
        }
        if self.tracker_viewport_closed.swap(false, Ordering::SeqCst) {
            self.show_tracker_list = false;
        }
        if self
            .tracker_servers_viewport_closed
            .swap(false, Ordering::SeqCst)
        {
            self.show_tracker_servers = false;
        }
        if self.bookmarks_viewport_closed.swap(false, Ordering::SeqCst) {
            self.show_bookmarks_window = false;
        }
        if self.about_closed.swap(false, Ordering::SeqCst) {
            self.show_about = false;
        }
        if self.settings_closed.swap(false, Ordering::SeqCst) {
            self.show_settings = false;
        }

        // Keep the live tracker-server subscription running exactly while the
        // window is open: start it on open, stop it (drop the handle) on close.
        if self.show_tracker_servers {
            if self.tracker_servers_watch.is_none() {
                if let Ok(mut servers) = self.tracker_servers.write() {
                    servers.clear();
                }
                self.tracker_servers_watch = Some(
                    self.client
                        .watch_servers_from_trackers(&self.tracker_servers),
                );
            }
        } else if self.tracker_servers_watch.take().is_some()
            && let Ok(mut servers) = self.tracker_servers.write()
        {
            servers.clear();
        }
        if self.login_window_closed.swap(false, Ordering::SeqCst) {
            if let Ok(mut p) = self.pending_server.write() {
                *p = None;
            }
            if let Ok(mut e) = self.connect_error.write() {
                *e = None;
            }
        }
        if self.servers_window_closed.swap(false, Ordering::SeqCst) {
            self.show_servers_window = false;
        }
        // Drain close requests from per-server user windows.
        let close_keys: Vec<String> = self
            .user_window_close_requests
            .write()
            .map(|mut r| r.drain(..).collect())
            .unwrap_or_default();
        if !close_keys.is_empty()
            && let Ok(mut open) = self.open_user_windows.write()
        {
            for k in close_keys {
                open.remove(&k);
            }
        }
        // Drain close requests from per-server admin windows.
        let admin_close_keys: Vec<String> = self
            .admin_window_close_requests
            .write()
            .map(|mut r| r.drain(..).collect())
            .unwrap_or_default();
        if !admin_close_keys.is_empty()
            && let Ok(mut open) = self.open_admin_windows.write()
        {
            for k in admin_close_keys {
                open.remove(&k);
            }
        }

        // ── Request repaint while async operations run ────────────────────
        if self.discovery_running.load(Ordering::SeqCst)
            || self.connect_pending.load(Ordering::SeqCst)
            || self.tracker_op_pending.load(Ordering::SeqCst)
            || self.bookmarks_op_pending.load(Ordering::SeqCst)
            || self.srv_pending.load(Ordering::SeqCst)
        {
            ui.ctx().request_repaint();
        }
    }

    /// Render the top menu bar.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn top_bar_menu(&mut self, ui: &mut egui::Ui) {
        // Snapshot of connections for the Servers menu, keyed the same way as
        // the per-server windows so a menu item opens the correct window. If a
        // server has more than one connection, its display name disambiguates.
        let menu_servers: Vec<MenuServer> = {
            let conns = self
                .active_connections
                .read()
                .map(|c| c.clone())
                .unwrap_or_default();
            let mut counts: HashMap<String, usize> = HashMap::new();
            for conn in &conns {
                *counts
                    .entry(hex::encode(conn.server_info().key.as_bytes()))
                    .or_default() += 1;
            }
            conns
                .iter()
                .map(|conn| {
                    let info = conn.server_info();
                    let server_key = hex::encode(info.key.as_bytes());
                    let key = format!("{server_key}:{}", conn.local_id());
                    let label = if counts.get(&server_key).is_some_and(|&n| n > 1) {
                        format!("{} ({})", info.name, conn.display_name())
                    } else {
                        info.name.clone()
                    };
                    MenuServer {
                        key,
                        label,
                        sharing: info.sharing_enabled,
                        is_admin: conn.is_admin(),
                        chat_enabled: info.chat_enabled,
                        forums_enabled: info.forums_enabled,
                        rooms: conn.chatrooms_available(),
                    }
                })
                .collect()
        };

        // ── Top-bar menu ──────────────────────────────────────────────────
        egui::Panel::top("top_panel").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Settings").clicked() {
                        self.show_settings = true;
                    }
                    if ui.button("About").clicked() {
                        self.show_about = true;
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ui.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Connect", |ui| {
                    if ui.button("Discover Local Servers").clicked() {
                        self.show_advertised_servers_list = true;
                        do_start_discovery(
                            self.discovered_servers.clone(),
                            self.discovery_running.clone(),
                            self.discovery_error.clone(),
                        );
                    }
                    if ui.button("Find via Trackers").clicked() {
                        self.show_tracker_servers = true;
                    }
                    if ui.button("Direct Connect").clicked() {
                        self.show_direct_connect = !self.show_direct_connect;
                    }
                    ui.separator();
                    // Bookmarks as a submenu: clicking one connects to it.
                    ui.menu_button("Bookmarks", |ui| {
                        let bookmarks = self.client.bookmarks();
                        if bookmarks.is_empty() {
                            ui.add_enabled(false, egui::Button::new("No bookmarks"));
                        }
                        for bookmark in bookmarks {
                            if ui.button(&bookmark.name).clicked() {
                                let auth = bookmark.auth.as_ref().map(|a| UserAuthentication {
                                    username: a.username.clone(),
                                    password: a.password.clone(),
                                });
                                spawn_connect(
                                    self.client.clone(),
                                    self.active_connections.clone(),
                                    self.connect_pending.clone(),
                                    self.connect_error.clone(),
                                    None,
                                    bookmark.server.host.clone(),
                                    bookmark.server.port,
                                    bookmark.share_time,
                                    bookmark.display_name.clone(),
                                    auth,
                                    Some(bookmark.server.key),
                                    bookmark.avatar.clone(),
                                    bookmark.profile.clone(),
                                    bookmark.urls.clone(),
                                );
                            }
                        }
                    });
                });
                ui.menu_button("Servers", |ui| {
                    if menu_servers.is_empty() {
                        ui.add_enabled(false, egui::Button::new("Not connected to any server"));
                    }
                    for server in &menu_servers {
                        ui.menu_button(&server.label, |ui| {
                            if ui.button("Users").clicked()
                                && let Ok(mut open) = self.open_user_windows.write()
                            {
                                open.insert(server.key.clone());
                            }
                            // Chat: a submenu of the server's rooms when enabled,
                            // greyed out otherwise.
                            if server.chat_enabled {
                                ui.menu_button("Chat", |ui| {
                                    if server.rooms.is_empty() {
                                        ui.add_enabled(
                                            false,
                                            egui::Button::new("No chatrooms available"),
                                        );
                                    }
                                    for room in &server.rooms {
                                        if ui.button(&room.name).clicked()
                                            && let Ok(mut open) = self.open_chats.write()
                                        {
                                            open.insert((server.key.clone(), room.id));
                                        }
                                    }
                                });
                            } else {
                                ui.add_enabled(false, egui::Button::new("Chat"));
                            }
                            // Forums: greyed out when disabled on the server.
                            if server.forums_enabled {
                                if ui.button("Forums").clicked()
                                    && let Ok(mut open) = self.open_forum_windows.write()
                                {
                                    open.insert(server.key.clone());
                                }
                            } else {
                                ui.add_enabled(false, egui::Button::new("Forums"));
                            }
                            if server.sharing
                                && ui.button("Files").clicked()
                                && let Ok(mut open) = self.open_file_windows.write()
                            {
                                open.insert(server.key.clone());
                            }
                            if server.is_admin
                                && ui.button("Admin").clicked()
                                && let Ok(mut open) = self.open_admin_windows.write()
                            {
                                open.insert(server.key.clone());
                            }
                            ui.separator();
                            if ui.button("Disconnect").clicked() {
                                // Reconstruct each connection's composite key to
                                // find and remove the exact one to disconnect.
                                let removed =
                                    self.active_connections.write().ok().and_then(|mut c| {
                                        let idx = c.iter().position(|conn| {
                                            format!(
                                                "{}:{}",
                                                hex::encode(conn.server_info().key),
                                                conn.local_id()
                                            ) == server.key
                                        });
                                        idx.map(|i| c.remove(i))
                                    });
                                if let Some(conn) = removed {
                                    if let Ok(mut o) = self.open_user_windows.write() {
                                        o.remove(&server.key);
                                    }
                                    tokio::spawn(async move {
                                        let _ = conn.disconnect().await;
                                    });
                                }
                            }
                        });
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.checkbox(
                        &mut self.show_advertised_servers_list,
                        "Local Server Discovery",
                    );
                    ui.checkbox(&mut self.show_tracker_list, "Trackers");
                    ui.checkbox(&mut self.show_tracker_servers, "Servers Listing");
                    ui.checkbox(&mut self.show_servers_window, "Connected Servers");
                    ui.checkbox(&mut self.show_bookmarks_window, "Bookmarks");
                });
                ui.add_space(16.0);
                egui::widgets::global_theme_preference_buttons(ui);
            });
        });
    }

    /// Render the About window when open.
    #[inline]
    fn about_window(&mut self, ui: &mut egui::Ui) {
        // ── About window ──────────────────────────────────────────────────
        if self.show_about {
            let closed = self.about_closed.clone();
            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("about_window"),
                egui::ViewportBuilder::default()
                    .with_title("About Conclave")
                    .with_inner_size([300.0, 150.0])
                    .with_resizable(false),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed.store(true, Ordering::SeqCst);
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.add_space(16.0);
                            ui.heading("Conclave");
                            ui.add_space(8.0);
                            ui.label(format!("Version {}", env!("CONCLAVE_VERSION")));
                            ui.label(format!("Built {}", env!("CONCLAVE_BUILD_DATE")));
                        });
                    });
                },
            );
        }
    }

    /// Render the Settings window when open.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn settings_window(&mut self, ui: &mut egui::Ui) {
        // ── Settings viewport ─────────────────────────────────────────────
        if self.show_settings {
            let closed = self.settings_closed.clone();
            let error_arc = self.settings_error.clone();
            let pending_arc = self.settings_pending.clone();
            let avatar_arc = self.settings_avatar.clone();
            let client_arc = self.client.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("settings_window"),
                egui::ViewportBuilder::default()
                    .with_title("Settings")
                    .with_inner_size([420.0, 560.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed.store(true, Ordering::SeqCst);
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if pending_arc.load(Ordering::SeqCst) {
                        ctx.request_repaint();
                    }

                    let current = avatar_arc.read().ok().and_then(|a| a.clone());
                    let is_pending = pending_arc.load(Ordering::SeqCst);
                    let mut paste_request = false;
                    let mut choose_request = false;
                    let mut remove_request = false;

                    // Profile text and links live in egui temp data, seeded from
                    // the saved config the first time the window is drawn.
                    let profile_id = egui::Id::new("settings_profile_text");
                    let urls_id = egui::Id::new("settings_url_pairs");
                    let mut profile_text: String = ctx
                        .data(|d| d.get_temp::<String>(profile_id))
                        .unwrap_or_else(|| client_arc.profile());
                    let mut url_pairs: Vec<(String, String)> = ctx
                        .data(|d| d.get_temp::<Vec<(String, String)>>(urls_id))
                        .unwrap_or_else(|| map_to_pairs(&client_arc.urls()));
                    let mut save_profile_request = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.heading("Avatar");
                        ui.label(
                            egui::RichText::new(
                                "Shown next to your name to other users. Changes take \
                                 effect the next time you connect.",
                            )
                            .weak(),
                        );
                        ui.add_space(8.0);

                        ui.horizontal(|ui| {
                            // A larger preview of the current avatar.
                            if let Some(bytes) = &current
                                && let Some(texture) = avatar_texture(ui.ctx(), bytes)
                            {
                                ui.add(
                                    egui::Image::new(&texture)
                                        .fit_to_exact_size(egui::vec2(128.0, 128.0)),
                                );
                            } else {
                                ui.add_sized(
                                    egui::vec2(128.0, 128.0),
                                    egui::Label::new(egui::RichText::new("No avatar").weak()),
                                );
                            }

                            ui.vertical(|ui| {
                                if ui
                                    .add_enabled(
                                        !is_pending,
                                        egui::Button::new("Paste from clipboard"),
                                    )
                                    .clicked()
                                {
                                    paste_request = true;
                                }
                                if ui
                                    .add_enabled(!is_pending, egui::Button::new("Choose file…"))
                                    .clicked()
                                {
                                    choose_request = true;
                                }
                                if ui
                                    .add_enabled(
                                        !is_pending && current.is_some(),
                                        egui::Button::new("Remove"),
                                    )
                                    .clicked()
                                {
                                    remove_request = true;
                                }
                                if is_pending {
                                    ui.add(egui::Spinner::new());
                                }
                            });
                        });

                        ui.add_space(12.0);
                        ui.separator();
                        ui.heading("Profile");
                        ui.label(
                            egui::RichText::new(
                                "A short description and links shown to other users when they \
                                 view your details. Used as the default for new bookmarks; \
                                 changes take effect the next time you connect.",
                            )
                            .weak(),
                        );
                        ui.add_space(6.0);
                        ui.add(
                            egui::TextEdit::multiline(&mut profile_text)
                                .hint_text("About me…")
                                .desired_rows(3)
                                .desired_width(f32::INFINITY),
                        );

                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Links (description → URL)").strong());
                        urls_editor(ui, "settings_urls", &mut url_pairs);

                        ui.add_space(8.0);
                        if ui
                            .add_enabled(!is_pending, egui::Button::new("Save profile"))
                            .clicked()
                        {
                            save_profile_request = true;
                        }

                        if let Ok(err) = error_arc.read()
                            && let Some(msg) = err.as_ref()
                        {
                            ui.add_space(6.0);
                            ui.colored_label(egui::Color32::RED, msg);
                        }
                    });

                    // Apply button actions outside the panel closure.
                    if remove_request {
                        if let Ok(mut a) = avatar_arc.write() {
                            *a = None;
                        }
                        if let Ok(mut e) = error_arc.write() {
                            *e = None;
                        }
                        spawn_set_avatar(&client_arc, &pending_arc, &error_arc, None);
                    }

                    if paste_request {
                        match load_clipboard_avatar() {
                            Ok(png) => {
                                if let Ok(mut a) = avatar_arc.write() {
                                    *a = Some(png.clone());
                                }
                                if let Ok(mut e) = error_arc.write() {
                                    *e = None;
                                }
                                spawn_set_avatar(&client_arc, &pending_arc, &error_arc, Some(png));
                            }
                            Err(e) => {
                                if let Ok(mut err) = error_arc.write() {
                                    *err = Some(format!("Paste failed: {e}"));
                                }
                            }
                        }
                    }

                    if choose_request {
                        match load_file_avatar() {
                            Ok(Some(png)) => {
                                if let Ok(mut a) = avatar_arc.write() {
                                    *a = Some(png.clone());
                                }
                                if let Ok(mut e) = error_arc.write() {
                                    *e = None;
                                }
                                spawn_set_avatar(&client_arc, &pending_arc, &error_arc, Some(png));
                            }
                            Ok(None) => {}
                            Err(e) => {
                                if let Ok(mut err) = error_arc.write() {
                                    *err = Some(format!("Could not load image: {e}"));
                                }
                            }
                        }
                    }

                    if save_profile_request {
                        let client = client_arc.clone();
                        let err_arc = error_arc.clone();
                        let profile = profile_text.clone();
                        let urls = pairs_to_map(&url_pairs);
                        tokio::spawn(async move {
                            let result = client.set_profile(profile, urls).await;
                            if let Ok(mut err) = err_arc.write() {
                                *err = result.err().map(|e| e.to_string());
                            }
                        });
                    }

                    // Persist the working profile/link state across frames.
                    ctx.data_mut(|d| {
                        d.insert_temp(profile_id, profile_text);
                        d.insert_temp(urls_id, url_pairs);
                    });
                },
            );
        }
    }

    /// Render the local server-discovery window when open.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn server_discovery_window(&mut self, ui: &mut egui::Ui) {
        // ── Server Discovery viewport ─────────────────────────────────────
        if self.show_advertised_servers_list {
            let closed_arc = self.discovery_viewport_closed.clone();
            let running_arc = self.discovery_running.clone();
            let servers_arc = self.discovered_servers.clone();
            let error_arc = self.discovery_error.clone();
            let pending_server_arc = self.pending_server.clone();
            let connect_error_arc = self.connect_error.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("local_server_discovery"),
                egui::ViewportBuilder::default()
                    .with_title("Local Server Discovery")
                    .with_inner_size([480.0, 340.0])
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
                    egui::CentralPanel::default().show(ctx, |ui| {
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
                                                    if ui.button("Connect").clicked() {
                                                        if let Ok(mut p) =
                                                            pending_server_arc.write()
                                                        {
                                                            *p = Some(PendingServer {
                                                                host: server.host.clone(),
                                                                port: server.port,
                                                                key: Some(server.key),
                                                                name: server.name.clone(),
                                                                anonymous_allowed: server
                                                                    .anonymous_allowed,
                                                            });
                                                        }
                                                        if let Ok(mut e) = connect_error_arc.write()
                                                        {
                                                            *e = None;
                                                        }
                                                    }
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
    }

    /// Render the tracker-list window when open.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn tracker_list_window(&mut self, ui: &mut egui::Ui) {
        // ── Tracker List viewport ─────────────────────────────────────────
        if self.show_tracker_list {
            let closed_arc = self.tracker_viewport_closed.clone();
            let error_arc = self.tracker_error.clone();
            let op_pending_arc = self.tracker_op_pending.clone();
            let client_arc = self.client.clone();
            let pending_info_arc = self.pending_tracker_info.clone();

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

                    egui::CentralPanel::default().show(ctx, |ui| {
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
                                                        tracker.host, tracker.port
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
                                                                tracker.host.clone(),
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
                        let has_pending_info = pending_info_arc.read().is_ok_and(|g| g.is_some());
                        let can_add = !is_pending
                            && !has_pending_info
                            && !form_host.is_empty()
                            && form_port.parse::<u16>().is_ok();
                        ui.add_space(4.0);
                        if ui.add_enabled(can_add, egui::Button::new("Add")).clicked() {
                            add_request = true;
                        }
                    });

                    // Confirmation dialog
                    let maybe_tracker = pending_info_arc.read().ok().and_then(|g| g.clone());
                    if let Some(ref tracker) = maybe_tracker {
                        let key_b64 = tracker.key_as_str();
                        let key_sha256 = hex::encode(Sha256::digest(tracker.key_bytes()));

                        let mut confirmed = false;
                        let mut cancelled = false;

                        egui::Window::new("Confirm Tracker")
                            .collapsible(false)
                            .resizable(true)
                            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                            .show(ctx, |ui| {
                                ui.label(format!("Add tracker {}:{}?", tracker.host, tracker.port));
                                ui.separator();
                                ui.label(egui::RichText::new("Public Key (SHA256):").strong());
                                ui.label(key_sha256);
                                ui.label(egui::RichText::new("Public Key (base64):").strong());
                                egui::ScrollArea::vertical()
                                    .id_salt("tracker_key_scroll")
                                    .max_height(120.0)
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new(&key_b64)
                                                    .monospace()
                                                    .size(10.0),
                                            )
                                            .wrap(),
                                        );
                                    });
                                ui.separator();
                                ui.horizontal(|ui| {
                                    if ui.button("Add").clicked() {
                                        confirmed = true;
                                    }
                                    if ui.button("Cancel").clicked() {
                                        cancelled = true;
                                    }
                                });
                            });

                        if confirmed {
                            if let Some(tracker) = maybe_tracker {
                                let client = client_arc.clone();
                                let err_arc = error_arc.clone();
                                let pending = op_pending_arc.clone();
                                let info_arc = pending_info_arc.clone();
                                pending.store(true, Ordering::SeqCst);
                                tokio::spawn(async move {
                                    if let Err(e) = client.add_tracker_with_key(tracker).await
                                        && let Ok(mut err) = err_arc.write()
                                    {
                                        *err = Some(e.to_string());
                                    }
                                    if let Ok(mut info) = info_arc.write() {
                                        *info = None;
                                    }
                                    pending.store(false, Ordering::SeqCst);
                                });
                            }
                        } else if cancelled && let Ok(mut info) = pending_info_arc.write() {
                            *info = None;
                        }
                    }

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
                        let err_arc = error_arc.clone();
                        let pending = op_pending_arc.clone();
                        let info_arc = pending_info_arc.clone();
                        pending.store(true, Ordering::SeqCst);
                        if let Ok(mut err) = err_arc.write() {
                            *err = None;
                        }

                        let name = std::mem::take(&mut form_host);
                        let port_str = std::mem::take(&mut form_port);
                        let Ok(port) = port_str.parse::<u16>() else {
                            error!("Invalid port: {port_str}");
                            if let Ok(mut err) = err_arc.write() {
                                *err = Some(format!("Invalid port: {port_str}"));
                            }
                            pending.store(false, Ordering::SeqCst);
                            ctx.data_mut(|d| {
                                d.insert_temp(form_host_id, name);
                                d.insert_temp(form_port_id, port_str);
                            });
                            return;
                        };

                        tokio::spawn(async move {
                            let tracker = Tracker { host: name, port };
                            match tracker.as_with_key().await {
                                Ok(tracker) => {
                                    if let Ok(mut info) = info_arc.write() {
                                        *info = Some(tracker);
                                    }
                                }
                                Err(e) => {
                                    if let Ok(mut err) = err_arc.write() {
                                        *err = Some(format!("Failed to get tracker key: {e}"));
                                    }
                                }
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
    }

    /// Render the bookmarks window when open.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn bookmarks_window(&mut self, ui: &mut egui::Ui) {
        // ── Bookmarks viewport ────────────────────────────────────────────
        if self.show_bookmarks_window {
            let closed_arc = self.bookmarks_viewport_closed.clone();
            let error_arc = self.bookmarks_error.clone();
            let op_pending_arc = self.bookmarks_op_pending.clone();
            let client_arc = self.client.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("bookmarks"),
                egui::ViewportBuilder::default()
                    .with_title("Bookmarks")
                    .with_inner_size([460.0, 520.0])
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
                    let bookmarks = client_arc.bookmarks();

                    // Form fields live in egui temp data, keyed once here.
                    let name_id = egui::Id::new("bm_form_name");
                    let host_id = egui::Id::new("bm_form_host");
                    let port_id = egui::Id::new("bm_form_port");
                    let display_id = egui::Id::new("bm_form_display");
                    let user_id = egui::Id::new("bm_form_user");
                    let pass_id = egui::Id::new("bm_form_pass");
                    let share_id = egui::Id::new("bm_form_share");
                    let avatar_id = egui::Id::new("bm_form_avatar");
                    let profile_field_id = egui::Id::new("bm_form_profile");
                    let urls_field_id = egui::Id::new("bm_form_urls");
                    let edit_id = egui::Id::new("bm_form_edit_index");

                    let mut f_name =
                        ctx.data(|d| d.get_temp::<String>(name_id).unwrap_or_default());
                    let mut f_host =
                        ctx.data(|d| d.get_temp::<String>(host_id).unwrap_or_default());
                    let mut f_port =
                        ctx.data(|d| d.get_temp::<String>(port_id).unwrap_or_default());
                    let mut f_display =
                        ctx.data(|d| d.get_temp::<String>(display_id).unwrap_or_default());
                    let mut f_user =
                        ctx.data(|d| d.get_temp::<String>(user_id).unwrap_or_default());
                    let mut f_pass =
                        ctx.data(|d| d.get_temp::<String>(pass_id).unwrap_or_default());
                    let mut f_share = ctx.data(|d| d.get_temp::<bool>(share_id).unwrap_or(false));
                    let mut f_avatar = ctx
                        .data(|d| d.get_temp::<Option<Vec<u8>>>(avatar_id))
                        .flatten();
                    let mut f_profile =
                        ctx.data(|d| d.get_temp::<String>(profile_field_id).unwrap_or_default());
                    let mut f_urls = ctx.data(|d| {
                        d.get_temp::<Vec<(String, String)>>(urls_field_id)
                            .unwrap_or_default()
                    });
                    let mut edit_index =
                        ctx.data(|d| d.get_temp::<Option<usize>>(edit_id)).flatten();

                    let mut delete_request: Option<usize> = None;
                    let mut edit_request: Option<usize> = None;
                    let mut save_request = false;
                    let mut cancel_request = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        if is_pending {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new());
                                ui.label("Working...");
                            });
                        } else {
                            let Ok(error_msg) = error_arc.read() else {
                                error!("Failed to read bookmarks error state");
                                return;
                            };
                            if let Some(err) = error_msg.clone() {
                                ui.colored_label(egui::Color32::RED, err);
                            }
                        }

                        ui.separator();

                        egui::ScrollArea::vertical()
                            .max_height(240.0)
                            .show(ui, |ui| {
                                if bookmarks.is_empty() {
                                    ui.label(egui::RichText::new("No bookmarks yet.").weak());
                                }
                                for (i, bookmark) in bookmarks.iter().enumerate() {
                                    ui.group(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(&bookmark.name).strong());
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "{}:{}",
                                                    bookmark.server.host, bookmark.server.port
                                                ))
                                                .monospace()
                                                .weak(),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if !is_pending && ui.button("Delete").clicked()
                                                    {
                                                        delete_request = Some(i);
                                                    }
                                                    if !is_pending && ui.button("Edit").clicked() {
                                                        edit_request = Some(i);
                                                    }
                                                },
                                            );
                                        });
                                        if !bookmark.display_name.is_empty() {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "as {}",
                                                    bookmark.display_name
                                                ))
                                                .weak(),
                                            );
                                        }
                                        if let Some(auth) = &bookmark.auth {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "Username: {}",
                                                    auth.username
                                                ))
                                                .weak(),
                                            );
                                        }

                                        // The server key is hidden until asked for.
                                        let show_key_id = egui::Id::new(("bm_show_key", i));
                                        let mut show_key = ui
                                            .data(|d| d.get_temp::<bool>(show_key_id))
                                            .unwrap_or(false);
                                        if ui
                                            .button(if show_key { "Hide key" } else { "Show key" })
                                            .clicked()
                                        {
                                            show_key = !show_key;
                                            ui.data_mut(|d| {
                                                d.insert_temp(show_key_id, show_key);
                                            });
                                        }
                                        if show_key {
                                            let key_hex =
                                                hex::encode(bookmark.server.key.as_bytes());
                                            let key_sha256 = hex::encode(Sha256::digest(
                                                bookmark.server.key.as_bytes(),
                                            ));
                                            ui.label(egui::RichText::new("Key (hex):").strong());
                                            egui::ScrollArea::vertical()
                                                .id_salt(("bm_key_hex", i))
                                                .max_height(48.0)
                                                .show(ui, |ui| {
                                                    ui.add(
                                                        egui::Label::new(
                                                            egui::RichText::new(&key_hex)
                                                                .monospace()
                                                                .size(10.0),
                                                        )
                                                        .wrap(),
                                                    );
                                                });
                                            ui.label(
                                                egui::RichText::new("Key (SHA-256):").strong(),
                                            );
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(&key_sha256)
                                                        .monospace()
                                                        .size(10.0),
                                                )
                                                .wrap(),
                                            );
                                        }
                                    });
                                }
                            });

                        ui.separator();
                        ui.label(
                            egui::RichText::new(if edit_index.is_some() {
                                "Edit Bookmark"
                            } else {
                                "Add Bookmark"
                            })
                            .strong(),
                        );
                        egui::Grid::new("bookmark_form_grid")
                            .num_columns(2)
                            .spacing([8.0, 6.0])
                            .show(ui, |ui| {
                                ui.label("Server name:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut f_name)
                                        .hint_text("fetched from server if blank"),
                                );
                                ui.end_row();
                                ui.label("Host:");
                                ui.text_edit_singleline(&mut f_host);
                                ui.end_row();
                                ui.label("Port:");
                                ui.add(egui::TextEdit::singleline(&mut f_port).desired_width(60.0));
                                ui.end_row();
                                ui.label("Display name:");
                                ui.text_edit_singleline(&mut f_display);
                                ui.end_row();
                                ui.label("Username:");
                                ui.text_edit_singleline(&mut f_user);
                                ui.end_row();
                                ui.label("Password:");
                                ui.add(egui::TextEdit::singleline(&mut f_pass).password(true));
                                ui.end_row();
                                ui.label("Share local time:");
                                ui.checkbox(&mut f_share, "");
                                ui.end_row();
                                ui.label("Profile:");
                                ui.vertical(|ui| {
                                    ui.add(
                                        egui::TextEdit::multiline(&mut f_profile)
                                            .hint_text("Optional; falls back to your default.")
                                            .desired_rows(2)
                                            .desired_width(220.0),
                                    );
                                });
                                ui.end_row();
                                ui.label("Links:");
                                ui.vertical(|ui| {
                                    urls_editor(ui, "bm_urls", &mut f_urls);
                                    ui.label(
                                        egui::RichText::new(
                                            "Optional; falls back to your default links.",
                                        )
                                        .weak(),
                                    );
                                });
                                ui.end_row();
                                ui.label("Avatar:");
                                ui.vertical(|ui| {
                                    if let Some(bytes) = &f_avatar
                                        && let Some(texture) = avatar_texture(ui.ctx(), bytes)
                                    {
                                        ui.add(
                                            egui::Image::new(&texture)
                                                .fit_to_exact_size(egui::vec2(48.0, 48.0)),
                                        );
                                    }
                                    ui.horizontal(|ui| {
                                        if ui.button("Paste").clicked() {
                                            match load_clipboard_avatar() {
                                                Ok(png) => f_avatar = Some(png),
                                                Err(e) => {
                                                    if let Ok(mut err) = error_arc.write() {
                                                        *err = Some(format!("Paste failed: {e}"));
                                                    }
                                                }
                                            }
                                        }
                                        if ui.button("File…").clicked() {
                                            match load_file_avatar() {
                                                Ok(Some(png)) => f_avatar = Some(png),
                                                Ok(None) => {}
                                                Err(e) => {
                                                    if let Ok(mut err) = error_arc.write() {
                                                        *err = Some(format!(
                                                            "Could not load image: {e}"
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                        if f_avatar.is_some() && ui.button("Clear").clicked() {
                                            f_avatar = None;
                                        }
                                    });
                                    ui.label(
                                        egui::RichText::new(
                                            "Optional; falls back to your default avatar.",
                                        )
                                        .weak(),
                                    );
                                });
                                ui.end_row();
                            });

                        ui.add_space(4.0);
                        // The server name may be left blank; it is fetched from
                        // the server when the bookmark is saved.
                        let can_save =
                            !is_pending && !f_host.is_empty() && f_port.parse::<u16>().is_ok();
                        ui.horizontal(|ui| {
                            let save_label = if edit_index.is_some() { "Save" } else { "Add" };
                            if ui
                                .add_enabled(can_save, egui::Button::new(save_label))
                                .clicked()
                            {
                                save_request = true;
                            }
                            if edit_index.is_some() && ui.button("Cancel").clicked() {
                                cancel_request = true;
                            }
                        });
                    });

                    // Load a bookmark into the form for editing.
                    if let Some(i) = edit_request
                        && let Some(bookmark) = bookmarks.get(i)
                    {
                        f_name.clone_from(&bookmark.name);
                        f_host.clone_from(&bookmark.server.host);
                        f_port = bookmark.server.port.to_string();
                        f_display.clone_from(&bookmark.display_name);
                        f_user = bookmark
                            .auth
                            .as_ref()
                            .map(|a| a.username.clone())
                            .unwrap_or_default();
                        f_pass = bookmark
                            .auth
                            .as_ref()
                            .map(|a| a.password.clone())
                            .unwrap_or_default();
                        f_share = bookmark.share_time;
                        f_avatar.clone_from(&bookmark.avatar);
                        f_profile.clone_from(&bookmark.profile);
                        f_urls = map_to_pairs(&bookmark.urls);
                        edit_index = Some(i);
                    }

                    if cancel_request {
                        f_name.clear();
                        f_host.clear();
                        f_port.clear();
                        f_display.clear();
                        f_user.clear();
                        f_pass.clear();
                        f_share = false;
                        f_avatar = None;
                        f_profile.clear();
                        f_urls.clear();
                        edit_index = None;
                    }

                    if let Some(i) = delete_request {
                        // If the deleted entry was being edited, leave edit mode.
                        if edit_index == Some(i) {
                            f_name.clear();
                            f_host.clear();
                            f_port.clear();
                            f_display.clear();
                            f_user.clear();
                            f_pass.clear();
                            f_share = false;
                            f_avatar = None;
                            f_profile.clear();
                            f_urls.clear();
                            edit_index = None;
                        }
                        let client = client_arc.clone();
                        let err_arc = error_arc.clone();
                        let pending = op_pending_arc.clone();
                        pending.store(true, Ordering::SeqCst);
                        tokio::spawn(async move {
                            if let Err(e) = client.remove_bookmark_by_index(i).await
                                && let Ok(mut err) = err_arc.write()
                            {
                                *err = Some(e.to_string());
                            }
                            pending.store(false, Ordering::SeqCst);
                        });
                    }

                    if save_request && let Ok(port) = f_port.parse::<u16>() {
                        // Reuse the stored key when the address is unchanged;
                        // otherwise fetch the server's key.
                        let key_reuse = edit_index
                            .and_then(|i| bookmarks.get(i))
                            .filter(|b| b.server.host == f_host && b.server.port == port)
                            .map(|b| b.server.key);

                        let name = std::mem::take(&mut f_name);
                        let host = std::mem::take(&mut f_host);
                        let display = std::mem::take(&mut f_display);
                        let user = std::mem::take(&mut f_user);
                        let pass = std::mem::take(&mut f_pass);
                        let share = f_share;
                        let avatar = std::mem::take(&mut f_avatar);
                        let profile = std::mem::take(&mut f_profile);
                        let urls = pairs_to_map(&std::mem::take(&mut f_urls));
                        let index = edit_index;

                        // Reset the form back to add mode.
                        f_port.clear();
                        f_share = false;
                        edit_index = None;

                        let client = client_arc.clone();
                        let err_arc = error_arc.clone();
                        let pending = op_pending_arc.clone();
                        pending.store(true, Ordering::SeqCst);
                        if let Ok(mut err) = err_arc.write() {
                            *err = None;
                        }

                        tokio::spawn(async move {
                            let key = match key_reuse {
                                Some(key) => Ok(key),
                                None => Client::fetch_server_key(&host, port).await,
                            };
                            let key = match key {
                                Ok(key) => key,
                                Err(e) => {
                                    if let Ok(mut err) = err_arc.write() {
                                        *err = Some(format!("Failed to get server key: {e}"));
                                    }
                                    pending.store(false, Ordering::SeqCst);
                                    return;
                                }
                            };

                            // Fetch the server's name when the user left it blank.
                            let name = if name.is_empty() {
                                let handshake_auth =
                                    (!user.is_empty() || !pass.is_empty()).then(|| {
                                        UserAuthentication {
                                            username: user.clone(),
                                            password: pass.clone(),
                                        }
                                    });
                                match Client::fetch_server_info(
                                    &host,
                                    port,
                                    key,
                                    &display,
                                    handshake_auth,
                                )
                                .await
                                {
                                    Ok(info) => info.name,
                                    Err(e) => {
                                        if let Ok(mut err) = err_arc.write() {
                                            *err =
                                                Some(format!("Failed to fetch server name: {e}"));
                                        }
                                        pending.store(false, Ordering::SeqCst);
                                        return;
                                    }
                                }
                            } else {
                                name
                            };

                            let auth = (!user.is_empty() || !pass.is_empty()).then(|| UserAuth {
                                username: user,
                                password: pass,
                            });
                            let entry = BookmarkEntry {
                                server: KnownHost { host, port, key },
                                name,
                                display_name: display,
                                profile,
                                urls,
                                auth,
                                share_time: share,
                                avatar,
                            };
                            let result = if let Some(i) = index {
                                client.update_bookmark(i, &entry).await
                            } else {
                                client.add_bookmark(&entry).await
                            };
                            if let Err(e) = result
                                && let Ok(mut err) = err_arc.write()
                            {
                                *err = Some(e.to_string());
                            }
                            pending.store(false, Ordering::SeqCst);
                        });
                    }

                    ctx.data_mut(|d| {
                        d.insert_temp(name_id, f_name);
                        d.insert_temp(host_id, f_host);
                        d.insert_temp(port_id, f_port);
                        d.insert_temp(display_id, f_display);
                        d.insert_temp(user_id, f_user);
                        d.insert_temp(pass_id, f_pass);
                        d.insert_temp(share_id, f_share);
                        d.insert_temp(avatar_id, f_avatar);
                        d.insert_temp(profile_field_id, f_profile);
                        d.insert_temp(urls_field_id, f_urls);
                        d.insert_temp(edit_id, edit_index);
                    });
                },
            );
        }
    }

    /// Render the tracker-advertised-servers window when open.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn tracker_servers_window(&mut self, ui: &mut egui::Ui) {
        // ── Tracker Servers viewport ──────────────────────────────────────
        if self.show_tracker_servers {
            let closed_arc = self.tracker_servers_viewport_closed.clone();
            let servers_arc = self.tracker_servers.clone();
            let pending_server_arc = self.pending_server.clone();
            let connect_error_arc = self.connect_error.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("tracker_servers"),
                egui::ViewportBuilder::default()
                    .with_title("Tracker Servers")
                    .with_inner_size([780.0, 400.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed_arc.store(true, Ordering::SeqCst);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    // The listing is pushed by the trackers; repaint periodically
                    // so those updates show up promptly.
                    ctx.request_repaint_after(std::time::Duration::from_millis(500));

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.heading("Servers via Trackers");
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new("live")
                                    .small()
                                    .color(egui::Color32::from_rgb(0x4c, 0xaf, 0x50)),
                            );
                        });
                        ui.separator();

                        let Ok(servers) = servers_arc.read() else {
                            error!("Failed to read tracker servers");
                            return;
                        };

                        if servers.is_empty() {
                            ui.label(
                                "No servers found. Make sure trackers are configured and reachable.",
                            );
                        } else {
                            egui::ScrollArea::both().show(ui, |ui| {
                                egui::Grid::new("tracker_servers_grid")
                                    .striped(true)
                                    .spacing([12.0, 4.0])
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new("Name").strong());
                                        ui.label(egui::RichText::new("Version").strong());
                                        ui.label(egui::RichText::new("Address").strong());
                                        ui.label(egui::RichText::new("Users").strong());
                                        ui.label(egui::RichText::new("Guests").strong());
                                        ui.label(egui::RichText::new("Uptime").strong());
                                        ui.label(egui::RichText::new("Description").strong());
                                        ui.label(egui::RichText::new("").strong());
                                        ui.end_row();

                                        for server in servers.iter() {
                                            ui.label(
                                                egui::RichText::new(&server.name).strong(),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "v{}",
                                                    server.version
                                                ))
                                                .monospace(),
                                            );
                                            ui.label(
                                                egui::RichText::new(&server.url).monospace(),
                                            );
                                            ui.label(server.users_connected.to_string());
                                            ui.label(if server.anonymous {
                                                "Yes"
                                            } else {
                                                "No"
                                            });
                                            ui.label(format_uptime(server.uptime()));
                                            ui.label(&server.description);
                                            if let Some((host, port)) =
                                                parse_server_url(&server.url)
                                            {
                                                if ui.button("Connect").clicked() {
                                                    if let Ok(mut p) =
                                                        pending_server_arc.write()
                                                    {
                                                        *p = Some(PendingServer {
                                                            host,
                                                            port,
                                                            key: Some(server.key),
                                                            name: server.name.clone(),
                                                            anonymous_allowed: server.anonymous,
                                                        });
                                                    }
                                                    if let Ok(mut e) =
                                                        connect_error_arc.write()
                                                    {
                                                        *e = None;
                                                    }
                                                }
                                            } else {
                                                ui.label("—");
                                            }
                                            ui.end_row();
                                        }
                                    });
                            });
                        }
                    });
                },
            );
        }
    }

    /// Render the per-server login window when open.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn login_window(&mut self, ui: &mut egui::Ui) {
        // ── Login window ──────────────────────────────────────────────────
        let pending_info: Option<PendingServer> =
            self.pending_server.read().ok().and_then(|p| p.clone());

        if let Some(server) = pending_info {
            let closed_arc = self.login_window_closed.clone();
            let pending_arc = self.pending_server.clone();
            let connect_pending = self.connect_pending.clone();
            let connect_error = self.connect_error.clone();
            let active_conns = self.active_connections.clone();
            let client = self.client.clone();
            let default_name = self.default_display_name.clone();
            let default_share = self.default_share_timezone;

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("login_window"),
                egui::ViewportBuilder::default()
                    .with_title(format!("Connect to {}", server.name))
                    .with_inner_size([360.0, 250.0])
                    .with_resizable(false),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed_arc.store(true, Ordering::SeqCst);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if connect_pending.load(Ordering::SeqCst) {
                        ctx.request_repaint();
                    }

                    let login_name_id = egui::Id::new("login_display_name");
                    let login_user_id = egui::Id::new("login_username");
                    let login_pass_id = egui::Id::new("login_password");
                    let login_share_id = egui::Id::new("login_share_time");

                    let mut display_name: String = ctx.data(|d| {
                        d.get_temp(login_name_id)
                            .unwrap_or_else(|| default_name.clone())
                    });
                    let mut username: String =
                        ctx.data(|d| d.get_temp(login_user_id).unwrap_or_default());
                    let mut password: String =
                        ctx.data(|d| d.get_temp(login_pass_id).unwrap_or_default());
                    let mut share_time: bool =
                        ctx.data(|d| d.get_temp(login_share_id).unwrap_or(default_share));

                    let is_pending = connect_pending.load(Ordering::SeqCst);
                    let conn_error: Option<String> =
                        connect_error.read().ok().and_then(|e| e.clone());

                    let mut connect_clicked = false;
                    let mut cancel_clicked = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.label(format!(
                            "{}  ({}:{})",
                            server.name, server.host, server.port
                        ));
                        ui.separator();

                        if is_pending {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new());
                                ui.label("Connecting…");
                            });
                            return;
                        }

                        if let Some(ref err) = conn_error {
                            ui.colored_label(egui::Color32::RED, err);
                            ui.separator();
                        }

                        // Servers that don't allow guests require credentials.
                        let credentials_required = !server.anonymous_allowed;
                        if credentials_required {
                            ui.label(
                                egui::RichText::new(
                                    "This server does not allow anonymous users — a username and \
                                     password are required.",
                                )
                                .small()
                                .color(egui::Color32::from_rgb(0xff, 0xa5, 0x00)),
                            );
                            ui.add_space(4.0);
                        }

                        egui::Grid::new("login_form_grid")
                            .num_columns(2)
                            .spacing([8.0, 6.0])
                            .show(ui, |ui| {
                                ui.label("Display name:");
                                ui.text_edit_singleline(&mut display_name);
                                ui.end_row();

                                ui.label("Share local time:");
                                ui.checkbox(&mut share_time, "");
                                ui.end_row();

                                ui.label("Username:");
                                ui.text_edit_singleline(&mut username);
                                ui.end_row();

                                ui.label("Password:");
                                ui.add(egui::TextEdit::singleline(&mut password).password(true));
                                ui.end_row();
                            });

                        ui.add_space(8.0);

                        // A display name is always needed; guests-disallowed
                        // servers additionally require a username and password.
                        let has_credentials = !username.is_empty() && !password.is_empty();
                        let can_connect =
                            !display_name.is_empty() && (!credentials_required || has_credentials);

                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(can_connect, egui::Button::new("Connect"))
                                .clicked()
                            {
                                connect_clicked = true;
                            }
                            if ui.button("Cancel").clicked() {
                                cancel_clicked = true;
                            }
                        });
                    });

                    ctx.data_mut(|d| {
                        d.insert_temp(login_name_id, display_name.clone());
                        d.insert_temp(login_user_id, username.clone());
                        d.insert_temp(login_pass_id, password.clone());
                        d.insert_temp(login_share_id, share_time);
                    });

                    if cancel_clicked {
                        if let Ok(mut p) = pending_arc.write() {
                            *p = None;
                        }
                        if let Ok(mut e) = connect_error.write() {
                            *e = None;
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    } else if connect_clicked {
                        let auth = (!username.is_empty()).then_some(UserAuthentication {
                            username: username.clone(),
                            password: password.clone(),
                        });
                        spawn_connect(
                            client.clone(),
                            active_conns.clone(),
                            connect_pending.clone(),
                            connect_error.clone(),
                            Some(pending_arc.clone()),
                            server.host.clone(),
                            server.port,
                            share_time,
                            display_name,
                            auth,
                            server.key,
                            // No per-server avatar here; connect falls back to the
                            // client's default avatar.
                            None,
                            // Likewise no per-server profile override; connect
                            // falls back to the client's default profile/links.
                            String::new(),
                            BTreeMap::new(),
                        );
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }
                },
            );
        }
    }

    /// Drop connections whose listener has ended.
    #[inline]
    fn prune_dead_connections(&mut self) {
        // ── Prune dead connections ────────────────────────────────────────
        // A connection whose listener has ended (the server closed it or kicked
        // us) is removed so it no longer appears in the servers list, as if we
        // had never connected. Its socket is released here and, asynchronously,
        // from the client's own connection list.
        {
            let mut removed_any = false;
            if let Ok(mut conns) = self.active_connections.write() {
                let before = conns.len();
                conns.retain(|conn| conn.connected_since().is_some());
                removed_any = conns.len() != before;
            }
            if removed_any {
                let client = self.client.clone();
                tokio::spawn(async move {
                    client.prune_disconnected().await;
                });
            }
        }
    }

    /// Snapshot the active connections for this frame's per-server windows.
    #[inline]
    fn snapshot_connections(&mut self) -> Vec<ConnSnapshot> {
        // ── Snapshot active connections ───────────────────────────────────
        // (stable key = hash of the server's public key, display name,
        //  still-connected flag, and a clone of the connection).
        // Clone the handles out from under the std RwLock first so the guard is
        // released before building the snapshot. server_info()/connected_users()
        // are synchronous reads, so no async runtime is touched on this thread.
        let conns: Vec<ConclaveConnection> = self
            .active_connections
            .read()
            .map(|c| c.clone())
            .unwrap_or_default();

        // Server public keys shared by more than one connection, so those
        // windows can be disambiguated by the user's display name.
        let mut server_counts: HashMap<String, usize> = HashMap::new();
        for conn in &conns {
            *server_counts
                .entry(hex::encode(conn.server_info().key.as_bytes()))
                .or_default() += 1;
        }

        // Each snapshot is keyed uniquely per connection (server key + a
        // process-unique connection id) so two connections to the same server
        // don't collide on egui window/viewport ids or temp state.
        let conn_snapshots: Vec<(String, String, bool, ConclaveConnection)> = conns
            .into_iter()
            .map(|conn| {
                let info = conn.server_info();
                let server_key = hex::encode(info.key.as_bytes());
                let active = conn.connected_since().is_some();
                let key = format!("{server_key}:{}", conn.local_id());
                let name = if server_counts.get(&server_key).is_some_and(|&n| n > 1) {
                    format!("{} ({})", info.name, conn.display_name())
                } else {
                    info.name
                };
                (key, name, active, conn)
            })
            .collect();

        // Auto-open a user window once per newly-seen server and surface the
        // Connected Servers window when the first connection appears.
        for (key, _, _, _) in &conn_snapshots {
            if self.seen_servers.insert(key.clone()) {
                if let Ok(mut open) = self.open_user_windows.write() {
                    open.insert(key.clone());
                }
                self.show_servers_window = true;
            }
        }

        // Forget servers that are no longer connected so their windows close and
        // a later reconnect re-opens them.
        {
            let live: HashSet<String> = conn_snapshots.iter().map(|(k, ..)| k.clone()).collect();
            self.seen_servers.retain(|k| live.contains(k));
            if let Ok(mut open) = self.open_user_windows.write() {
                open.retain(|k| live.contains(k));
            }
            if let Ok(mut open) = self.open_admin_windows.write() {
                open.retain(|k| live.contains(k));
            }
        }

        conn_snapshots
    }

    /// Render the Connected Servers overview window when open.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn connected_servers_window(&mut self, ui: &mut egui::Ui, conn_snapshots: &[ConnSnapshot]) {
        // ── Connected Servers window ──────────────────────────────────────
        if self.show_servers_window {
            let closed_arc = self.servers_window_closed.clone();
            let active_conns = self.active_connections.clone();
            let open_windows = self.open_user_windows.clone();
            let open_admin = self.open_admin_windows.clone();
            let open_files = self.open_file_windows.clone();
            let open_chats = self.open_chats.clone();
            let open_forums = self.open_forum_windows.clone();
            let servers: Vec<ConnSnapshot> = conn_snapshots.to_vec();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of("connected_servers"),
                egui::ViewportBuilder::default()
                    .with_title("Connected Servers")
                    .with_inner_size([300.0, 360.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        closed_arc.store(true, Ordering::SeqCst);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    let mut disconnect_key: Option<String> = None;
                    let mut repaint_root = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.heading("Servers");
                        ui.separator();

                        if servers.is_empty() {
                            ui.label(egui::RichText::new("Not connected to any server.").weak());
                        }

                        for (key, name, active, conn) in &servers {
                            let info = conn.server_info();
                            let is_admin = conn.is_admin();
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    let label = if *active {
                                        name.clone()
                                    } else {
                                        format!("{name} (disconnected)")
                                    };
                                    ui.label(egui::RichText::new(label).strong());
                                    // A per-server actions menu, on the right: open
                                    // any feature the server supports, or disconnect.
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.menu_button("Open ⏷", |ui| {
                                                if ui.button("User list").clicked() {
                                                    if let Ok(mut o) = open_windows.write() {
                                                        o.insert(key.clone());
                                                    }
                                                    repaint_root = true;
                                                }
                                                // Chat: a submenu of the server's
                                                // rooms when chat is enabled.
                                                if info.chat_enabled {
                                                    let rooms = conn.chatrooms_available();
                                                    ui.menu_button("Chat", |ui| {
                                                        if rooms.is_empty() {
                                                            ui.add_enabled(
                                                                false,
                                                                egui::Button::new(
                                                                    "No chatrooms available",
                                                                ),
                                                            );
                                                        }
                                                        for room in &rooms {
                                                            if ui.button(&room.name).clicked() {
                                                                if let Ok(mut o) =
                                                                    open_chats.write()
                                                                {
                                                                    o.insert((
                                                                        key.clone(),
                                                                        room.id,
                                                                    ));
                                                                }
                                                                repaint_root = true;
                                                            }
                                                        }
                                                    });
                                                }
                                                if info.sharing_enabled
                                                    && ui.button("Files").clicked()
                                                {
                                                    if let Ok(mut o) = open_files.write() {
                                                        o.insert(key.clone());
                                                    }
                                                    repaint_root = true;
                                                }
                                                if info.forums_enabled
                                                    && ui.button("Forums").clicked()
                                                {
                                                    if let Ok(mut o) = open_forums.write() {
                                                        o.insert(key.clone());
                                                    }
                                                    repaint_root = true;
                                                }
                                                // The admin panel is offered only for
                                                // connections holding admin rights.
                                                if is_admin && ui.button("Admin").clicked() {
                                                    if let Ok(mut o) = open_admin.write() {
                                                        o.insert(key.clone());
                                                    }
                                                    repaint_root = true;
                                                }
                                                ui.separator();
                                                if ui.button("Disconnect").clicked() {
                                                    disconnect_key = Some(key.clone());
                                                }
                                            });
                                        },
                                    );
                                });
                            });
                        }
                    });

                    if repaint_root {
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }

                    if let Some(key) = disconnect_key {
                        // server_info() is a synchronous (std-lock) read, so it is safe
                        // to match on it while briefly holding the connections write lock.
                        // The window key is `{server_key}:{local_id}`, so reconstruct
                        // it per connection to find the exact one to disconnect.
                        let removed = active_conns.write().ok().and_then(|mut c| {
                            let idx = c.iter().position(|conn| {
                                format!(
                                    "{}:{}",
                                    hex::encode(conn.server_info().key),
                                    conn.local_id()
                                ) == key
                            });
                            idx.map(|i| c.remove(i))
                        });
                        if let Some(conn) = removed {
                            if let Ok(mut o) = open_windows.write() {
                                o.remove(&key);
                            }
                            tokio::spawn(async move {
                                let _ = conn.disconnect().await;
                            });
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }
                },
            );
        }
    }

    /// Render each open per-server user list window.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn user_windows(&mut self, ui: &mut egui::Ui, conn_snapshots: &[ConnSnapshot]) {
        // ── Per-server user windows ───────────────────────────────────────
        let open_keys: HashSet<String> = self
            .open_user_windows
            .read()
            .map(|o| o.clone())
            .unwrap_or_default();

        for (key, name, _active, conn) in conn_snapshots {
            if !open_keys.contains(key) {
                continue;
            }
            let conn = conn.clone();
            let key_owned = key.clone();
            let title = format!("Users — {name}");
            let close_reqs = self.user_window_close_requests.clone();
            let open_dms = self.open_dms.clone();
            let active_server = self.active_server.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("server_users:{key}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([420.0, 360.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    note_active_server(&active_server, ctx, &key_owned);
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push(key_owned.clone());
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    let server_info = conn.server_info();
                    let users = conn.get_connected_users();
                    let is_admin = conn.is_admin();
                    let details = conn.user_details();
                    let own_name = conn.display_name();

                    // Which user's detail panel is expanded (by connection id).
                    let selected_id = egui::Id::new(format!("user_details_sel:{key_owned}"));
                    let selected: Option<u16> = ctx
                        .data(|d| d.get_temp::<Option<u16>>(selected_id))
                        .flatten();

                    let mut details_request: Option<u16> = None;
                    let mut kick_request: Option<u16> = None;
                    let mut clear_selection = false;
                    let mut open_dm_request: Option<u16> = None;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.heading(format!("Users on {}", server_info.name));
                        ui.separator();

                        if users.is_empty() {
                            ui.label(egui::RichText::new("No users connected yet.").weak());
                        } else {
                            egui::ScrollArea::vertical()
                                .id_salt(format!("users_scroll:{key_owned}"))
                                .max_height(160.0)
                                .show(ui, |ui| {
                                    egui::Grid::new(format!("users_grid:{key_owned}"))
                                        .striped(true)
                                        .spacing([12.0, 4.0])
                                        .show(ui, |ui| {
                                            ui.label(egui::RichText::new("Name").strong());
                                            ui.label(egui::RichText::new("Connected").strong());
                                            ui.label("");
                                            ui.end_row();

                                            for user in &users {
                                                // Avatar (if any) then the name,
                                                // tinted its groups' colour and
                                                // dulled when idle.
                                                ui.horizontal(|ui| {
                                                    show_avatar(
                                                        ui,
                                                        user.avatar.as_deref(),
                                                        is_idle(user.idle),
                                                    );
                                                    ui.label(styled_name(
                                                        &user.display_name,
                                                        base_name_color(user),
                                                        is_idle(user.idle),
                                                    ));
                                                });
                                                ui.label(format_uptime(user.connected_since));
                                                ui.horizontal(|ui| {
                                                    // The Details button toggles the
                                                    // detail panel for this user.
                                                    let shown = selected == Some(user.id);
                                                    let label =
                                                        if shown { "Hide" } else { "Details" };
                                                    if ui.small_button(label).clicked() {
                                                        if shown {
                                                            clear_selection = true;
                                                        } else {
                                                            details_request = Some(user.id);
                                                        }
                                                    }
                                                    // Open a direct-message window (not
                                                    // to oneself); a lock marks that the
                                                    // peer's key allows E2E encryption.
                                                    if user.display_name != own_name {
                                                        let dm_label =
                                                            if conn.dm_encrypted_with(user.id) {
                                                                "🔒 Message"
                                                            } else {
                                                                "Message"
                                                            };
                                                        if ui.small_button(dm_label).clicked() {
                                                            open_dm_request = Some(user.id);
                                                        }
                                                    }
                                                });
                                                ui.end_row();
                                            }
                                        });
                                });
                        }

                        // ── Selected user's detail panel ──────────────────────
                        if let Some(sel) = selected {
                            if let Some(user) = users.iter().find(|u| u.id == sel) {
                                ui.separator();
                                ui.heading(&user.display_name);
                                ui.label(format!(
                                    "Connected: {}",
                                    format_uptime(user.connected_since)
                                ));
                                ui.label(format!("Idle: {}", format_uptime(user.idle)));
                                ui.label(timezone_offset_text(user.timezone, conn.own_timezone()));

                                match details.as_ref().filter(|d| d.connection_id == sel) {
                                    Some(d) => {
                                        if d.groups.is_empty() {
                                            ui.label("Groups: none");
                                        } else {
                                            ui.label(format!("Groups: {}", d.groups.join(", ")));
                                        }
                                        // Administrator-only fields.
                                        if let Some(username) = &d.username {
                                            ui.label(format!("Username: {username}"));
                                        }
                                        if let Some(ip) = &d.ip {
                                            ui.label(format!("IP: {ip}"));
                                        }
                                        // The user's shared profile and links.
                                        profile_view(ui, &d.profile, &d.urls);
                                        if is_admin && ui.button("Kick").clicked() {
                                            kick_request = Some(sel);
                                        }
                                    }
                                    None => {
                                        ui.label(egui::RichText::new("Loading details…").weak());
                                    }
                                }
                            } else {
                                // The selected user is no longer connected.
                                clear_selection = true;
                            }
                        }
                    });

                    // Perform queued actions outside the panel closure.
                    if let Some(peer) = open_dm_request {
                        if let Ok(mut open) = open_dms.write() {
                            open.insert((key_owned.clone(), peer));
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }
                    if let Some(id) = details_request {
                        ctx.data_mut(|d| d.insert_temp(selected_id, Some(id)));
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.request_user_details(id).await;
                        });
                    }
                    if let Some(id) = kick_request {
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.admin_kick_user(id).await;
                        });
                        ctx.data_mut(|d| d.insert_temp(selected_id, Option::<u16>::None));
                    }
                    if clear_selection {
                        ctx.data_mut(|d| d.insert_temp(selected_id, Option::<u16>::None));
                    }

                    // The server pushes roster changes automatically, and detail
                    // replies arrive asynchronously; repaint frequently so both
                    // are picked up promptly.
                    ctx.request_repaint_after(std::time::Duration::from_millis(200));
                },
            );
        }
    }

    /// Render each open chatroom window.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn chatroom_windows(&mut self, ui: &mut egui::Ui, conn_snapshots: &[ConnSnapshot]) {
        // ── Chatroom windows ──────────────────────────────────────────────
        // Drain close requests (leaving the room) and drop chats whose server
        // has disconnected.
        {
            let live: HashSet<String> = conn_snapshots.iter().map(|(k, ..)| k.clone()).collect();
            let closed: Vec<(String, u16)> = self
                .chat_window_close_requests
                .write()
                .map(|mut r| r.drain(..).collect())
                .unwrap_or_default();
            if let Ok(mut open) = self.open_chats.write() {
                for entry in &closed {
                    open.remove(entry);
                }
                open.retain(|(k, _)| live.contains(k));
            }
            for (k, room) in closed {
                if let Some((.., conn)) = conn_snapshots.iter().find(|(key, ..)| *key == k) {
                    let conn = conn.clone();
                    tokio::spawn(async move {
                        let _ = conn.chat_leave(room).await;
                    });
                }
            }
        }

        let open_chats: Vec<(String, u16)> = self
            .open_chats
            .read()
            .map(|o| o.iter().cloned().collect())
            .unwrap_or_default();

        for (key, room) in open_chats {
            let Some((_, server_name, _, conn)) = conn_snapshots.iter().find(|(k, ..)| *k == key)
            else {
                continue;
            };
            let conn = conn.clone();
            let key_owned = key.clone();
            let room_name = conn
                .chatrooms_available()
                .into_iter()
                .find(|r| r.id == room)
                .map_or_else(|| format!("Room {room}"), |r| r.name);
            // Fold the current topic (and who set it) into the window title.
            let title = match conn.chat_room(room).and_then(|s| s.topic) {
                Some(t) => format!(
                    "{room_name}: {} (set by {}) — {server_name}",
                    t.text, t.set_by
                ),
                None => format!("{room_name} — {server_name}"),
            };
            let close_reqs = self.chat_window_close_requests.clone();
            let active_server = self.active_server.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("chat:{key}:{room}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([640.0, 460.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    note_active_server(&active_server, ctx, &key_owned);
                    // Join the room when the window opens and leave when it
                    // closes (the close-drain spawns chat_leave). The joined flag
                    // is reset on close so reopening rejoins.
                    let joined_id = egui::Id::new(format!("chat_joined:{key_owned}:{room}"));
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push((key_owned.clone(), room));
                        }
                        ctx.data_mut(|d| d.insert_temp(joined_id, false));
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    } else if !ctx.data(|d| d.get_temp::<bool>(joined_id).unwrap_or(false)) {
                        ctx.data_mut(|d| d.insert_temp(joined_id, true));
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.chat_join(room).await;
                        });
                    }

                    let state = conn.chat_room(room).unwrap_or_default();
                    // Name colour and idle state per connected user, so chat
                    // names can be tinted (and dulled when idle) to match, plus
                    // each user's avatar keyed by display name.
                    let roster = conn.get_connected_users();
                    let user_styles: HashMap<String, (Option<egui::Color32>, bool)> = roster
                        .iter()
                        .map(|u| {
                            let style = (base_name_color(u), is_idle(u.idle));
                            (u.display_name.clone(), style)
                        })
                        .collect();
                    let user_avatars: HashMap<String, Vec<u8>> = roster
                        .into_iter()
                        .filter_map(|u| u.avatar.map(|a| (u.display_name, a)))
                        .collect();

                    let input_id = egui::Id::new(format!("chat_input:{key_owned}:{room}"));
                    let mut input: String = ctx.data(|d| d.get_temp(input_id).unwrap_or_default());
                    let mut send = false;

                    let topic_input_id =
                        egui::Id::new(format!("chat_topic_input:{key_owned}:{room}"));
                    let mut topic_input: String =
                        ctx.data(|d| d.get_temp(topic_input_id).unwrap_or_default());
                    // Whether the inline topic editor is open for this room.
                    let editing_topic_id =
                        egui::Id::new(format!("chat_topic_editing:{key_owned}:{room}"));
                    let mut editing_topic: bool =
                        ctx.data(|d| d.get_temp(editing_topic_id).unwrap_or(false));
                    // `None` = no change this frame; `Some(text)` sets the topic
                    // (an empty string clears it).
                    let mut set_topic: Option<String> = None;

                    // Top: the room topic. A pencil button opens an inline editor
                    // (input + Update + Clear); any member may set it. The topic
                    // and who set it also appear in the window title.
                    egui::Panel::top(format!("chat_topic:{key_owned}:{room}")).show(ctx, |ui| {
                        ui.add_space(4.0);
                        if editing_topic {
                            ui.horizontal(|ui| {
                                let response = ui.add(
                                    egui::TextEdit::singleline(&mut topic_input)
                                        .desired_width(ui.available_width() - 180.0)
                                        .hint_text("Room topic"),
                                );
                                let entered = response.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                if (ui.button("Update").clicked() || entered)
                                    && !topic_input.trim().is_empty()
                                {
                                    set_topic = Some(std::mem::take(&mut topic_input));
                                    editing_topic = false;
                                }
                                // Clearing sends an empty topic, which the server
                                // interprets as removing it.
                                if ui.button("Clear").clicked() {
                                    set_topic = Some(String::new());
                                    topic_input.clear();
                                    editing_topic = false;
                                }
                                if ui.button("✖").on_hover_text("Cancel").clicked() {
                                    editing_topic = false;
                                }
                            });
                        } else {
                            ui.horizontal_wrapped(|ui| {
                                if ui.button("✏").on_hover_text("Edit topic").clicked() {
                                    // Seed the editor with the current topic text.
                                    topic_input = state
                                        .topic
                                        .as_ref()
                                        .map(|t| t.text.clone())
                                        .unwrap_or_default();
                                    editing_topic = true;
                                }
                                match &state.topic {
                                    Some(t) => {
                                        ui.label(egui::RichText::new(&t.text).strong());
                                        ui.label(
                                            egui::RichText::new(format!("— set by {}", t.set_by))
                                                .weak(),
                                        );
                                    }
                                    None => {
                                        ui.label(egui::RichText::new("No topic set").weak());
                                    }
                                }
                            });
                        }
                        ui.add_space(4.0);
                    });

                    // Bottom: message composer.
                    egui::Panel::bottom(format!("chat_compose:{key_owned}:{room}")).show(
                        ctx,
                        |ui| {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                let response = ui.add(
                                    egui::TextEdit::singleline(&mut input)
                                        .desired_width(ui.available_width() - 60.0)
                                        .hint_text("Message"),
                                );
                                let entered = response.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                if (ui.button("Send").clicked() || entered)
                                    && !input.trim().is_empty()
                                {
                                    send = true;
                                }
                            });
                            ui.add_space(4.0);
                        },
                    );

                    // Right: the room's user list.
                    egui::Panel::right(format!("chat_users:{key_owned}:{room}"))
                        .resizable(true)
                        .default_size(140.0)
                        .show(ctx, |ui| {
                            ui.heading("Users");
                            ui.separator();
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                for user in &state.users {
                                    let (color, idle) =
                                        user_styles.get(user).copied().unwrap_or((None, false));
                                    ui.horizontal(|ui| {
                                        show_avatar(
                                            ui,
                                            user_avatars.get(user).map(Vec::as_slice),
                                            idle,
                                        );
                                        ui.label(styled_name(user, color, idle));
                                    });
                                }
                            });
                        });

                    // Center: the conversation.
                    egui::CentralPanel::default().show(ctx, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                for line in &state.lines {
                                    match line {
                                        ChatLine::System(text) => {
                                            ui.label(egui::RichText::new(text).weak().italics());
                                        }
                                        ChatLine::Message {
                                            time,
                                            display_name,
                                            message,
                                        } => {
                                            ui.horizontal_wrapped(|ui| {
                                                let idle = user_styles
                                                    .get(display_name)
                                                    .is_some_and(|(_, idle)| *idle);
                                                show_avatar(
                                                    ui,
                                                    user_avatars
                                                        .get(display_name)
                                                        .map(Vec::as_slice),
                                                    idle,
                                                );
                                                ui.label(
                                                    egui::RichText::new(
                                                        time.format("%H:%M:%S").to_string(),
                                                    )
                                                    .weak()
                                                    .monospace(),
                                                );
                                                ui.label(
                                                    egui::RichText::new(format!("{display_name}:"))
                                                        .strong(),
                                                );
                                                ui.label(message);
                                            });
                                        }
                                    }
                                }
                            });
                    });

                    if send {
                        let message = std::mem::take(&mut input);
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.chat_send(room, message).await;
                        });
                    }
                    if let Some(topic) = set_topic {
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.chat_set_topic(room, topic).await;
                        });
                    }
                    ctx.data_mut(|d| {
                        d.insert_temp(input_id, input);
                        d.insert_temp(topic_input_id, topic_input);
                        d.insert_temp(editing_topic_id, editing_topic);
                    });
                    // Messages arrive asynchronously; repaint so they show promptly.
                    ctx.request_repaint_after(std::time::Duration::from_millis(150));
                },
            );
        }
    }

    /// Render each open direct-message window.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn dm_windows(&mut self, ui: &mut egui::Ui, conn_snapshots: &[ConnSnapshot]) {
        // ── Direct-message windows ────────────────────────────────────────
        // Drain close requests and drop windows whose server disconnected.
        {
            let live: HashSet<String> = conn_snapshots.iter().map(|(k, ..)| k.clone()).collect();
            let closed: Vec<(String, u16)> = self
                .dm_window_close_requests
                .write()
                .map(|mut r| r.drain(..).collect())
                .unwrap_or_default();
            if let Ok(mut open) = self.open_dms.write() {
                for entry in &closed {
                    open.remove(entry);
                }
                open.retain(|(k, _)| live.contains(k));
            }
        }

        // Auto-open a window for any peer that just sent a direct message and
        // does not already have one open.
        for (key, _, _, conn) in conn_snapshots {
            let requests = conn.take_dm_open_requests();
            if requests.is_empty() {
                continue;
            }
            if let Ok(mut open) = self.open_dms.write() {
                for peer in requests {
                    open.insert((key.clone(), peer));
                }
            }
        }
        // Poll while connected so inbound messages surface even when the main
        // window is otherwise idle.
        if !conn_snapshots.is_empty() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(300));
        }

        let open_dms: Vec<(String, u16)> = self
            .open_dms
            .read()
            .map(|o| o.iter().cloned().collect())
            .unwrap_or_default();

        for (key, peer) in open_dms {
            let Some((_, server_name, _, conn)) = conn_snapshots.iter().find(|(k, ..)| *k == key)
            else {
                continue;
            };
            let conn = conn.clone();
            let key_owned = key.clone();
            let own_name = conn.display_name();
            let peer_name = conn
                .get_connected_users()
                .into_iter()
                .find(|u| u.id == peer)
                .map_or_else(|| format!("#{peer}"), |u| u.display_name);
            let encrypted = conn.dm_encrypted_with(peer);
            let fingerprint = conn.peer_key_fingerprint(peer);
            let title = format!("DM {peer_name} — {server_name}");
            let close_reqs = self.dm_window_close_requests.clone();
            let active_server = self.active_server.clone();

            // The window is identified by server name plus both display names,
            // as requested.
            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("dm:{server_name}:{own_name}:{peer_name}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([460.0, 420.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    note_active_server(&active_server, ctx, &key_owned);
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push((key_owned.clone(), peer));
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    let thread = conn.dm_thread(peer);
                    let input_id = egui::Id::new(format!("dm_input:{key_owned}:{peer}"));
                    let mut input: String = ctx.data(|d| d.get_temp(input_id).unwrap_or_default());
                    let mut send = false;

                    // Top: encryption status and the peer's key fingerprint.
                    egui::Panel::top(format!("dm_status:{key_owned}:{peer}")).show(ctx, |ui| {
                        ui.add_space(2.0);
                        if encrypted {
                            ui.label(
                                egui::RichText::new("🔒 End-to-end encrypted")
                                    .color(egui::Color32::from_rgb(0x33, 0xaa, 0x33))
                                    .strong(),
                            );
                            if let Some(fp) = &fingerprint {
                                ui.label(
                                    egui::RichText::new(format!("Key: {fp}"))
                                        .weak()
                                        .monospace()
                                        .small(),
                                );
                            }
                        } else {
                            ui.label(
                                egui::RichText::new("🔓 Not encrypted — peer has no key")
                                    .color(egui::Color32::from_rgb(0xcc, 0x88, 0x00)),
                            );
                        }
                        ui.add_space(2.0);
                    });

                    // Bottom: message composer.
                    egui::Panel::bottom(format!("dm_compose:{key_owned}:{peer}")).show(ctx, |ui| {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            let response = ui.add(
                                egui::TextEdit::singleline(&mut input)
                                    .desired_width(ui.available_width() - 60.0)
                                    .hint_text("Message"),
                            );
                            let entered = response.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            if (ui.button("Send").clicked() || entered) && !input.trim().is_empty()
                            {
                                send = true;
                            }
                        });
                        ui.add_space(4.0);
                    });

                    // Center: the conversation.
                    egui::CentralPanel::default().show(ctx, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                for msg in &thread {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(
                                            egui::RichText::new(
                                                msg.time.format("%H:%M:%S").to_string(),
                                            )
                                            .weak()
                                            .monospace(),
                                        );
                                        let who = if msg.from_me {
                                            "You"
                                        } else {
                                            peer_name.as_str()
                                        };
                                        ui.label(egui::RichText::new(format!("{who}:")).strong());
                                        ui.label(&msg.text);
                                    });
                                }
                            });
                    });

                    if send {
                        let message = std::mem::take(&mut input);
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.send_dm(peer, message).await;
                        });
                    }
                    ctx.data_mut(|d| d.insert_temp(input_id, input));
                    // Messages arrive asynchronously; repaint so they show promptly.
                    ctx.request_repaint_after(std::time::Duration::from_millis(150));
                },
            );
        }
    }

    /// Render each open file-browser window.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn file_windows(&mut self, ui: &mut egui::Ui, conn_snapshots: &[ConnSnapshot]) {
        // ── Per-server file-browser windows ───────────────────────────────
        {
            let live: HashSet<String> = conn_snapshots.iter().map(|(k, ..)| k.clone()).collect();
            let closed: Vec<String> = self
                .file_window_close_requests
                .write()
                .map(|mut r| r.drain(..).collect())
                .unwrap_or_default();
            if let Ok(mut open) = self.open_file_windows.write() {
                for key in &closed {
                    open.remove(key);
                }
                open.retain(|k| live.contains(k));
            }
        }
        let file_open_keys: HashSet<String> = self
            .open_file_windows
            .read()
            .map(|o| o.clone())
            .unwrap_or_default();

        for (key, name, _active, conn) in conn_snapshots {
            if !file_open_keys.contains(key) {
                continue;
            }
            let conn = conn.clone();
            let key_owned = key.clone();
            let title = format!("Files — {name}");
            let close_reqs = self.file_window_close_requests.clone();
            let active_server = self.active_server.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("server_files:{key}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([460.0, 420.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    note_active_server(&active_server, ctx, &key_owned);
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push(key_owned.clone());
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    let path_id = egui::Id::new(format!("file_path:{key_owned}"));
                    let req_id = egui::Id::new(format!("file_req:{key_owned}"));
                    let status_id = egui::Id::new(format!("file_status:{key_owned}"));
                    let mut path: String = ctx.data(|d| d.get_temp(path_id).unwrap_or_default());

                    // Fetch the listing whenever the path changes.
                    let requested: Option<String> = ctx.data(|d| d.get_temp(req_id));
                    if requested.as_deref() != Some(path.as_str()) {
                        ctx.data_mut(|d| d.insert_temp(req_id, path.clone()));
                        let c = conn.clone();
                        let p = path.clone();
                        tokio::spawn(async move {
                            let _ = c.request_file_list(p).await;
                        });
                    }

                    // Save a completed download.
                    if let Some(download) = conn.download()
                        && download.done
                    {
                        let name = download
                            .path
                            .rsplit('/')
                            .next()
                            .unwrap_or("download")
                            .to_string();
                        let status = match save_download(&name, &download.data) {
                            Ok(saved) => format!("Saved to {}", saved.display()),
                            Err(e) => format!("Failed to save {name}: {e}"),
                        };
                        ctx.data_mut(|d| d.insert_temp(status_id, status));
                        conn.clear_download();
                    }
                    let status: String = ctx.data(|d| d.get_temp(status_id).unwrap_or_default());

                    let mut nav: Option<String> = None;
                    let is_admin = conn.is_admin();

                    egui::CentralPanel::default().show(ctx, |ui| {
                        // Path bar.
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(!path.is_empty(), egui::Button::new("⬆ Up"))
                                .clicked()
                            {
                                nav = Some(
                                    path.rsplit_once('/')
                                        .map_or_else(String::new, |(parent, _)| parent.to_string()),
                                );
                            }
                            let shown = if path.is_empty() { "/" } else { path.as_str() };
                            ui.label(egui::RichText::new(shown).monospace());
                        });

                        // Create a new directory in the current folder (server-
                        // enforced by the Write permission).
                        ui.horizontal(|ui| {
                            let newdir_id = egui::Id::new(format!("newdir:{key_owned}"));
                            let mut newdir: String =
                                ui.data(|d| d.get_temp(newdir_id).unwrap_or_default());
                            ui.add(
                                egui::TextEdit::singleline(&mut newdir)
                                    .desired_width(140.0)
                                    .hint_text("new folder"),
                            );
                            if ui
                                .add_enabled(!newdir.trim().is_empty(), egui::Button::new("📁+"))
                                .on_hover_text("Create folder")
                                .clicked()
                            {
                                let target = if path.is_empty() {
                                    newdir.trim().to_string()
                                } else {
                                    format!("{path}/{}", newdir.trim())
                                };
                                let c = conn.clone();
                                let refresh = path.clone();
                                tokio::spawn(async move {
                                    let _ = c.create_dir(target).await;
                                    let _ = c.request_file_list(refresh).await;
                                });
                                newdir.clear();
                            }
                            ui.data_mut(|d| d.insert_temp(newdir_id, newdir));
                        });
                        ui.separator();

                        // Listing (only shown when it matches the current path).
                        match conn.file_listing() {
                            Some((listed, entries)) if listed == path => {
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    if entries.is_empty() {
                                        ui.label(egui::RichText::new("Empty.").weak());
                                    }
                                    for entry in &entries {
                                        ui.horizontal(|ui| {
                                            let child = if path.is_empty() {
                                                entry.name.clone()
                                            } else {
                                                format!("{path}/{}", entry.name)
                                            };
                                            if entry.is_dir {
                                                if ui.button(format!("📁 {}", entry.name)).clicked()
                                                {
                                                    nav = Some(child);
                                                }
                                            } else {
                                                ui.label(format!("📄 {}", entry.name));
                                                ui.label(
                                                    egui::RichText::new(human_size(entry.size))
                                                        .weak()
                                                        .small(),
                                                );
                                                if ui
                                                    .small_button("⬇")
                                                    .on_hover_text("Download")
                                                    .clicked()
                                                {
                                                    let c = conn.clone();
                                                    let target = child.clone();
                                                    tokio::spawn(async move {
                                                        let _ =
                                                            c.request_file_download(target).await;
                                                    });
                                                }
                                                // Deletion is server-enforced by the
                                                // Delete permission; the listing is
                                                // refreshed afterwards.
                                                if ui
                                                    .small_button("🗑")
                                                    .on_hover_text("Delete")
                                                    .clicked()
                                                {
                                                    let c = conn.clone();
                                                    let target = child.clone();
                                                    let refresh = path.clone();
                                                    tokio::spawn(async move {
                                                        let _ = c.delete_file(target).await;
                                                        let _ = c.request_file_list(refresh).await;
                                                    });
                                                }
                                            }
                                        });
                                    }
                                });
                            }
                            _ => {
                                ui.label(egui::RichText::new("Loading…").weak());
                            }
                        }

                        // Download progress / status.
                        if let Some(download) = conn.download() {
                            if !download.done {
                                ui.separator();
                                ui.label(format!(
                                    "Downloading {}: {} / {}",
                                    download.path,
                                    human_size(download.data.len() as u64),
                                    human_size(download.size),
                                ));
                            }
                        } else if !status.is_empty() {
                            ui.separator();
                            ui.label(egui::RichText::new(&status).weak());
                        }

                        // Upload (server-enforced by the Write permission). A
                        // drop box works even without List: type the destination
                        // folder directly.
                        ui.separator();
                        file_upload_panel(ui, &conn, &key_owned, &path);

                        // Admin: per-directory permissions.
                        if is_admin {
                            ui.separator();
                            file_acl_editor(ui, &conn, &key_owned, &path);
                        }
                    });

                    if let Some(target) = nav {
                        path = target;
                    }
                    ctx.data_mut(|d| d.insert_temp(path_id, path));
                    ctx.request_repaint_after(std::time::Duration::from_millis(200));
                },
            );
        }
    }

    /// Render each open forum window.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn forum_windows(&mut self, ui: &mut egui::Ui, conn_snapshots: &[ConnSnapshot]) {
        // ── Per-server forum windows ──────────────────────────────────────
        {
            let live: HashSet<String> = conn_snapshots.iter().map(|(k, ..)| k.clone()).collect();
            let closed: Vec<String> = self
                .forum_window_close_requests
                .write()
                .map(|mut r| r.drain(..).collect())
                .unwrap_or_default();
            if let Ok(mut open) = self.open_forum_windows.write() {
                for key in &closed {
                    open.remove(key);
                }
                open.retain(|k| live.contains(k));
            }
        }
        let forum_open_keys: HashSet<String> = self
            .open_forum_windows
            .read()
            .map(|o| o.clone())
            .unwrap_or_default();

        for (key, name, _active, conn) in conn_snapshots {
            if !forum_open_keys.contains(key) {
                continue;
            }
            let conn = conn.clone();
            let key_owned = key.clone();
            let title = format!("Forums — {name}");
            let close_reqs = self.forum_window_close_requests.clone();
            let active_server = self.active_server.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("server_forums:{key}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([560.0, 500.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    note_active_server(&active_server, ctx, &key_owned);
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push(key_owned.clone());
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    let topic_id = egui::Id::new(format!("forum_topic:{key_owned}"));
                    let thread_id = egui::Id::new(format!("forum_thread:{key_owned}"));
                    let opened_id = egui::Id::new(format!("forum_opened:{key_owned}"));
                    let treq_id = egui::Id::new(format!("forum_treq:{key_owned}"));
                    let nt_subject_id = egui::Id::new(format!("forum_nt_subject:{key_owned}"));
                    let nt_body_id = egui::Id::new(format!("forum_nt_body:{key_owned}"));
                    let nt_md_id = egui::Id::new(format!("forum_nt_md:{key_owned}"));
                    let nt_sign_id = egui::Id::new(format!("forum_nt_sign:{key_owned}"));
                    let reply_to_id = egui::Id::new(format!("forum_reply_to:{key_owned}"));
                    let reply_body_id = egui::Id::new(format!("forum_reply_body:{key_owned}"));
                    let reply_md_id = egui::Id::new(format!("forum_reply_md:{key_owned}"));
                    let reply_sign_id = egui::Id::new(format!("forum_reply_sign:{key_owned}"));

                    let mut sel_topic: Option<u32> = ctx.data(|d| d.get_temp(topic_id)).flatten();
                    let mut sel_thread: Option<u32> = ctx.data(|d| d.get_temp(thread_id)).flatten();
                    let mut nt_subject: String =
                        ctx.data(|d| d.get_temp(nt_subject_id).unwrap_or_default());
                    let mut nt_body: String =
                        ctx.data(|d| d.get_temp(nt_body_id).unwrap_or_default());
                    let mut nt_md: bool = ctx.data(|d| d.get_temp(nt_md_id).unwrap_or(false));
                    let mut nt_sign: bool = ctx.data(|d| d.get_temp(nt_sign_id).unwrap_or(false));
                    let mut reply_to: Option<u32> = ctx.data(|d| d.get_temp(reply_to_id)).flatten();
                    let mut reply_body: String =
                        ctx.data(|d| d.get_temp(reply_body_id).unwrap_or_default());
                    let mut reply_md: bool = ctx.data(|d| d.get_temp(reply_md_id).unwrap_or(false));
                    let mut reply_sign: bool =
                        ctx.data(|d| d.get_temp(reply_sign_id).unwrap_or(false));

                    let is_admin = conn.is_admin();
                    let topics = conn.forum_topics();

                    let mut open_topic: Option<Option<u32>> = None;
                    let mut open_thread: Option<Option<u32>> = None;
                    let mut post_actions: Vec<ForumAction> = Vec::new();
                    let mut create_thread = false;
                    let mut send_reply = false;

                    egui::CentralPanel::default().show(ctx, |ui| {
                        // Breadcrumb navigation.
                        ui.horizontal(|ui| {
                            if ui.selectable_label(sel_topic.is_none(), "Topics").clicked() {
                                open_topic = Some(None);
                                open_thread = Some(None);
                            }
                            if let Some(tid) = sel_topic {
                                let tname = topics
                                    .iter()
                                    .find(|t| t.id == tid)
                                    .map_or_else(|| format!("Topic {tid}"), |t| t.name.clone());
                                ui.label("›");
                                if ui.selectable_label(sel_thread.is_none(), tname).clicked() {
                                    open_thread = Some(None);
                                }
                                if let Some(th) = sel_thread {
                                    let subject = conn
                                        .forum_threads(tid)
                                        .into_iter()
                                        .find(|t| t.id == th)
                                        .map_or_else(|| format!("Thread {th}"), |t| t.subject);
                                    ui.label("›");
                                    ui.label(egui::RichText::new(subject).strong());
                                }
                            }
                        });
                        ui.separator();

                        match (sel_topic, sel_thread) {
                            // Topic list.
                            (None, _) => {
                                if topics.is_empty() {
                                    ui.label(egui::RichText::new("No topics available.").weak());
                                }
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    for topic in &topics {
                                        ui.horizontal(|ui| {
                                            if ui.button(&topic.name).clicked() {
                                                open_topic = Some(Some(topic.id));
                                            }
                                            if !topic.description.is_empty() {
                                                ui.label(
                                                    egui::RichText::new(&topic.description).weak(),
                                                );
                                            }
                                        });
                                    }
                                });
                            }
                            // Thread list + new-thread form.
                            (Some(topic), None) => {
                                let threads = conn.forum_threads(topic);
                                egui::ScrollArea::vertical()
                                    .max_height(260.0)
                                    .show(ui, |ui| {
                                        if threads.is_empty() {
                                            ui.label(egui::RichText::new("No threads yet.").weak());
                                        }
                                        for th in &threads {
                                            ui.horizontal(|ui| {
                                                if ui.button(&th.subject).clicked() {
                                                    open_thread = Some(Some(th.id));
                                                }
                                                ui.label(
                                                    egui::RichText::new(format!(
                                                        "by {} · {} repl{} · {}",
                                                        th.author_name,
                                                        th.reply_count,
                                                        if th.reply_count == 1 {
                                                            "y"
                                                        } else {
                                                            "ies"
                                                        },
                                                        th.last_activity.format("%Y-%m-%d %H:%M")
                                                    ))
                                                    .weak()
                                                    .small(),
                                                );
                                            });
                                        }
                                    });
                                ui.separator();
                                ui.label(egui::RichText::new("New thread").strong());
                                ui.add(
                                    egui::TextEdit::singleline(&mut nt_subject)
                                        .hint_text("Subject")
                                        .desired_width(f32::INFINITY),
                                );
                                ui.add(
                                    egui::TextEdit::multiline(&mut nt_body)
                                        .hint_text("Body")
                                        .desired_rows(3)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut nt_md, "Markdown");
                                    ui.checkbox(&mut nt_sign, "Sign");
                                    let can =
                                        !nt_subject.trim().is_empty() && !nt_body.trim().is_empty();
                                    if ui.add_enabled(can, egui::Button::new("Create")).clicked() {
                                        create_thread = true;
                                    }
                                });
                            }
                            // Thread view: posts + reply composer.
                            (Some(_topic), Some(thread)) => {
                                egui::ScrollArea::vertical()
                                    .max_height(320.0)
                                    .show(ui, |ui| match conn.forum_posts(thread) {
                                        Some(posts) if !posts.is_empty() => {
                                            render_forum_posts(
                                                ui,
                                                &key_owned,
                                                &posts,
                                                None,
                                                0,
                                                is_admin,
                                                &mut post_actions,
                                            );
                                        }
                                        Some(_) => {
                                            ui.label(egui::RichText::new("No posts.").weak());
                                        }
                                        None => {
                                            ui.horizontal(|ui| {
                                                ui.add(egui::Spinner::new());
                                                ui.label("Loading…");
                                            });
                                        }
                                    });
                                ui.separator();
                                ui.horizontal(|ui| {
                                    let label = match reply_to {
                                        Some(id) => format!("Replying to post #{id}"),
                                        None => "Reply to thread".to_string(),
                                    };
                                    ui.label(egui::RichText::new(label).small());
                                    if reply_to.is_some() && ui.small_button("clear").clicked() {
                                        reply_to = None;
                                    }
                                });
                                ui.add(
                                    egui::TextEdit::multiline(&mut reply_body)
                                        .hint_text("Reply")
                                        .desired_rows(2)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut reply_md, "Markdown");
                                    ui.checkbox(&mut reply_sign, "Sign");
                                    if ui
                                        .add_enabled(
                                            !reply_body.trim().is_empty(),
                                            egui::Button::new("Send"),
                                        )
                                        .clicked()
                                    {
                                        send_reply = true;
                                    }
                                });
                            }
                        }
                    });

                    // Apply navigation.
                    if let Some(v) = open_topic {
                        sel_topic = v;
                        sel_thread = None;
                    }
                    if let Some(v) = open_thread {
                        sel_thread = v;
                    }

                    // Apply post actions (reply target / delete).
                    for action in post_actions {
                        match action {
                            ForumAction::Reply(pid) => reply_to = Some(pid),
                            ForumAction::Delete(pid) => {
                                let c = conn.clone();
                                tokio::spawn(async move {
                                    let _ = c.delete_forum_post(pid).await;
                                });
                            }
                        }
                    }

                    // Keep the thread subscription in sync with the selection.
                    let current_open: Option<u32> = ctx.data(|d| d.get_temp(opened_id)).flatten();
                    if current_open != sel_thread {
                        if let Some(old) = current_open {
                            let c = conn.clone();
                            tokio::spawn(async move {
                                let _ = c.close_forum_thread(old).await;
                            });
                        }
                        if let Some(new) = sel_thread {
                            let c = conn.clone();
                            tokio::spawn(async move {
                                let _ = c.open_forum_thread(new).await;
                            });
                        }
                        ctx.data_mut(|d| d.insert_temp(opened_id, sel_thread));
                    }

                    // Fetch a topic's thread list the first time it is viewed.
                    if let Some(topic) = sel_topic
                        && sel_thread.is_none()
                    {
                        let requested: Option<u32> = ctx.data(|d| d.get_temp(treq_id)).flatten();
                        if requested != Some(topic) {
                            ctx.data_mut(|d| d.insert_temp(treq_id, Some(topic)));
                            let c = conn.clone();
                            tokio::spawn(async move {
                                let _ = c.request_forum_threads(topic).await;
                            });
                        }
                    }

                    if create_thread && let Some(topic) = sel_topic {
                        let subject = std::mem::take(&mut nt_subject);
                        let body = std::mem::take(&mut nt_body);
                        let (md, sign) = (nt_md, nt_sign);
                        let c = conn.clone();
                        tokio::spawn(async move {
                            let _ = c.new_forum_thread(topic, subject, body, md, sign).await;
                        });
                    }

                    if send_reply && let Some(thread) = sel_thread {
                        let body = std::mem::take(&mut reply_body);
                        let (md, sign) = (reply_md, reply_sign);
                        // A "reply to thread" (no explicit target) attaches under
                        // the opening post so the tree stays rooted.
                        let parent = reply_to.or_else(|| {
                            conn.forum_posts(thread).and_then(|posts| {
                                posts.iter().find(|p| p.reply_to.is_none()).map(|p| p.id)
                            })
                        });
                        reply_to = None;
                        let c = conn.clone();
                        tokio::spawn(async move {
                            let _ = c.new_forum_post(thread, parent, body, md, sign).await;
                        });
                    }

                    ctx.data_mut(|d| {
                        d.insert_temp(topic_id, sel_topic);
                        d.insert_temp(thread_id, sel_thread);
                        d.insert_temp(nt_subject_id, nt_subject);
                        d.insert_temp(nt_body_id, nt_body);
                        d.insert_temp(nt_md_id, nt_md);
                        d.insert_temp(nt_sign_id, nt_sign);
                        d.insert_temp(reply_to_id, reply_to);
                        d.insert_temp(reply_body_id, reply_body);
                        d.insert_temp(reply_md_id, reply_md);
                        d.insert_temp(reply_sign_id, reply_sign);
                    });
                    ctx.request_repaint_after(std::time::Duration::from_millis(250));
                },
            );
        }
    }

    /// Render each open administration window.
    #[inline]
    fn admin_windows(&mut self, ui: &mut egui::Ui, conn_snapshots: &[ConnSnapshot]) {
        // ── Per-server admin windows (admin connections only) ─────────────
        let admin_open_keys: HashSet<String> = self
            .open_admin_windows
            .read()
            .map(|o| o.clone())
            .unwrap_or_default();

        for (key, name, _active, conn) in conn_snapshots {
            if !admin_open_keys.contains(key) || !conn.is_admin() {
                continue;
            }
            let conn = conn.clone();
            let key_owned = key.clone();
            let title = format!("Admin — {name}");
            let close_reqs = self.admin_window_close_requests.clone();
            let active_server = self.active_server.clone();

            ui.ctx().show_viewport_deferred(
                egui::ViewportId::from_hash_of(format!("server_admin:{key}")),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([500.0, 400.0])
                    .with_resizable(true),
                move |ctx, _class| {
                    note_active_server(&active_server, ctx, &key_owned);
                    if ctx.input(|i| i.viewport().close_requested()) {
                        if let Ok(mut r) = close_reqs.write() {
                            r.push(key_owned.clone());
                        }
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    conclave_client::adminui::admin_ui(ctx, &conn, &key_owned);
                },
            );
        }
    }

    /// Render the root connection-launcher panel.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn root_window(&mut self, ui: &mut egui::Ui, conn_snapshots: &[ConnSnapshot]) {
        // ── Root window: connection launcher ──────────────────────────────
        // The active server's banner (or a placeholder) tops the main window.
        let active_key = self.active_server.read().ok().and_then(|a| a.clone());
        let active_banner = active_key.as_ref().and_then(|key| {
            conn_snapshots
                .iter()
                .find(|(k, ..)| k == key)
                .and_then(|(.., conn)| conn.server_banner())
        });
        egui::CentralPanel::default().show(ui, |ui| {
            render_banner(ui, active_banner.as_deref());
            ui.separator();
            if !conn_snapshots.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(format!("Connected to {} server(s).", conn_snapshots.len()));
                    if ui.small_button("Show Servers").clicked() {
                        self.show_servers_window = true;
                    }
                });
                ui.separator();
            }

            {
                // The main window is a launcher: it shows connection status and,
                // when opened from the Connect menu, the Direct Connect form. All
                // ways to connect live in the Connect menu.
                ui.vertical_centered(|ui| {
                    // ── Connection status (bookmark or in-flight connect) ─────
                    let bm_is_pending = self.connect_pending.load(Ordering::SeqCst);
                    let bm_error: Option<String> =
                        self.connect_error.read().ok().and_then(|e| e.clone());

                    if bm_is_pending {
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new());
                            ui.label("Connecting…");
                        });
                    }
                    if let Some(ref err) = bm_error {
                        ui.add_space(4.0);
                        ui.colored_label(egui::Color32::RED, err);
                    }

                    // ── Direct Connect form ───────────────────────────────────
                    if self.show_direct_connect {
                        ui.add_space(16.0);
                        ui.separator();
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Direct Connect").strong());

                        let host_id = egui::Id::new("direct_connect_host");
                        let port_id = egui::Id::new("direct_connect_port");
                        let mut host: String =
                            ui.ctx().data(|d| d.get_temp(host_id).unwrap_or_default());
                        let mut port_str: String = ui
                            .ctx()
                            .data(|d| d.get_temp(port_id).unwrap_or_else(|| "9101".to_string()));

                        // A completed SRV lookup fills in the resolved host and
                        // port so the user can see and use them.
                        if let Some((srv_host, srv_port)) =
                            self.srv_result.write().ok().and_then(|mut r| r.take())
                        {
                            host = srv_host;
                            port_str = srv_port.to_string();
                        }

                        ui.horizontal(|ui| {
                            ui.label("Host:");
                            ui.text_edit_singleline(&mut host);
                            ui.label("Port:");
                            ui.add(
                                egui::TextEdit::singleline(&mut port_str)
                                    .desired_width(60.0)
                                    .hint_text("SRV"),
                            );
                        });

                        let port_ok = port_str.parse::<u16>().is_ok();
                        let no_port = port_str.trim().is_empty();
                        let srv_pending = self.srv_pending.load(Ordering::SeqCst);
                        // Connecting is allowed with a valid port, or with no
                        // port (which triggers an SRV lookup instead).
                        let can_connect = !host.is_empty()
                            && (port_ok || no_port)
                            && !bm_is_pending
                            && !srv_pending;

                        ui.add_space(4.0);
                        if ui
                            .add_enabled(can_connect, egui::Button::new("Connect"))
                            .clicked()
                        {
                            if no_port {
                                // No port: look up the SRV record and, if
                                // successful, fill in the host and port above.
                                // Errors are ignored.
                                self.srv_pending.store(true, Ordering::SeqCst);
                                let lookup_host = host.clone();
                                let result = self.srv_result.clone();
                                let pending = self.srv_pending.clone();
                                tokio::spawn(async move {
                                    if let Ok(found) =
                                        conclave_client::lookup_srv_record(&lookup_host).await
                                        && let Ok(mut slot) = result.write()
                                    {
                                        *slot = Some(found);
                                    }
                                    pending.store(false, Ordering::SeqCst);
                                });
                            } else {
                                let port = port_str.parse::<u16>().unwrap_or(9101);
                                if let Ok(mut p) = self.pending_server.write() {
                                    *p = Some(PendingServer {
                                        host: host.clone(),
                                        port,
                                        key: None,
                                        name: format!("{host}:{port}"),
                                        anonymous_allowed: true,
                                    });
                                }
                                if let Ok(mut e) = self.connect_error.write() {
                                    *e = None;
                                }
                            }
                        }

                        ui.ctx().data_mut(|d| {
                            d.insert_temp(host_id, host);
                            d.insert_temp(port_id, port_str);
                        });
                    }

                    // When nothing else is on screen, point to the Connect menu.
                    if !self.show_direct_connect && conn_snapshots.is_empty() {
                        ui.add_space(24.0);
                        ui.label(
                            egui::RichText::new(
                                "Use the Connect menu to find and connect to a server.",
                            )
                            .weak(),
                        );
                    }
                });

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    egui::warn_if_debug_build(ui);
                });
            }
        });
    }
}
