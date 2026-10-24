// SPDX-License-Identifier: Apache-2.0

//! Open/closed bookkeeping for deferred viewports.
//!
//! A deferred viewport's closure runs outside `ConclaveGUI::ui` and cannot
//! borrow the GUI state, so a window that the user closes reports it through a
//! shared handle. The root frame then applies that report on its next pass.

use std::collections::HashSet;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use eframe::egui;

/// Handle the OS close button inside a viewport closure: run `on_close`, wake
/// the root viewport so it notices promptly, and close this viewport. Returns
/// whether a close was requested this frame.
fn handle_close_request(ctx: &egui::Context, on_close: impl FnOnce()) -> bool {
    if !ctx.input(|i| i.viewport().close_requested()) {
        return false;
    }
    on_close();
    ctx.request_repaint_of(egui::ViewportId::ROOT);
    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    true
}

/// Close signal for a single-instance viewport, set from inside its closure.
#[derive(Clone, Debug, Default)]
pub struct CloseFlag(Arc<AtomicBool>);

impl CloseFlag {
    /// Call from the viewport closure. Returns whether the window is closing.
    pub fn handle(&self, ctx: &egui::Context) -> bool {
        handle_close_request(ctx, || self.0.store(true, Ordering::SeqCst))
    }

    /// Whether the window was closed since the last call (clears the flag).
    pub fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

/// A single-instance window: whether it is shown, and its close signal.
#[derive(Debug, Default)]
pub struct Window {
    /// Whether the window is shown. Toggle directly, e.g. from a menu checkbox.
    pub open: bool,
    closed: CloseFlag,
}

impl Window {
    /// Apply a close made from the viewport closure. Call once per frame.
    pub fn sync(&mut self) {
        if self.closed.take() {
            self.open = false;
        }
    }

    /// The close signal to move into the viewport closure.
    pub fn closer(&self) -> CloseFlag {
        self.closed.clone()
    }
}

/// A family of windows, one per key (e.g. per server, or per chatroom). Cheap
/// to clone; clones share state, so a clone can be moved into a closure to
/// open or close windows from there.
#[derive(Debug)]
pub struct WindowSet<K> {
    open: Arc<RwLock<HashSet<K>>>,
    closed: Arc<RwLock<Vec<K>>>,
}

impl<K> Default for WindowSet<K> {
    fn default() -> Self {
        Self {
            open: Arc::default(),
            closed: Arc::default(),
        }
    }
}

impl<K> Clone for WindowSet<K> {
    fn clone(&self) -> Self {
        Self {
            open: self.open.clone(),
            closed: self.closed.clone(),
        }
    }
}

impl<K: Clone + Eq + Hash> WindowSet<K> {
    /// Open the window for `key` (no-op if it is already open).
    pub fn open(&self, key: K) {
        self.open
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
    }

    /// Close the window for `key` immediately.
    pub fn remove(&self, key: &K) {
        self.open
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    /// Keep only the windows for which `keep` returns true.
    pub fn retain(&self, keep: impl FnMut(&K) -> bool) {
        self.open
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(keep);
    }

    /// A snapshot of the open keys.
    pub fn keys(&self) -> HashSet<K> {
        self.open
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Call from the viewport closure for `key`. Queues the close for
    /// [`Self::drain_closed`] and returns whether the window is closing.
    pub fn handle_close(&self, ctx: &egui::Context, key: &K) -> bool {
        handle_close_request(ctx, || {
            self.closed
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .push(key.clone());
        })
    }

    /// Forget windows closed from their closures since the last call, and
    /// return their keys so the caller can run any follow-up (e.g. leaving a
    /// chatroom). Call once per frame.
    pub fn drain_closed(&self) -> Vec<K> {
        let closed: Vec<K> = self
            .closed
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect();
        if !closed.is_empty() {
            let mut open = self.open.write().unwrap_or_else(PoisonError::into_inner);
            for key in &closed {
                open.remove(key);
            }
        }
        closed
    }
}

/// Every window the GUI opens besides the root one.
#[derive(Debug, Default)]
pub struct Windows {
    pub about: Window,
    pub settings: Window,
    /// Local server discovery (mDNS)
    pub discovery: Window,
    /// Known trackers
    pub trackers: Window,
    /// Servers advertised via trackers
    pub tracker_servers: Window,
    /// Bookmarks window
    pub bookmarks: Window,
    /// Window for directly connecting to a server
    pub direct_connect: Window,
    /// Connected Servers overview
    pub servers: Window,
    /// The login window is shown while a server is pending, so it has only a
    /// close signal.
    pub login_closed: CloseFlag,
    /// Per-server user lists, keyed by server key
    pub users: WindowSet<String>,
    /// Per-server administration (admin connections only), keyed by server key
    pub admin: WindowSet<String>,
    /// Chatrooms, keyed by (server key, room id)
    pub chats: WindowSet<(String, u16)>,
    /// Direct messages, keyed by (server key, peer connection id)
    pub dms: WindowSet<(String, u16)>,
    /// Per-server file browsers, keyed by server key
    pub files: WindowSet<String>,
    /// Per-server forums, keyed by server key
    pub forums: WindowSet<String>,
}
