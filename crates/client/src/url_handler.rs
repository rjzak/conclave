// SPDX-License-Identifier: Apache-2.0

//! Getting `conclave://` links from the operating system to the GUI.
//!
//! How a clicked link reaches the client depends on the platform. On Linux and
//! Windows the client is started with the link as an argument, a new process
//! per click. On macOS it is never an argument: Launch Services starts the
//! client if it is not running, and either way hands the link over as an Apple
//! Event, which can arrive before the GUI exists or long after.
//!
//! Both paths end in [`deliver`], which queues the link for the GUI to collect
//! with [`take`] on its next frame and wakes the GUI so that frame comes now.

use std::sync::{Mutex, OnceLock, PoisonError};

use eframe::egui;

/// Links that have arrived and the GUI has not collected yet.
static PENDING: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The GUI's context, once there is one, to wake it when a link arrives.
static GUI: OnceLock<egui::Context> = OnceLock::new();

/// Queue a link for the GUI, and wake the GUI if it is already running.
pub fn deliver(url: String) {
    PENDING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(url);
    if let Some(ctx) = GUI.get() {
        ctx.request_repaint();
    }
}

/// Every link that has arrived since the last call, oldest first.
pub fn take() -> Vec<String> {
    std::mem::take(&mut *PENDING.lock().unwrap_or_else(PoisonError::into_inner))
}

/// Tell this module which context to wake when a link arrives. Links that
/// came in before there was one are already queued, and the GUI's first frame
/// collects them.
pub fn attach(ctx: &egui::Context) {
    let _ = GUI.set(ctx.clone());
}

/// Start listening for links the operating system sends, rather than passes on
/// the command line. Call before the event loop starts.
pub fn listen() {
    #[cfg(target_os = "macos")]
    apple::listen();
}

/// Make sure the operating system knows this client opens `conclave://` links,
/// where the client can see to that itself.
///
/// Only Windows needs it: there the scheme lives in the registry, and with no
/// installer to put it there, the client does it on start. On macOS the app
/// bundle declares the scheme; on Linux a desktop entry does.
///
/// Debug builds leave the registry alone, so that `cargo run` does not claim
/// the scheme for a binary in a build directory.
pub fn register() {
    #[cfg(all(target_os = "windows", not(debug_assertions)))]
    registry::register();
}

/// The open command a scheme registration holds, and when to write one.
///
/// Plain string work, kept apart from the registry so it is tested on every
/// platform. Only release builds on Windows use it.
#[cfg_attr(
    not(all(target_os = "windows", not(debug_assertions))),
    allow(dead_code)
)]
mod command {
    use std::path::{Path, PathBuf};

    /// The command Windows runs to open a link with `exe`: the program, then the
    /// link in place of `%1`, each quoted against spaces in the path.
    pub(super) fn open_command(exe: &Path) -> String {
        format!("\"{}\" \"%1\"", exe.display())
    }

    /// The program a registered open command runs: the first word of it, or the
    /// whole quoted path when it is quoted.
    pub(super) fn command_program(command: &str) -> Option<PathBuf> {
        let command = command.trim_start();
        let program = match command.strip_prefix('"') {
            Some(quoted) => quoted.split('"').next()?,
            None => command.split_whitespace().next()?,
        };
        (!program.is_empty()).then(|| PathBuf::from(program))
    }

    /// Whether the scheme needs registering, given the open command already
    /// registered for it, if any.
    ///
    /// A registration is left alone as long as the program it runs is still
    /// there, whichever program that is: it may be another copy of the client the
    /// user prefers, and this is a convenience, not a claim. One whose program has
    /// gone — the client moved or was deleted — is no use to anybody and is
    /// replaced.
    pub(super) fn needs_registering(
        existing: Option<&str>,
        exists: impl Fn(&Path) -> bool,
    ) -> bool {
        existing
            .and_then(command_program)
            .is_none_or(|program| !exists(&program))
    }
}

/// The Windows side: the scheme's keys in the registry.
///
/// They are written under `HKEY_CURRENT_USER\Software\Classes`, which needs no
/// administrator rights and touches no other user's settings. They are read
/// through `HKEY_CLASSES_ROOT`, the merged view Windows itself uses, so a
/// machine-wide registration from an installer counts as already registered.
#[cfg(all(target_os = "windows", not(debug_assertions)))]
mod registry {
    use std::path::Path;

    use tracing::{info, warn};
    use windows_registry::{CLASSES_ROOT, CURRENT_USER};

    /// The scheme's key, under `Software\Classes` or `HKEY_CLASSES_ROOT`.
    const SCHEME: &str = "conclave";

    /// The scheme's open command, under its key.
    const COMMAND: &str = r"shell\open\command";

    /// Register the scheme for this user if it is not usefully registered.
    pub(super) fn register() {
        let existing = CLASSES_ROOT
            .open(format!(r"{SCHEME}\{COMMAND}"))
            .and_then(|key| key.get_string(""))
            .ok();
        if !super::command::needs_registering(existing.as_deref(), Path::exists) {
            return;
        }
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => {
                warn!("Not registering conclave:// links: cannot tell where this client is: {e}");
                return;
            }
        };
        match write(&exe) {
            Ok(()) => info!("Registered {} to open conclave:// links", exe.display()),
            Err(e) => warn!("Could not register conclave:// links: {e}"),
        }
    }

    /// Write the scheme's keys for this user, with `exe` to open links.
    fn write(exe: &Path) -> windows_registry::Result<()> {
        let classes = CURRENT_USER.create(r"Software\Classes")?;
        let scheme = classes.create(SCHEME)?;
        scheme.set_string("", "URL:Conclave")?;
        // Present and empty is what marks a key as a URL scheme.
        scheme.set_string("URL Protocol", "")?;
        scheme
            .create("DefaultIcon")?
            .set_string("", format!("\"{}\",0", exe.display()))?;
        scheme
            .create(COMMAND)?
            .set_string("", super::command::open_command(exe))
    }
}

/// The macOS side: the "get URL" Apple Event.
///
/// The handler has to be in place before the event is dispatched, which for a
/// link that launched the client happens during launch. It cannot be installed
/// before launch begins either: `NSApplication` installs its own handlers as it
/// starts up, over the top of anything already there. The window between the
/// two is `applicationWillFinishLaunching`, so this watches for the
/// notification of that and installs the handler when it arrives. winit owns
/// the application delegate, so a notification observer is the way in that
/// does not take it from winit.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod apple {
    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, NSObject};
    use objc2::{AnyThread, define_class, msg_send, sel};
    use objc2_foundation::{
        NSAppleEventDescriptor, NSAppleEventManager, NSNotification, NSNotificationCenter, NSString,
    };

    /// `kInternetEventClass` and `kAEGetURL`, both the four-character code
    /// `'GURL'`.
    const GET_URL: u32 = u32::from_be_bytes(*b"GURL");

    /// `keyDirectObject`, `'----'`: the parameter holding the link itself.
    const DIRECT_OBJECT: u32 = u32::from_be_bytes(*b"----");

    /// The value of `NSApplicationWillFinishLaunchingNotification`. Spelled
    /// out rather than linked from `AppKit`, which nothing else here needs.
    const WILL_FINISH_LAUNCHING: &str = "NSApplicationWillFinishLaunchingNotification";

    define_class!(
        /// Receives the launch notification and then the Apple Events.
        #[unsafe(super(NSObject))]
        #[name = "ConclaveUrlHandler"]
        struct UrlHandler;

        impl UrlHandler {
            #[unsafe(method(willFinishLaunching:))]
            fn will_finish_launching(&self, _notification: &NSNotification) {
                let manager = NSAppleEventManager::sharedAppleEventManager();
                // SAFETY: `self` responds to the selector, with the argument
                // types `NSAppleEventManager` calls a handler with; the
                // handler lives for the rest of the process (see `listen`).
                unsafe {
                    let _: () = msg_send![
                        &manager,
                        setEventHandler: self,
                        andSelector: sel!(handleGetUrl:withReplyEvent:),
                        forEventClass: GET_URL,
                        andEventID: GET_URL
                    ];
                }
            }

            #[unsafe(method(handleGetUrl:withReplyEvent:))]
            fn handle_get_url(
                &self,
                event: &NSAppleEventDescriptor,
                _reply: &NSAppleEventDescriptor,
            ) {
                // SAFETY: `paramDescriptorForKeyword:` takes an `AEKeyword`, a
                // `u32`, and returns a descriptor or nil.
                let param: Option<Retained<NSAppleEventDescriptor>> =
                    unsafe { msg_send![event, paramDescriptorForKeyword: DIRECT_OBJECT] };
                if let Some(url) = param.and_then(|p| p.stringValue()) {
                    super::deliver(url.to_string());
                } else {
                    tracing::warn!("A \"get URL\" Apple Event arrived without a URL");
                }
            }
        }
    );

    /// Watch for launch, to install the Apple Event handler in time.
    pub(super) fn listen() {
        // SAFETY: plain `NSObject` initialisation.
        let handler: Retained<UrlHandler> =
            unsafe { msg_send![super(UrlHandler::alloc().set_ivars(())), init] };
        let name = NSString::from_str(WILL_FINISH_LAUNCHING);
        // SAFETY: `handler` responds to the selector with an `NSNotification`
        // argument. Notification centres and Apple Event managers keep only
        // weak references, so the handler is leaked to outlive both: it is
        // needed for as long as the process runs.
        unsafe {
            NSNotificationCenter::defaultCenter().addObserver_selector_name_object(
                &handler,
                sel!(willFinishLaunching:),
                Some(&name),
                None::<&AnyObject>,
            );
        }
        std::mem::forget(handler);
    }
}

#[cfg(test)]
mod tests {
    use super::command::{command_program, needs_registering, open_command};
    use super::*;

    /// Links queue until collected, in the order they came, and are collected
    /// once.
    #[test]
    fn links_wait_for_the_gui_in_order() {
        deliver("conclave://one".to_string());
        deliver("conclave://two".to_string());
        assert_eq!(take(), vec!["conclave://one", "conclave://two"]);
        assert!(take().is_empty());
    }

    #[test]
    fn the_open_command_quotes_a_path_with_spaces() {
        let exe = std::path::Path::new(r"C:\Program Files\Conclave\conclave-client.exe");
        let command = open_command(exe);
        assert_eq!(
            command,
            r#""C:\Program Files\Conclave\conclave-client.exe" "%1""#
        );
        // And reads back as the program it runs.
        assert_eq!(command_program(&command).as_deref(), Some(exe));
    }

    #[test]
    fn the_program_is_read_out_of_a_registered_command() {
        let program = |command: &str| command_program(command).map(|p| p.display().to_string());
        assert_eq!(
            program(r#""C:\a b\c.exe" "%1""#).as_deref(),
            Some(r"C:\a b\c.exe")
        );
        assert_eq!(program(r"C:\ab\c.exe %1").as_deref(), Some(r"C:\ab\c.exe"));
        assert_eq!(program(""), None);
        assert_eq!(program("   "), None);
        assert_eq!(program(r#""" "%1""#), None);
    }

    #[test]
    fn only_a_missing_or_broken_registration_is_replaced() {
        let here = |_: &std::path::Path| true;
        let gone = |_: &std::path::Path| false;
        // Nothing registered: register.
        assert!(needs_registering(None, here));
        // Registered to a program that is there, this one or another: leave it.
        assert!(!needs_registering(
            Some(r#""C:\other\client.exe" "%1""#),
            here
        ));
        // Registered to a program that has gone, or to nothing readable: replace.
        assert!(needs_registering(Some(r#""C:\old\client.exe" "%1""#), gone));
        assert!(needs_registering(Some(""), here));
    }
}
