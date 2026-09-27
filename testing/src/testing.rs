// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tempdir::TempDir;
use uuid::Uuid;

const TRACKER_PORT: u16 = 8080;
const SERVER_PORT: u16 = 8090;
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration() {
    conclave_common::init_tracing();

    let tempdir = TempDir::new("conclave_testing").unwrap();
    let server_db = tempdir
        .path()
        .join(format!("testing_server_{}.db", Uuid::new_v4()));
    let client_db = tempdir
        .path()
        .join(format!("testing_client_{}.toml", Uuid::new_v4()));

    // Create the client
    let client = conclave_client::Client::new(client_db).unwrap();

    // Set up the tracker
    let keys = conclave_tracker::Keys::default();
    let tracker = Arc::new(conclave_tracker::State::new(LOCALHOST, TRACKER_PORT, keys));
    let tracker_clone = tracker.clone();
    let tracker_process = tokio::spawn(async move {
        eprintln!("Tracker process starting");
        tracker_clone.serve().await.unwrap();
    });

    // Set up the server
    let (server, password) = conclave_server::State::new(
        "Conclave Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        SERVER_PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);
    server.add_tracker(LOCALHOST, TRACKER_PORT).await.unwrap();
    let server_clone = server.clone();
    let server_process = tokio::spawn(async move {
        eprintln!("Tracker process starting");
        server_clone.serve().await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    assert!(server.create_user("admin".into(), "admin").await.is_err());

    assert_eq!(
        server
            .authenticate_user(("admin".into(), password.to_string()).into())
            .await
            .unwrap(),
        (0, true)
    );
    server
        .create_user("user".into(), "user12345")
        .await
        .unwrap();

    server
        .authenticate_user(("user", "user12345").into())
        .await
        .unwrap();

    assert!(
        server
            .authenticate_user(("admin", "user1dsfsfslkfjsl").into())
            .await
            .is_err()
    );
    server.disable_user("user".into()).await.unwrap();
    assert!(server.anonymous_clients_allowed());
    server.anonymous_clients_enabled(false).await.unwrap();
    assert!(!server.anonymous_clients_allowed());

    let tracker_info = (LOCALHOST, TRACKER_PORT).into();
    client.add_tracker(&tracker_info).await.unwrap();

    eprintln!("Client: added tracker, querying tracker(s)");
    assert_eq!(client.list_servers_from_trackers().await.unwrap().len(), 1);

    eprintln!("Tracker: querying for server(s)");
    let tracked_servers = tracker.servers().servers;
    assert_eq!(tracked_servers.len(), 1);
    assert_eq!(tracked_servers[0].name, "Conclave Server");
    assert_eq!(
        tracked_servers[0].url,
        format!("conclave://localhost:{SERVER_PORT}")
    );

    eprintln!("Server: querying for connected user(s)");
    assert!(server.connected_users().await.is_empty());

    // User authentication is required, this should fail
    assert!(
        client
            .connect(
                LOCALHOST.to_string().as_str(),
                SERVER_PORT,
                true,
                "Unnamed".into(),
                None,
                None,
                None,
                String::new(),
                std::collections::BTreeMap::new(),
            )
            .await
            .is_err()
    );

    // Log in as the admin user
    client
        .connect(
            LOCALHOST.to_string().as_str(),
            SERVER_PORT,
            true,
            "admin".into(),
            Some(("admin".to_string(), password.to_string()).into()),
            None,
            None,
            String::new(),
            std::collections::BTreeMap::new(),
        )
        .await
        .unwrap();

    let users = server.connected_users().await;
    assert_eq!(users.len(), 1);

    client
        .map_connections(|conn| {
            assert!(conn.connection_duration().is_some());
        })
        .await;

    client.disconnect_all().await;

    // Cleanup
    tracker_process.abort();
    server_process.abort();
}

#[test]
fn version() {
    // The version parses — conclave_common::VERSION would panic on first use
    // otherwise — and carries the commit it was built from.
    println!("Semver version: {:?}", *conclave_common::VERSION);
    assert!(!conclave_common::VERSION.build.is_empty(), "no git hash");

    // The commit (and `dirty`) are build metadata, not a pre-release: a working
    // build is the same version as the release it came from, not older than it,
    // so it is never mistaken for an out-of-date binary.
    assert!(
        conclave_common::VERSION.pre.is_empty(),
        "version is a pre-release"
    );
    let released = semver::Version::new(
        conclave_common::VERSION.major,
        conclave_common::VERSION.minor,
        conclave_common::VERSION.patch,
    );
    assert!(*conclave_common::VERSION >= released);

    // Every crate reports that one version, by re-exporting it rather than
    // working it out again, so no two binaries can disagree.
    println!("Version: {}", *conclave_server::VERSION);
    assert_eq!(*conclave_client::VERSION, *conclave_common::VERSION);
    assert_eq!(*conclave_server::VERSION, *conclave_common::VERSION);
    assert_eq!(*conclave_tracker::VERSION, *conclave_common::VERSION);

    // What the binaries print for --version quotes the same numbers.
    assert!(conclave_common::VERSION_BANNER.contains(conclave_common::VERSION_STRING));
    assert!(conclave_common::VERSION_BANNER.contains(conclave_common::BUILD_DATE));
}

/// Poll `check` until it returns a value or the deadline passes.
async fn eventually<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(value) = check() {
            return value;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("Timed out waiting for {what}");
}

/// Every file transfer in a direct-message conversation with `peer`, in the
/// order the conversation shows them.
fn transfers(
    conn: &conclave_client::conn::ConclaveConnection,
    peer: u16,
) -> Vec<conclave_client::conn::FileTransfer> {
    use conclave_client::conn::DmBody;

    conn.dm_thread(peer)
        .into_iter()
        .filter_map(|msg| match msg.body {
            DmBody::File(key) => conn.file_transfer(key),
            DmBody::Text(_) | DmBody::Notice(_) => None,
        })
        .collect()
}

/// Two users send each other files over the direct-message protocol: one file
/// is accepted and arrives byte for byte, one is declined, and one is refused
/// by the server for exceeding its size limit.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_file_transfer() {
    use conclave_client::conn::TransferState;

    const PORT: u16 = 8091;

    let tempdir = TempDir::new("conclave_dm_files").unwrap();
    let server_db = tempdir.path().join(format!("dm_{}.db", Uuid::new_v4()));

    let (server, _password) = conclave_server::State::new(
        "File Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);
    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Two clients with their own configs, so they hold distinct identity keys.
    let connect = async |name: &str| {
        let config = tempdir
            .path()
            .join(format!("{name}_{}.toml", Uuid::new_v4()));
        let client = conclave_client::Client::new(config).unwrap();
        let conn = client
            .connect(
                LOCALHOST.to_string().as_str(),
                PORT,
                true,
                name.to_string(),
                None,
                None,
                None,
                String::new(),
                std::collections::BTreeMap::new(),
            )
            .await
            .unwrap();
        (client, conn)
    };
    let (_alice_client, alice) = connect("alice").await;
    let (_bob_client, bob) = connect("bob").await;

    // Each side needs the other's connection id, which arrives with the roster.
    let peer_id = async |conn: &conclave_client::conn::ConclaveConnection, name: &str| {
        eventually(&format!("{name}'s connection id"), || {
            conn.get_connected_users()
                .into_iter()
                .find(|user| user.display_name == name)
                .map(|user| user.id)
        })
        .await
    };
    let bob_id = peer_id(&alice, "bob").await;
    let alice_id = peer_id(&bob, "alice").await;

    // A file large enough to span several chunks.
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let source = tempdir.path().join("greetings.bin");
    std::fs::write(&source, &payload).unwrap();

    // Wait for the `index`-th transfer in a conversation to reach a state.
    let settled = async |conn: &conclave_client::conn::ConclaveConnection,
                         peer: u16,
                         index: usize,
                         what: &str| {
        eventually(what, || {
            let transfer = transfers(conn, peer).into_iter().nth(index)?;
            (transfer.state != TransferState::Offered
                && transfer.state != TransferState::Transferring)
                .then_some(transfer)
        })
        .await
    };

    // ── Accepted ──────────────────────────────────────────────────────────
    alice.offer_file(bob_id, &source).await.unwrap();
    let offered = eventually("bob to be offered a file", || {
        transfers(&bob, alice_id).into_iter().next()
    })
    .await;
    assert_eq!(offered.name, "greetings.bin");
    assert_eq!(offered.size, payload.len() as u64);
    assert_eq!(offered.state, TransferState::Offered);

    let destination = tempdir.path().join("received.bin");
    bob.accept_file(offered.key, destination.clone())
        .await
        .unwrap();

    let received = settled(&bob, alice_id, 0, "the received file to finish").await;
    assert_eq!(received.state, TransferState::Complete);
    assert_eq!(std::fs::read(&destination).unwrap(), payload);
    // The partial file is moved into place, not left behind.
    assert!(!tempdir.path().join("received.bin.conclave-part").exists());

    let sent = settled(&alice, bob_id, 0, "the sent file to finish").await;
    assert_eq!(sent.state, TransferState::Complete);
    assert_eq!(sent.progress, payload.len() as u64);

    // ── Declined ──────────────────────────────────────────────────────────
    bob.offer_file(alice_id, &source).await.unwrap();
    let to_decline = eventually("alice to be offered a file", || {
        transfers(&alice, bob_id).into_iter().nth(1)
    })
    .await;
    alice.decline_file(to_decline.key).await.unwrap();
    assert_eq!(
        alice.file_transfer(to_decline.key).unwrap().state,
        TransferState::Declined
    );
    let refused = settled(&bob, alice_id, 1, "bob to see the file declined").await;
    assert_eq!(refused.state, TransferState::Declined);

    // ── Over the server's limit ───────────────────────────────────────────
    server.set_max_upload_size(Some(1024)).await.unwrap();
    alice.offer_file(bob_id, &source).await.unwrap();
    let rejected = settled(&alice, bob_id, 2, "the server to refuse the offer").await;
    match rejected.state {
        TransferState::Failed(reason) => assert!(reason.contains("1024"), "{reason}"),
        state => panic!("Expected a refusal, got {state:?}"),
    }
    // The recipient was never told about a file the server would not carry.
    assert_eq!(transfers(&bob, alice_id).len(), 2);

    // ── Withdrawn ─────────────────────────────────────────────────────────
    // Both users number their own transfers from zero, so by now each holds
    // ids the other also holds; a cancel still has to reach the right one.
    server.set_max_upload_size(None).await.unwrap();
    bob.offer_file(alice_id, &source).await.unwrap();
    let pending = eventually("alice to be offered another file", || {
        transfers(&alice, bob_id).into_iter().nth(3)
    })
    .await;
    assert_eq!(pending.state, TransferState::Offered);

    let withdrawn = transfers(&bob, alice_id)[2].key;
    bob.cancel_file(withdrawn).await.unwrap();
    let seen = settled(&alice, bob_id, 3, "alice to see the offer withdrawn").await;
    assert!(
        matches!(seen.state, TransferState::Failed(_)),
        "expected a withdrawal, got {:?}",
        seen.state
    );
    // The completed transfer that shares its id with the cancelled one is
    // untouched.
    assert_eq!(transfers(&alice, bob_id)[0].state, TransferState::Complete);

    server_process.abort();
}

/// A client may ask a server to describe itself without presenting an identity
/// key, but joining requires one: every peer's key is what direct messages and
/// files are encrypted to, so admitting a keyless member would mean admitting
/// someone nobody could write to in confidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_key_required_to_join() {
    use conclave_common::net::{DefaultEncryptedStream, EncryptedStream};
    use conclave_common::server::{
        AuthRequest, ClientMessagesEncrypted, ServerError, ServerMessagesEncrypted, unencrypted,
    };

    const PORT: u16 = 8092;

    let tempdir = TempDir::new("conclave_keyless").unwrap();
    let server_db = tempdir
        .path()
        .join(format!("keyless_{}.db", Uuid::new_v4()));

    let (server, password) = conclave_server::State::new(
        "Keyless Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    // Guests are admitted, so authentication is not what turns anything away
    // until the last section below.
    assert!(server.anonymous_clients_allowed());
    let server = Arc::new(server);
    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let host = LOCALHOST.to_string();
    let key = conclave_client::Client::fetch_server_key(&host, PORT)
        .await
        .unwrap();

    // A keyless handshake, which the transport is happy to make: it is Conclave
    // that decides what such a connection may do.
    let keyless = async || {
        let mut stream = tokio::net::TcpStream::connect(format!("{host}:{PORT}"))
            .await
            .unwrap();
        unencrypted::ClientToServer::GoCrypto
            .send(&mut stream)
            .await
            .unwrap();
        let encrypted: DefaultEncryptedStream =
            EncryptedStream::connect(stream, &key, None).await.unwrap();
        encrypted
    };

    // ── Describing the server needs no key ────────────────────────────────
    let info = conclave_client::Client::fetch_server_info(&host, PORT, key, None)
        .await
        .unwrap();
    assert_eq!(info.name, "Keyless Server");
    // Asking about a server is not joining it, so nothing was added to the
    // roster and the count the server reports stays at zero.
    assert_eq!(info.users_connected, 0);
    assert!(server.connected_users().await.is_empty());

    // ── Joining does not ──────────────────────────────────────────────────
    let mut encrypted = keyless().await;
    let join = ServerMessagesEncrypted::ServerAuthenticationRequest(AuthRequest {
        display_name: "keyless".to_string(),
        timezone: None,
        avatar: None,
        profile: String::new(),
        urls: std::collections::BTreeMap::new(),
        auth: None,
    })
    .to_vec();
    encrypted.send(&join).await.unwrap();
    assert!(matches!(
        ClientMessagesEncrypted::from_bytes(&encrypted.recv().await.unwrap()).unwrap(),
        ClientMessagesEncrypted::Error(ServerError::IdentityKeyRequired)
    ));

    // And the connection is over: nothing further is answered, and the would-be
    // member never appears.
    let _ = encrypted.send(&join).await;
    assert!(encrypted.recv().await.is_err());
    assert!(server.connected_users().await.is_empty());

    // ── A server that admits no guests describes itself to no guests ──────
    // Not needing a key is not the same as needing nothing: the query answers
    // only a caller the server would let in.
    server.anonymous_clients_enabled(false).await.unwrap();
    let refused = conclave_client::Client::fetch_server_info(&host, PORT, key, None).await;
    assert_eq!(
        refused.unwrap_err().to_string(),
        ServerError::AuthenticationRequired.to_string()
    );
    let credentialed = conclave_client::Client::fetch_server_info(
        &host,
        PORT,
        key,
        Some(("admin".to_string(), password.to_string()).into()),
    )
    .await
    .unwrap();
    assert_eq!(credentialed.name, "Keyless Server");

    server_process.abort();
}

/// Direct messages round-trip through the end-to-end encryption, and there is
/// no path that sends one any other way: once the recipient is gone, so is the
/// key to seal it with, and the message is refused rather than relayed in the
/// clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_messages_are_always_encrypted() {
    use conclave_client::conn::DmBody;

    const PORT: u16 = 8093;

    let tempdir = TempDir::new("conclave_dm_text").unwrap();
    let server_db = tempdir.path().join(format!("dm_{}.db", Uuid::new_v4()));

    let (server, _password) = conclave_server::State::new(
        "Message Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);
    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Two clients with their own configs, so they hold distinct identity keys.
    let connect = async |name: &str| {
        let config = tempdir
            .path()
            .join(format!("{name}_{}.toml", Uuid::new_v4()));
        let client = conclave_client::Client::new(config).unwrap();
        let conn = client
            .connect(
                LOCALHOST.to_string().as_str(),
                PORT,
                true,
                name.to_string(),
                None,
                None,
                None,
                String::new(),
                std::collections::BTreeMap::new(),
            )
            .await
            .unwrap();
        (client, conn)
    };
    let (_alice_client, alice) = connect("alice").await;
    let (_bob_client, bob) = connect("bob").await;

    let peer_id = async |conn: &conclave_client::conn::ConclaveConnection, name: &str| {
        eventually(&format!("{name}'s connection id"), || {
            conn.get_connected_users()
                .into_iter()
                .find(|user| user.display_name == name)
                .map(|user| user.id)
        })
        .await
    };
    let bob_id = peer_id(&alice, "bob").await;
    let alice_id = peer_id(&bob, "alice").await;

    // The text arriving intact is evidence of the round trip: the server relays
    // only ciphertext, which bob opens with the key derived from alice's.
    alice
        .send_dm(bob_id, "hello bob".to_string())
        .await
        .unwrap();
    let received = eventually("bob to receive the message", || {
        bob.dm_thread(alice_id).into_iter().next()
    })
    .await;
    assert!(!received.from_me);
    match received.body {
        DmBody::Text(text) => assert_eq!(text, "hello bob"),
        body => panic!("Expected a message, got {body:?}"),
    }

    // Once bob leaves, his key goes with him from alice's roster.
    bob.disconnect().await.unwrap();
    eventually("bob to leave the roster", || {
        alice
            .get_connected_users()
            .iter()
            .all(|user| user.id != bob_id)
            .then_some(())
    })
    .await;

    // With nothing to encrypt to, the message is refused outright — the old
    // plaintext fallback is gone — and the conversation says why.
    assert!(
        alice
            .send_dm(bob_id, "still there?".to_string())
            .await
            .is_err()
    );
    let thread = alice.dm_thread(bob_id);
    assert!(
        matches!(thread.last().map(|msg| &msg.body), Some(DmBody::Notice(_))),
        "expected a notice, got {:?}",
        thread.last()
    );
    // Nothing was appended as a sent message.
    assert!(
        !thread
            .iter()
            .any(|msg| matches!(&msg.body, DmBody::Text(text) if text == "still there?"))
    );

    server_process.abort();
}

/// A room or topic tells the members who can see it what groups gate it, so the
/// client can say who else is reading. An unrestricted one carries nothing,
/// which is what "everyone on this server" looks like on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rooms_and_topics_name_the_groups_that_gate_them() {
    const PORT: u16 = 8094;

    let tempdir = TempDir::new("conclave_gating").unwrap();
    let server_db = tempdir.path().join(format!("gating_{}.db", Uuid::new_v4()));

    let (server, password) = conclave_server::State::new(
        "Gating Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);

    // One coloured group, with the admin account in it.
    server
        .create_group("Engineering".into(), None, Some([0x33, 0x88, 0xcc]))
        .await
        .unwrap();
    let gid = server
        .admin_list_groups()
        .await
        .unwrap()
        .into_iter()
        .find(|g| g.name == "Engineering")
        .expect("the group just created")
        .id;
    let (admin_uid, _) = server
        .authenticate_user(("admin".to_string(), password.to_string()).into())
        .await
        .unwrap();
    server.add_user_to_group(admin_uid, gid).await.unwrap();

    server.set_chat_enabled(true).await.unwrap();
    server.set_forums_enabled(true).await.unwrap();
    server
        .create_chatroom("Lobby".into(), vec![])
        .await
        .unwrap();
    server
        .create_chatroom("Standup".into(), vec![gid])
        .await
        .unwrap();
    server
        .create_forum_topic("Announcements".into(), String::new(), vec![])
        .await
        .unwrap();
    server
        .create_forum_topic("Roadmap".into(), String::new(), vec![gid])
        .await
        .unwrap();

    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let config = tempdir
        .path()
        .join(format!("admin_{}.toml", Uuid::new_v4()));
    let client = conclave_client::Client::new(config).unwrap();
    let conn = client
        .connect(
            LOCALHOST.to_string().as_str(),
            PORT,
            true,
            "admin".to_string(),
            Some(("admin".to_string(), password.to_string()).into()),
            None,
            None,
            String::new(),
            std::collections::BTreeMap::new(),
        )
        .await
        .unwrap();

    // Three rooms: the server's built-in Public one, plus the two created here.
    let rooms = eventually("the room list", || {
        let rooms = conn.chatrooms_available();
        (rooms.len() == 3).then_some(rooms)
    })
    .await;
    let topics = eventually("the topic list", || {
        let topics = conn.forum_topics();
        (topics.len() == 2).then_some(topics)
    })
    .await;

    // Open to everyone: nothing to name.
    let lobby = rooms.iter().find(|r| r.name == "Lobby").unwrap();
    assert!(lobby.restricted_to.is_empty());
    let announcements = topics.iter().find(|t| t.name == "Announcements").unwrap();
    assert!(announcements.restricted_to.is_empty());

    // Gated: the group arrives by name and colour, not as an id the client
    // could not render.
    let standup = rooms.iter().find(|r| r.name == "Standup").unwrap();
    assert_eq!(standup.restricted_to.len(), 1);
    assert_eq!(standup.restricted_to[0].name, "Engineering");
    assert_eq!(standup.restricted_to[0].color, Some([0x33, 0x88, 0xcc]));

    let roadmap = topics.iter().find(|t| t.name == "Roadmap").unwrap();
    assert_eq!(roadmap.restricted_to.len(), 1);
    assert_eq!(roadmap.restricted_to[0].name, "Engineering");
    assert_eq!(roadmap.restricted_to[0].color, Some([0x33, 0x88, 0xcc]));

    server_process.abort();
}

/// A poll reports a tally and never a voter. The creator sees the count from
/// the start when they kept it private; everyone else sees the options and
/// nothing more until it closes. A ballot is counted once, and a ballot the
/// poll's terms do not allow is not counted at all.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_poll_tallies_votes_without_recording_voters() {
    use conclave_common::poll::{NewPoll, PollDuration};

    const PORT: u16 = 8095;

    let tempdir = TempDir::new("conclave_poll").unwrap();
    let server_db = tempdir.path().join(format!("poll_{}.db", Uuid::new_v4()));

    let (server, password) = conclave_server::State::new(
        "Poll Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);

    server.set_forums_enabled(true).await.unwrap();
    server
        .create_forum_topic("Lunch".into(), String::new(), vec![])
        .await
        .unwrap();

    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // The poll's author, and a second identity to vote with: separate clients,
    // so separate identity keys, which is what a voter is known by.
    let author = conclave_client::Client::new(
        tempdir
            .path()
            .join(format!("author_{}.toml", Uuid::new_v4())),
    )
    .unwrap()
    .connect(
        LOCALHOST.to_string().as_str(),
        PORT,
        true,
        "admin".to_string(),
        Some(("admin".to_string(), password.to_string()).into()),
        None,
        None,
        String::new(),
        std::collections::BTreeMap::new(),
    )
    .await
    .unwrap();

    let voter = conclave_client::Client::new(
        tempdir
            .path()
            .join(format!("voter_{}.toml", Uuid::new_v4())),
    )
    .unwrap()
    .connect(
        LOCALHOST.to_string().as_str(),
        PORT,
        true,
        "Guest".to_string(),
        None,
        None,
        None,
        String::new(),
        std::collections::BTreeMap::new(),
    )
    .await
    .unwrap();

    let topic = eventually("the topic list", || {
        author.forum_topics().first().map(|t| t.id)
    })
    .await;

    // Results kept private: only the author sees the count before it closes.
    author
        .new_forum_thread(
            topic,
            "Lunch on Friday".into(),
            "Pick one.".into(),
            false,
            false,
            Some(NewPoll {
                question: "What are we having?".into(),
                options: vec![
                    "Tacos".into(),
                    "Pasta".into(),
                    "Pizza".into(),
                    "Sushi".into(),
                ],
                multiple_choices: false,
                duration: PollDuration::days(2).unwrap(),
                public_results: false,
            }),
        )
        .await
        .unwrap();

    // The thread list says a thread carries a poll before it is opened.
    let thread = eventually("the new thread", || {
        author
            .forum_threads(topic)
            .into_iter()
            .find(|t| t.subject == "Lunch on Friday")
    })
    .await;
    assert!(thread.has_poll);
    let thread = thread.id;

    voter.request_forum_threads(topic).await.unwrap();
    author.open_forum_thread(thread).await.unwrap();
    voter.open_forum_thread(thread).await.unwrap();

    let author_view = eventually("the author's poll", || author.forum_poll(thread)).await;
    let voter_view = eventually("the voter's poll", || voter.forum_poll(thread)).await;

    // The author kept the results private, so the author has them and the
    // voter does not — not as zeroes to be hidden, but not at all.
    assert!(author_view.results_visible());
    assert_eq!(author_view.total_voters, Some(0));
    assert!(!voter_view.results_visible());
    assert!(voter_view.options.iter().all(|o| o.votes.is_none()));
    assert_eq!(voter_view.total_voters, None);
    assert_eq!(voter_view.options.len(), 4);
    assert!(!voter_view.voted);

    let pizza = voter_view
        .options
        .iter()
        .find(|o| o.text == "Pizza")
        .unwrap()
        .id;
    let tacos = voter_view
        .options
        .iter()
        .find(|o| o.text == "Tacos")
        .unwrap()
        .id;

    // Two choices on a single-choice poll is not a ballot: it is turned away
    // before the voter is written down, so it costs them nothing.
    voter
        .vote_forum_poll(voter_view.id, vec![pizza, tacos])
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(author.forum_poll(thread).unwrap().total_voters, Some(0));
    assert!(!voter.forum_poll(thread).unwrap().voted);

    voter
        .vote_forum_poll(voter_view.id, vec![pizza])
        .await
        .unwrap();
    let after_one = eventually("the first vote", || {
        author
            .forum_poll(thread)
            .filter(|p| p.total_voters == Some(1))
    })
    .await;
    let pizza_votes = |poll: &conclave_common::poll::Poll| {
        poll.options.iter().find(|o| o.id == pizza).unwrap().votes
    };
    assert_eq!(pizza_votes(&after_one), Some(1));

    // The voter is told they voted, and still not told the tally: which option
    // they chose is not recorded anywhere, so it cannot be read back to them.
    let ballot_cast = eventually("the voter's updated poll", || {
        voter.forum_poll(thread).filter(|p| p.voted)
    })
    .await;
    assert!(!ballot_cast.results_visible());

    // A second ballot from the same identity changes nothing.
    voter
        .vote_forum_poll(voter_view.id, vec![tacos])
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let unchanged = author.forum_poll(thread).unwrap();
    assert_eq!(unchanged.total_voters, Some(1));
    assert_eq!(pizza_votes(&unchanged), Some(1));

    // A different identity is a different voter.
    author
        .vote_forum_poll(voter_view.id, vec![tacos])
        .await
        .unwrap();
    let both = eventually("the second vote", || {
        author
            .forum_poll(thread)
            .filter(|p| p.total_voters == Some(2))
    })
    .await;
    assert_eq!(pizza_votes(&both), Some(1));
    assert_eq!(
        both.options.iter().find(|o| o.id == tacos).unwrap().votes,
        Some(1)
    );

    server_process.abort();
}

/// Reactions on both sides of the server: a forum post keeps its emoji, a chat
/// message's are relayed to the room and counted by whoever was there. Both
/// name the people who reacted, and reacting again takes the reaction back.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reactions_tally_emoji_and_name_who_left_them() {
    const PORT: u16 = 8096;

    let tempdir = TempDir::new("conclave_reactions").unwrap();
    let server_db = tempdir
        .path()
        .join(format!("reactions_{}.db", Uuid::new_v4()));

    let (server, password) = conclave_server::State::new(
        "Reaction Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);

    server.set_chat_enabled(true).await.unwrap();
    server.set_forums_enabled(true).await.unwrap();
    server
        .create_forum_topic("Announcements".into(), String::new(), vec![])
        .await
        .unwrap();

    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let connect = async |name: &str, auth: Option<conclave_common::server::UserAuthentication>| {
        conclave_client::Client::new(
            tempdir
                .path()
                .join(format!("{name}_{}.toml", Uuid::new_v4())),
        )
        .unwrap()
        .connect(
            LOCALHOST.to_string().as_str(),
            PORT,
            true,
            name.to_string(),
            auth,
            None,
            None,
            String::new(),
            std::collections::BTreeMap::new(),
        )
        .await
        .unwrap()
    };

    let ada = connect(
        "admin",
        Some(("admin".to_string(), password.to_string()).into()),
    )
    .await;
    let grace = connect("Grace", None).await;

    // ── A forum post keeps its reactions ──────────────────────────────
    let topic = eventually("the topic list", || {
        ada.forum_topics().first().map(|t| t.id)
    })
    .await;
    ada.new_forum_thread(
        topic,
        "Ship it".into(),
        "Release is out.".into(),
        false,
        false,
        None,
    )
    .await
    .unwrap();

    let thread = eventually("the new thread", || {
        ada.forum_threads(topic).first().map(|t| t.id)
    })
    .await;
    grace.request_forum_threads(topic).await.unwrap();
    ada.open_forum_thread(thread).await.unwrap();
    grace.open_forum_thread(thread).await.unwrap();

    let post = eventually("the opening post", || {
        ada.forum_posts(thread)
            .and_then(|p| p.first().map(|p| p.id))
    })
    .await;
    let reactions = |conn: &conclave_client::conn::ConclaveConnection| {
        conn.forum_posts(thread)
            .and_then(|posts| posts.into_iter().find(|p| p.id == post))
            .map(|p| p.reactions)
            .unwrap_or_default()
    };

    grace.react_forum_post(post, '★', true).await.unwrap();
    let seen = eventually("Grace's reaction", || {
        let seen = reactions(&ada);
        (!seen.is_empty()).then_some(seen)
    })
    .await;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].emoji, '★');
    assert_eq!(seen[0].who, vec!["Grace".to_string()]);
    // Grace's reaction is Grace's, and it is not Ada's.
    assert!(!seen[0].mine);
    assert!(
        eventually("Grace's own view", || {
            reactions(&grace).into_iter().next()
        })
        .await
        .mine
    );

    // A second person joining the same emoji is a second name on it.
    ada.react_forum_post(post, '★', true).await.unwrap();
    let both = eventually("both reactions", || {
        reactions(&ada).into_iter().find(|r| r.count() == 2)
    })
    .await;
    assert!(both.mine);
    assert_eq!(both.who_line(), "★ Grace and you");

    // Taking one back leaves the other standing.
    grace.react_forum_post(post, '★', false).await.unwrap();
    let left = eventually("Grace's reaction withdrawn", || {
        reactions(&ada).into_iter().find(|r| r.count() == 1)
    })
    .await;
    // All that is left is Ada's own, so there is nobody else to name.
    assert!(left.mine);
    assert!(left.who.is_empty());
    assert_eq!(left.who_line(), "★ you");

    // The picker's palette is a shortcut, not the limit: an emoji that is not
    // on it is still a reaction, on the wire and in the database.
    assert!(
        !conclave_common::reaction::REACTION_PALETTE
            .iter()
            .any(|(emoji, _)| *emoji == '👍'),
        "picked for this test because the palette does not offer it"
    );
    grace.react_forum_post(post, '👍', true).await.unwrap();
    let off_palette = eventually("an emoji from outside the palette", || {
        reactions(&ada).into_iter().find(|r| r.emoji == '👍')
    })
    .await;
    assert_eq!(off_palette.who, vec!["Grace".to_string()]);
    grace.react_forum_post(post, '👍', false).await.unwrap();
    eventually("it coming back off", || {
        reactions(&ada)
            .into_iter()
            .all(|r| r.emoji != '👍')
            .then_some(())
    })
    .await;

    // A letter is not a reaction, and the server is not asked to take a
    // client's word for it: the client refuses before sending, and nothing
    // lands if it does.
    assert!(grace.react_forum_post(post, 'x', true).await.is_err());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(reactions(&ada).len(), 1);

    // ── A chat message's reactions are relayed to the room ────────────
    ada.chat_join(0).await.unwrap();
    grace.chat_join(0).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    ada.chat_send(0, "Deploying now".to_string()).await.unwrap();
    let message = eventually("the chat message", || {
        grace
            .chat_room(0)?
            .lines
            .iter()
            .find_map(|line| match line {
                conclave_client::conn::ChatLine::Message { id, message, .. }
                    if message == "Deploying now" =>
                {
                    Some(*id)
                }
                _ => None,
            })
    })
    .await;

    grace.chat_react(0, message, '♡', true).await.unwrap();

    // Both ends count it, and each recognises whose it is. A client does not
    // count its own reaction until the server echoes it back to the room, so
    // each side is waited for separately: one having it says nothing about the
    // other, which is what made an earlier version of this test flaky.
    let tallies = |conn: &conclave_client::conn::ConclaveConnection| {
        let me = conn.my_connection_id();
        conn.chat_room(0)
            .map(|room| {
                room.lines
                    .iter()
                    .flat_map(|line| line.reaction_tallies(me))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let on_adas_screen = eventually("the reaction reaching Ada", || {
        tallies(&ada).into_iter().next()
    })
    .await;
    assert_eq!(on_adas_screen.emoji, '♡');
    assert_eq!(on_adas_screen.who, vec!["Grace".to_string()]);
    assert!(!on_adas_screen.mine);

    // Waiting on `mine` also waits for the user list, which is where a client
    // finds the connection id that tells its own reactions from anyone else's.
    let on_graces_screen = eventually("Grace to count her own reaction", || {
        tallies(&grace).into_iter().find(|r| r.mine)
    })
    .await;
    assert_eq!(on_graces_screen.emoji, '♡');
    assert_eq!(on_graces_screen.count(), 1);

    // The same reaction twice is still one reaction.
    grace.chat_react(0, message, '♡', true).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let counted = tallies(&ada);
    assert_eq!(counted.len(), 1, "one emoji, not two: {counted:?}");
    assert_eq!(counted[0].count(), 1, "one person, counted once");

    // And taking it back leaves nothing behind.
    grace.chat_react(0, message, '♡', false).await.unwrap();
    eventually("the reaction being taken back", || {
        let me = ada.my_connection_id();
        ada.chat_room(0)?
            .lines
            .iter()
            .all(|line| line.reaction_tallies(me).is_empty())
            .then_some(())
    })
    .await;

    server_process.abort();
}

/// Display names are not unique, so a reaction cannot be keyed by one. Two
/// people both calling themselves "Ada" each own their own reaction: neither can
/// take back the other's, on a post or on a chat message.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_display_name_does_not_share_reactions() {
    const PORT: u16 = 8097;

    let tempdir = TempDir::new("conclave_samename").unwrap();
    let server_db = tempdir
        .path()
        .join(format!("samename_{}.db", Uuid::new_v4()));

    let (server, password) = conclave_server::State::new(
        "Same Name Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);

    server.set_chat_enabled(true).await.unwrap();
    server.set_forums_enabled(true).await.unwrap();
    server
        .create_forum_topic("Announcements".into(), String::new(), vec![])
        .await
        .unwrap();

    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Two separate clients, so two separate identity keys, both introducing
    // themselves as "Ada". The server takes display names as given.
    let connect = async |file: &str, auth: Option<conclave_common::server::UserAuthentication>| {
        conclave_client::Client::new(
            tempdir
                .path()
                .join(format!("{file}_{}.toml", Uuid::new_v4())),
        )
        .unwrap()
        .connect(
            LOCALHOST.to_string().as_str(),
            PORT,
            true,
            "Ada".to_string(),
            auth,
            None,
            None,
            String::new(),
            std::collections::BTreeMap::new(),
        )
        .await
        .unwrap()
    };

    let first = connect(
        "first",
        Some(("admin".to_string(), password.to_string()).into()),
    )
    .await;
    let second = connect("second", None).await;
    assert_ne!(
        first.my_public_key(),
        second.my_public_key(),
        "two clients, two identities"
    );

    // ── On a forum post ───────────────────────────────────────────────
    let topic = eventually("the topic list", || {
        first.forum_topics().first().map(|t| t.id)
    })
    .await;
    first
        .new_forum_thread(
            topic,
            "Release".into(),
            "It is out.".into(),
            false,
            false,
            None,
        )
        .await
        .unwrap();
    let thread = eventually("the new thread", || {
        first.forum_threads(topic).first().map(|t| t.id)
    })
    .await;
    first.open_forum_thread(thread).await.unwrap();
    second.open_forum_thread(thread).await.unwrap();
    let post = eventually("the opening post", || {
        first
            .forum_posts(thread)
            .and_then(|p| p.first().map(|p| p.id))
    })
    .await;
    let star = |conn: &conclave_client::conn::ConclaveConnection| {
        conn.forum_posts(thread)
            .and_then(|posts| posts.into_iter().find(|p| p.id == post))
            .and_then(|p| p.reactions.into_iter().find(|r| r.emoji == '★'))
    };

    first.react_forum_post(post, '★', true).await.unwrap();
    eventually("the first Ada's reaction", || star(&first)).await;

    // The second Ada asks for it to come off. It is not hers to take back.
    second.react_forum_post(post, '★', false).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let mine = star(&first).expect("the first Ada's reaction still stands");
    assert_eq!(mine.count(), 1);
    assert!(mine.mine);
    // And from the other Ada's side it is still somebody else's. Waited for
    // rather than assumed: each viewer is sent the post's reactions separately,
    // so one side holding them says nothing about the other.
    let theirs = eventually("the second Ada's view of it", || star(&second)).await;
    assert!(!theirs.mine);
    assert_eq!(theirs.who, vec!["Ada".to_string()]);

    // Both reacting is two reactions from two people with one name.
    second.react_forum_post(post, '★', true).await.unwrap();
    let both = eventually("both Adas", || star(&first).filter(|r| r.count() == 2)).await;
    assert_eq!(both.who, vec!["Ada".to_string()]);
    assert!(both.mine);

    // The second Ada takes back her own, and only her own.
    second.react_forum_post(post, '★', false).await.unwrap();
    let left = eventually("one Ada left", || star(&first).filter(|r| r.count() == 1)).await;
    assert!(left.mine, "the reaction left standing is the first Ada's");

    // ── On a chat message ─────────────────────────────────────────────
    first.chat_join(0).await.unwrap();
    second.chat_join(0).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    first.chat_send(0, "Deploying".to_string()).await.unwrap();
    let message = eventually("the chat message", || {
        second
            .chat_room(0)?
            .lines
            .iter()
            .find_map(|line| match line {
                conclave_client::conn::ChatLine::Message { id, message, .. }
                    if message == "Deploying" =>
                {
                    Some(*id)
                }
                _ => None,
            })
    })
    .await;
    let chat_star = |conn: &conclave_client::conn::ConclaveConnection| {
        let me = conn.my_connection_id();
        conn.chat_room(0)?
            .lines
            .iter()
            .flat_map(|line| line.reaction_tallies(me))
            .find(|r| r.emoji == '★')
    };

    first.chat_react(0, message, '★', true).await.unwrap();
    eventually("the reaction arriving", || chat_star(&second)).await;

    // Same again: the other Ada cannot take back a reaction she did not make,
    // because a reaction is the connection's, not the name's.
    second.chat_react(0, message, '★', false).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    // The first Ada counts her own reaction once the server echoes it back to
    // the room, which is a separate delivery from the one the second Ada got.
    let still = eventually("the first Ada to count her own", || {
        chat_star(&first).filter(|r| r.mine)
    })
    .await;
    assert_eq!(still.count(), 1);
    assert!(
        !chat_star(&second)
            .expect("still on the second Ada's screen")
            .mine
    );

    server_process.abort();
}

/// A ballot belongs to a person, not to a name and not to a client install.
/// Renaming yourself is the same voter; so is the same account on a second
/// machine. Two genuinely separate anonymous identities are two voters, because
/// without accounts that is all the server can tell apart.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_poll_counts_the_person_not_the_client() {
    use conclave_common::poll::{NewPoll, PollDuration};

    const PORT: u16 = 8098;

    let tempdir = TempDir::new("conclave_revote").unwrap();
    let server_db = tempdir.path().join(format!("revote_{}.db", Uuid::new_v4()));

    let (server, password) = conclave_server::State::new(
        "Revote Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);

    server.set_forums_enabled(true).await.unwrap();
    server
        .create_forum_topic("Lunch".into(), String::new(), vec![])
        .await
        .unwrap();

    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // One config file is one identity: reconnecting through it keeps the key
    // whatever name is given, which is how a client keeps its identity at all.
    let voter_config = tempdir
        .path()
        .join(format!("voter_{}.toml", Uuid::new_v4()));
    let connect =
        async |config: std::path::PathBuf,
               name: &str,
               auth: Option<conclave_common::server::UserAuthentication>| {
            conclave_client::Client::new(config)
                .unwrap()
                .connect(
                    LOCALHOST.to_string().as_str(),
                    PORT,
                    true,
                    name.to_string(),
                    auth,
                    None,
                    None,
                    String::new(),
                    std::collections::BTreeMap::new(),
                )
                .await
                .unwrap()
        };

    let author = connect(
        tempdir
            .path()
            .join(format!("author_{}.toml", Uuid::new_v4())),
        "admin",
        Some(("admin".to_string(), password.to_string()).into()),
    )
    .await;

    let topic = eventually("the topic list", || {
        author.forum_topics().first().map(|t| t.id)
    })
    .await;
    author
        .new_forum_thread(
            topic,
            "Friday".into(),
            "Pick one.".into(),
            false,
            false,
            Some(NewPoll {
                question: "Where?".into(),
                options: vec!["Tacos".into(), "Pizza".into()],
                multiple_choices: false,
                duration: PollDuration::days(1).unwrap(),
                public_results: true,
            }),
        )
        .await
        .unwrap();
    let thread = eventually("the new thread", || {
        author.forum_threads(topic).first().map(|t| t.id)
    })
    .await;
    author.open_forum_thread(thread).await.unwrap();

    // Vote once as "Ada".
    let ada = connect(voter_config.clone(), "Ada", None).await;
    ada.open_forum_thread(thread).await.unwrap();
    let poll = eventually("the poll", || ada.forum_poll(thread)).await;
    let tacos = poll.options.iter().find(|o| o.text == "Tacos").unwrap().id;
    let pizza = poll.options.iter().find(|o| o.text == "Pizza").unwrap().id;
    ada.vote_forum_poll(poll.id, vec![tacos]).await.unwrap();
    eventually("the first vote", || {
        author
            .forum_poll(thread)
            .filter(|p| p.total_voters == Some(1))
    })
    .await;

    // Come back as "Grace" through the same config — same key, same voter.
    let grace = connect(voter_config.clone(), "Grace", None).await;
    assert_eq!(
        ada.my_public_key(),
        grace.my_public_key(),
        "one config file, one identity, whatever name it gives"
    );
    grace.open_forum_thread(thread).await.unwrap();
    let seen = eventually("the poll as Grace", || grace.forum_poll(thread)).await;
    // The poll already knows this voter, under the new name as under the old.
    assert!(seen.voted);

    grace.vote_forum_poll(poll.id, vec![pizza]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let after = author.forum_poll(thread).unwrap();
    assert_eq!(after.total_voters, Some(1), "still one voter, renamed");
    assert_eq!(
        after.options.iter().find(|o| o.id == pizza).unwrap().votes,
        Some(0),
        "the second ballot was not counted"
    );
    assert_eq!(
        after.options.iter().find(|o| o.id == tacos).unwrap().votes,
        Some(1),
        "and the first was not moved"
    );

    // A different anonymous identity is a different voter, even sharing a
    // display name: without an account, a key is all the server has to go on.
    let other = connect(
        tempdir
            .path()
            .join(format!("other_{}.toml", Uuid::new_v4())),
        "Ada",
        None,
    )
    .await;
    other.open_forum_thread(thread).await.unwrap();
    let fresh = eventually("the poll for a new identity", || {
        other.forum_poll(thread).filter(|p| !p.voted)
    })
    .await;
    other.vote_forum_poll(fresh.id, vec![pizza]).await.unwrap();
    let two = eventually("the second voter", || {
        author
            .forum_poll(thread)
            .filter(|p| p.total_voters == Some(2))
    })
    .await;
    assert_eq!(
        two.options.iter().find(|o| o.id == pizza).unwrap().votes,
        Some(1)
    );

    // An account, though, is one voter however many machines it votes from: a
    // second client signed in to the same account is a second key and the same
    // person, and the roll knows it by the account.
    let second_device = connect(
        tempdir
            .path()
            .join(format!("device_{}.toml", Uuid::new_v4())),
        "admin elsewhere",
        Some(("admin".to_string(), password.to_string()).into()),
    )
    .await;
    assert_ne!(
        author.my_public_key(),
        second_device.my_public_key(),
        "two installs, two keys"
    );

    // The author votes from the machine they created the poll on.
    author.vote_forum_poll(poll.id, vec![tacos]).await.unwrap();
    let three = eventually("the account's vote", || {
        author
            .forum_poll(thread)
            .filter(|p| p.total_voters == Some(3))
    })
    .await;
    assert_eq!(
        three.options.iter().find(|o| o.id == tacos).unwrap().votes,
        Some(2)
    );

    // The same account from the other machine is already on the roll.
    second_device.open_forum_thread(thread).await.unwrap();
    let elsewhere = eventually("the poll on the other machine", || {
        second_device.forum_poll(thread)
    })
    .await;
    assert!(
        elsewhere.voted,
        "the account has voted, whichever machine asks"
    );
    // And it can still see the tally early, because the author is the account.
    assert!(elsewhere.results_visible());

    second_device
        .vote_forum_poll(poll.id, vec![pizza])
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let unchanged = author.forum_poll(thread).unwrap();
    assert_eq!(
        unchanged.total_voters,
        Some(3),
        "one account, one vote, two devices"
    );
    assert_eq!(
        unchanged
            .options
            .iter()
            .find(|o| o.id == tacos)
            .unwrap()
            .votes,
        Some(2)
    );

    server_process.abort();
}

/// A reaction to a direct message rides inside the same sealed envelope as the
/// message, so the server relaying it cannot tell the two apart. Both sides see
/// the tally, each recognising their own, and either side can react to either
/// side's messages.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_message_reactions_stay_inside_the_encryption() {
    use conclave_client::conn::DmBody;

    const PORT: u16 = 8099;

    let tempdir = TempDir::new("conclave_dm_react").unwrap();
    let server_db = tempdir
        .path()
        .join(format!("dm_react_{}.db", Uuid::new_v4()));

    let (server, _password) = conclave_server::State::new(
        "Reaction DM Server".into(),
        "Description".into(),
        LOCALHOST,
        Some("localhost".into()),
        PORT,
        false,
        server_db,
    )
    .unwrap();
    let server = Arc::new(server);
    let server_clone = server.clone();
    let server_process = tokio::spawn(async move { server_clone.serve().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let connect = async |name: &str| {
        conclave_client::Client::new(
            tempdir
                .path()
                .join(format!("{name}_{}.toml", Uuid::new_v4())),
        )
        .unwrap()
        .connect(
            LOCALHOST.to_string().as_str(),
            PORT,
            true,
            name.to_string(),
            None,
            None,
            None,
            String::new(),
            std::collections::BTreeMap::new(),
        )
        .await
        .unwrap()
    };
    let alice = connect("alice").await;
    let bob = connect("bob").await;

    let peer_id = async |conn: &conclave_client::conn::ConclaveConnection, name: &str| {
        eventually(&format!("{name}'s connection id"), || {
            conn.get_connected_users()
                .into_iter()
                .find(|user| user.display_name == name)
                .map(|user| user.id)
        })
        .await
    };
    let bob_id = peer_id(&alice, "bob").await;
    let alice_id = peer_id(&bob, "alice").await;

    // Alice says something; both sides end up holding the same message, each
    // from their own side of it.
    alice
        .send_dm(bob_id, "shipping today".to_string())
        .await
        .unwrap();
    let said = |conn: &conclave_client::conn::ConclaveConnection, peer: u16| {
        conn.dm_thread(peer)
            .into_iter()
            .find(|m| matches!(&m.body, DmBody::Text(t) if t == "shipping today"))
    };
    let on_bobs_side = eventually("bob to receive it", || said(&bob, alice_id)).await;
    let on_alices_side = said(&alice, bob_id).expect("her own message");
    let id = on_bobs_side.id.expect("a message carries a number");
    assert_eq!(
        on_alices_side.id,
        Some(id),
        "the sender's number, both sides"
    );
    assert!(on_alices_side.from_me, "hers");
    assert!(!on_bobs_side.from_me, "not his");

    // Bob reacts to her message. From his side it is not his own, so the
    // reference he sends says so, and she has to read it the other way round.
    bob.react_dm(alice_id, id, false, '★', true).await.unwrap();

    let hers = eventually("the reaction reaching alice", || {
        said(&alice, bob_id)
            .map(|m| m.reaction_tallies("bob"))
            .filter(|t| !t.is_empty())
    })
    .await;
    assert_eq!(hers.len(), 1);
    assert_eq!(hers[0].emoji, '★');
    assert_eq!(hers[0].count(), 1);
    assert!(!hers[0].mine, "bob's reaction is not alice's");
    assert_eq!(hers[0].who_line(), "★ bob");

    // And Bob sees his own as his.
    let his = said(&bob, alice_id).unwrap().reaction_tallies("alice");
    assert!(his[0].mine);
    assert_eq!(his[0].who_line(), "★ you");

    // Alice joins the same emoji: two people, one reaction each.
    alice.react_dm(bob_id, id, true, '★', true).await.unwrap();
    let both = eventually("both reactions", || {
        said(&bob, alice_id)
            .map(|m| m.reaction_tallies("alice"))
            .filter(|t| t.first().is_some_and(|r| r.count() == 2))
    })
    .await;
    assert_eq!(both[0].who_line(), "★ alice and you");

    // Bob takes his back; hers stands.
    bob.react_dm(alice_id, id, false, '★', false).await.unwrap();
    let left = eventually("bob's reaction withdrawn", || {
        said(&alice, bob_id)
            .map(|m| m.reaction_tallies("bob"))
            .filter(|t| t.first().is_some_and(|r| r.count() == 1))
    })
    .await;
    assert!(left[0].mine, "what is left is alice's own");

    // Either side can react to its own messages too, and to a second message
    // numbered separately from the first.
    bob.send_dm(alice_id, "on it".to_string()).await.unwrap();
    let bobs_own = eventually("bob's own message", || {
        bob.dm_thread(alice_id)
            .into_iter()
            .find(|m| matches!(&m.body, DmBody::Text(t) if t == "on it"))
    })
    .await;
    let bob_msg = bobs_own.id.expect("numbered");
    alice
        .react_dm(bob_id, bob_msg, false, '♡', true)
        .await
        .unwrap();
    let on_his = eventually("her reaction to his message", || {
        bob.dm_thread(alice_id)
            .into_iter()
            .find(|m| m.id == Some(bob_msg) && m.from_me)
            .map(|m| m.reaction_tallies("alice"))
            .filter(|t| !t.is_empty())
    })
    .await;
    assert_eq!(on_his[0].emoji, '♡');
    assert!(!on_his[0].mine, "hers, on his message");

    // Her ★ on the first message is untouched by any of that.
    let first = said(&bob, alice_id).unwrap().reaction_tallies("alice");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].emoji, '★');

    // A letter is not a reaction, and nothing is sent when it is refused.
    assert!(bob.react_dm(alice_id, id, false, 'x', true).await.is_err());

    server_process.abort();
}
