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
