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
    // Ensure the calls to unwrap() in the semver parsing don't panic.
    assert!(!conclave_client::VERSION.build.is_empty()); // Git hash
    println!("Semver version: {:?}", conclave_client::VERSION);
    let _ = conclave_client::VERSION.to_string();
    let v = conclave_server::VERSION.to_string();
    println!("Version: {v}");
    let _ = conclave_tracker::VERSION.to_string();
    assert_eq!(*conclave_client::VERSION, *conclave_server::VERSION);
    assert_eq!(*conclave_tracker::VERSION, *conclave_server::VERSION);
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

    // Both advertised identity keys. A file transfer has no unencrypted mode,
    // so this is what makes one possible at all: the name arriving intact below
    // is itself evidence it was sealed to the shared key and opened again.
    assert!(alice.dm_encrypted_with(bob_id));
    assert!(bob.dm_encrypted_with(alice_id));

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
