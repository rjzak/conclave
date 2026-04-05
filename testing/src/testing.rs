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
    let tracker = Arc::new(conclave_tracker::DefaultState::new(LOCALHOST, TRACKER_PORT));
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
        SERVER_PORT + 1,
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
        0
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
    assert!(server.anonymous_clients_allowed().await.unwrap());
    server.anonymous_clients_enabled(false).await.unwrap();
    assert!(!server.anonymous_clients_allowed().await.unwrap());

    client
        .add_tracker(LOCALHOST.to_string().as_str(), TRACKER_PORT)
        .await
        .unwrap();

    eprintln!("Client: added tracker, querying tracker(s)");
    assert_eq!(client.list_servers().await.unwrap().len(), 1);

    eprintln!("Tracker: querying for server(s)");
    let tracked_servers = tracker.servers();
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
