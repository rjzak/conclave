// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tempdir::TempDir;
use uuid::Uuid;

const TRACKER_PORT: u16 = 8080;
const SERVER_PORT: u16 = 8090;
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

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
    let tracker = Arc::new(conclave_tracker::State::new(LOCALHOST, TRACKER_PORT));
    let tracker_clone = tracker.clone();
    let tracker_process = tokio::spawn(async move {
        eprintln!("Tracker process starting");
        tracker_clone.serve().await.unwrap();
    });

    // Set up the server
    let server = Arc::new(
        conclave_server::State::new(
            "Conclave Server".into(),
            "Description".into(),
            LOCALHOST,
            SERVER_PORT,
            SERVER_PORT + 1,
            server_db,
        )
        .unwrap(),
    );
    server.add_tracker(LOCALHOST, TRACKER_PORT).await.unwrap();
    let server_clone = server.clone();
    let server_process = tokio::spawn(async move {
        eprintln!("Tracker process starting");
        server_clone.serve().await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    client
        .add_tracker(LOCALHOST.to_string().as_str(), TRACKER_PORT)
        .await
        .unwrap();

    eprintln!("Client: added tracker, querying tracker(s)");
    assert_eq!(client.list_servers().await.unwrap().len(), 1);

    eprintln!("Tracker: querying for server(s)");
    assert_eq!(tracker.servers().len(), 1);

    eprintln!("Server: querying for connected user(s)");
    assert!(server.connected_users().await.is_empty());

    client
        .connect(
            LOCALHOST.to_string().as_str(),
            SERVER_PORT,
            "Unnamed",
            None,
            None,
        )
        .await
        .unwrap();

    // Cleanup
    tracker_process.abort();
    server_process.abort();
}
