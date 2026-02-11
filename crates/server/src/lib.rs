// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

/// Server state
pub struct State {
    /// Server name
    pub name: String,

    /// Server description
    pub description: String,

    /// Advertised URL
    pub url: String,
}

#[cfg(test)]
mod tests {
    use conclave_common::tracker::TrackerProtocol::AdvertiseServer;
    use conclave_common::tracker::{Advertise, TrackerProtocol};

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Once;

    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpStream;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    fn init_tracing() {
        tracing_subscriber::fmt::init();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn advertise() {
        static TRACING: Once = Once::new();
        TRACING.call_once(init_tracing);

        let version = env!("CARGO_PKG_VERSION").parse().unwrap();

        let port = 8080u16;

        let tracker = tokio::spawn(async move {
            let state = conclave_tracker::State::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            state.serve().await.expect("Failed to start tracker");
        });
        assert!(!tracker.is_finished());

        {
            let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            let serialized = postcard::to_stdvec(&TrackerProtocol::GetServers).unwrap();
            framed.send(Bytes::from(serialized)).await.unwrap();
            if let Some(res_result) = framed.next().await {
                let bytes = res_result.unwrap();
                let resp: TrackerProtocol = postcard::from_bytes(&bytes).unwrap();
                match resp {
                    TrackerProtocol::ServersList(servers) => {
                        assert!(servers.is_empty());
                    }
                    _ => panic!("Unexpected response type"),
                }
            }
        }

        {
            let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            let server = AdvertiseServer(Advertise {
                name: "Testing".to_string(),
                description: "Testing".to_string(),
                version,
                anonymous: false,
                url: String::new(),
            });
            let serialized = postcard::to_stdvec(&server).unwrap();
            framed.send(Bytes::from(serialized)).await.unwrap();
        }

        {
            let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

            let serialized = postcard::to_stdvec(&TrackerProtocol::GetServers).unwrap();
            framed.send(Bytes::from(serialized)).await.unwrap();
            if let Some(res_result) = framed.next().await {
                let bytes = res_result.unwrap();
                let resp: TrackerProtocol = postcard::from_bytes(&bytes).unwrap();
                match resp {
                    TrackerProtocol::ServersList(servers) => {
                        assert_eq!(servers.len(), 1);
                        assert_eq!(servers[0].name, "Testing");
                    }
                    _ => panic!("Unexpected response type"),
                }
            }
        }

        tracker.abort();
    }
}
