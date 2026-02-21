// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, Interest, Ready};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::RwLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::ZeroizeOnDrop;

/// Protocol version
const VERSION: u8 = 1;

#[derive(ZeroizeOnDrop)]
struct CryptoAlgorithmAndCounter<const REKEY_INTERVAL: u16> {
    cipher: XChaCha20Poly1305,
    current_key: [u8; 32],
    record_count: u16,
}

impl<const REKEY_INTERVAL: u16> CryptoAlgorithmAndCounter<REKEY_INTERVAL> {
    fn rekey(&mut self) -> Result<()> {
        // Derive the new key from the current key
        let hk = Hkdf::<Sha256>::new(None, &self.current_key);
        let mut new_key = [0u8; 32];
        hk.expand(b"secure-stream-rekey", &mut new_key)
            .map_err(|_| anyhow!("Rekey failed"))?;

        // Use the new key
        self.cipher = XChaCha20Poly1305::new(Key::from_slice(&new_key));
        self.current_key = new_key;

        self.record_count = 0;
        Ok(())
    }

    async fn recv<R: AsyncRead + Unpin>(&mut self, stream: &mut R) -> Result<Vec<u8>> {
        if self.record_count >= REKEY_INTERVAL {
            self.rekey()?;
        }

        let version = stream.read_u8().await?;
        if version != VERSION {
            return Err(anyhow!("Unsupported protocol version: {version}"));
        }

        let len = stream.read_u32().await?;
        if len < 24 + 16 {
            return Err(anyhow!("Invalid record length"));
        }

        let mut nonce_bytes = [0u8; 24];
        stream.read_exact(&mut nonce_bytes).await?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext_len = len as usize - 24;
        let mut buf = vec![0u8; ciphertext_len];
        stream.read_exact(&mut buf).await?;

        // AAD = version || len || nonce
        let mut aad = Vec::with_capacity(1 + 4 + 24);
        aad.push(version);
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(&nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: &buf,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("Decryption failed: {e}"))?;

        self.record_count += 1;
        Ok(plaintext)
    }

    async fn send<S: AsyncWrite + Unpin>(&mut self, stream: &mut S, data: &[u8]) -> Result<()> {
        use rand::RngCore;

        // Rekey if needed
        if self.record_count >= REKEY_INTERVAL {
            self.rekey()?;
        }

        // Generate random 192-bit nonce
        let mut nonce_bytes = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Ciphertext length = nonce (24) + plaintext + 16-byte tag
        let len = u32::try_from(24 + data.len() + 16)?;

        // AAD = version || len || nonce
        let mut aad = Vec::with_capacity(1 + 4 + 24);
        aad.push(VERSION);
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: data,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("Encryption failed: {e}"))?;

        stream.write_u8(VERSION).await?;
        stream.write_u32(len).await?;
        stream.write_all(&nonce_bytes).await?;
        stream.write_all(&encrypted).await?;

        self.record_count += 1;
        Ok(())
    }

    #[inline]
    #[allow(clippy::unused_self, unused)]
    const fn interval(&self) -> u16 {
        REKEY_INTERVAL
    }
}

/// Write half of the encrypted stream
pub struct EncryptedWrite<const REKEY_INTERVAL: u16> {
    crypto: Arc<RwLock<CryptoAlgorithmAndCounter<REKEY_INTERVAL>>>,
    write: OwnedWriteHalf,
}

impl<const REKEY_INTERVAL: u16> EncryptedWrite<REKEY_INTERVAL> {
    /// Send data
    ///
    /// # Errors
    ///
    /// Network errors
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.crypto.write().await.send(&mut self.write, data).await
    }

    #[inline]
    #[allow(clippy::unused_self, unused)]
    const fn interval(&self) -> u16 {
        REKEY_INTERVAL
    }
}

/// Read half of the encrypted stream
pub struct EncryptedRead<const REKEY_INTERVAL: u16> {
    crypto: Arc<RwLock<CryptoAlgorithmAndCounter<REKEY_INTERVAL>>>,
    read: OwnedReadHalf,
}

impl<const REKEY_INTERVAL: u16> EncryptedRead<REKEY_INTERVAL> {
    /// Receive data
    ///
    /// # Errors
    ///
    /// Network errors
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.crypto.write().await.recv(&mut self.read).await
    }

    #[inline]
    #[allow(clippy::unused_self, unused)]
    const fn interval(&self) -> u16 {
        REKEY_INTERVAL
    }
}

/// Default `EncryptedStream`
pub type DefaultEncryptedStream = EncryptedStream<1_000>;

/// Encrypted socket
pub struct EncryptedStream<const REKEY_INTERVAL: u16> {
    stream: TcpStream,
    crypto: CryptoAlgorithmAndCounter<REKEY_INTERVAL>,
}

impl<const REKEY_INTERVAL: u16> EncryptedStream<REKEY_INTERVAL> {
    /// Client: Create an encrypted stream for connecting to a server
    ///
    /// # Errors
    ///
    /// Network or cryptography errors are possible.
    pub async fn connect(mut stream: TcpStream, server_identity: &VerifyingKey) -> Result<Self> {
        // --- Client ephemeral ---
        let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);

        let client_pub = X25519Public::from(&client_secret);

        // Send client ephemeral
        stream.write_all(client_pub.as_bytes()).await?;

        // --- Receive server ephemeral ---
        let mut server_pub_buf = [0u8; 32];
        stream.read_exact(&mut server_pub_buf).await?;
        let server_pub = X25519Public::from(server_pub_buf);

        // --- Receive signature ---
        let mut sig_buf = [0u8; 64];
        stream.read_exact(&mut sig_buf).await?;
        let sig = Signature::from_bytes(&sig_buf);

        // Verify server signed both keys
        let mut transcript = [0u8; 64];
        transcript[..32].copy_from_slice(client_pub.as_bytes());
        transcript[32..].copy_from_slice(server_pub.as_bytes());

        server_identity
            .verify(&transcript, &sig)
            .map_err(|e| anyhow!("Failed to verify signature: {e}"))?;

        // --- Derive shared secret ---
        let shared = client_secret.diffie_hellman(&server_pub);

        let key = derive_key(shared.as_bytes());

        Ok(Self {
            stream,
            crypto: CryptoAlgorithmAndCounter {
                cipher: XChaCha20Poly1305::new(Key::from_slice(&key)),
                current_key: key,
                record_count: 0,
            },
        })
    }

    /// Server: Accept an encrypted stream from a client
    ///
    /// # Errors
    ///
    /// Network or cryptography errors are possible.
    pub async fn accept(mut stream: TcpStream, server_identity: &SigningKey) -> Result<Self> {
        // Receive client ephemeral
        let mut client_buf = [0u8; 32];
        stream.read_exact(&mut client_buf).await?;
        let client_pub = X25519Public::from(client_buf);

        // Server ephemeral
        let server_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);

        let server_pub = X25519Public::from(&server_secret);

        // Send server ephemeral
        stream.write_all(server_pub.as_bytes()).await?;

        // --- Sign transcript ---
        let mut transcript = [0u8; 64];
        transcript[..32].copy_from_slice(client_pub.as_bytes());
        transcript[32..].copy_from_slice(server_pub.as_bytes());

        let sig = server_identity.sign(&transcript);

        stream.write_all(&sig.to_bytes()).await?;

        // --- Shared secret ---
        let shared = server_secret.diffie_hellman(&client_pub);

        let key = derive_key(shared.as_bytes());

        Ok(Self {
            stream,
            crypto: CryptoAlgorithmAndCounter {
                cipher: XChaCha20Poly1305::new(Key::from_slice(&key)),
                current_key: key,
                record_count: 0,
            },
        })
    }

    /// Send data over the encrypted socket
    ///
    /// # Errors
    ///
    /// Networking errors may result
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.crypto.send(&mut self.stream, data).await
    }

    /// Receive data over the encrypted socket
    ///
    /// # Errors
    ///
    /// Networking errors may result
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.crypto.recv(&mut self.stream).await
    }

    /// Close the connection
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }

    /// Check on socket's readiness
    ///
    /// # Errors
    ///
    /// Network errors are possible
    pub async fn ready(&self, interest: Interest) -> io::Result<Ready> {
        self.stream.ready(interest).await
    }

    /// Get the peer address
    ///
    /// # Errors
    ///
    /// Network errors are possible but improbable.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    /// Reads the linger duration for the socket
    ///
    /// # Errors
    ///
    /// Network errors are possible but improbable.
    pub fn linger(&self) -> io::Result<Option<Duration>> {
        self.stream.linger()
    }

    /// Wait for the socket to become readable
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn readable(&self) -> io::Result<()> {
        self.stream.readable().await
    }

    /// Wait for the socket to become readable
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    pub async fn writable(&self) -> io::Result<()> {
        self.stream.writable().await
    }

    /// Get the `TCP_NODELAY` option on the socket.
    ///
    /// # Errors
    ///
    /// Errors shouldn't happen.
    pub fn nodelay(&self) -> io::Result<bool> {
        self.stream.nodelay()
    }

    /// Set the `TCP_NODELAY` option on the socket
    ///
    /// # Errors
    ///
    /// Shouldn't be any errors
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    #[inline]
    #[allow(unused)]
    const fn interval(&self) -> u16 {
        self.crypto.interval()
    }

    /// Split the encrypted stream into separate read and write halves
    pub fn into_split(
        self,
    ) -> (
        EncryptedRead<REKEY_INTERVAL>,
        EncryptedWrite<REKEY_INTERVAL>,
    ) {
        let crypto = Arc::new(RwLock::new(self.crypto));
        let (read, write) = self.stream.into_split();
        (
            EncryptedRead {
                crypto: crypto.clone(),
                read,
            },
            EncryptedWrite { crypto, write },
        )
    }
}

impl<const REKEY_INTERVAL: u16> std::fmt::Debug for EncryptedStream<REKEY_INTERVAL> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(addr) = self.peer_addr() {
            write!(f, "EncryptedStream to {addr}")
        } else {
            write!(f, "EncryptedStream")
        }
    }
}

#[inline]
fn derive_key(shared: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(b"secure-stream", &mut key).unwrap();
    key
}

/// Generate random server keys
#[must_use]
pub fn random_server_keys() -> (SigningKey, VerifyingKey) {
    let mut bytes = [0u8; 32];
    let mut rng = rand::rngs::OsRng;

    rng.fill(&mut bytes);
    let signing = SigningKey::from_bytes(&bytes);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crypto_socket() {
        const PORT: u16 = 12345;

        let (server_signing, server_verifying) = random_server_keys();
        let handle = tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();
            eprintln!("Server listening on port {PORT}");
            let (stream, _) = listener.accept().await.unwrap();
            let mut link = EncryptedStream::<100>::accept(stream, &server_signing)
                .await
                .expect("Server Accept failed");
            loop {
                println!("EncryptedStream: accept() created, waiting for data");
                let mut msg = link.recv().await.expect("Server Receive failed");
                println!("Server Received: {msg:?}");
                msg.reverse();
                println!("Server Sending: {msg:?}");
                link.send(&msg).await.expect("Server Send failed");
            }
        });
        tokio::time::sleep(Duration::from_secs(1)).await; // Required by Linux
        assert!(!handle.is_finished());
        eprintln!("Server process created.");

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let mut link = EncryptedStream::<100>::connect(stream, &server_verifying)
            .await
            .expect("Client Connect failed");
        println!("EncryptedStream: connect() created, sending data");

        for _ in 0..link.interval() * 3 {
            let uuid = Uuid::new_v4().to_string();
            let uuid_bytes = uuid.as_bytes();
            println!("Client Sending: {uuid_bytes:?}");
            link.send(uuid_bytes).await.expect("Client Send failed");
            let mut msg = link.recv().await.expect("Client Receive failed");
            println!("Client Received: {msg:?}");
            msg.reverse();
            assert_eq!(msg, uuid_bytes);
        }

        // We would rekey on the next exchange.
        assert_eq!(link.crypto.record_count, link.interval());

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn crypto_socket_split() {
        const PORT: u16 = 12399;

        let (server_signing, server_verifying) = random_server_keys();

        let handle = tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();
            eprintln!("Server listening on port {PORT}");
            let (stream, _) = listener.accept().await.unwrap();
            let mut link = EncryptedStream::<100>::accept(stream, &server_signing)
                .await
                .expect("Server Accept failed");
            loop {
                println!("EncryptedStream: accept() created, waiting for data");
                let mut msg = link.recv().await.expect("Server Receive failed");
                println!("Server Received: {msg:?}");
                msg.reverse();
                println!("Server Sending: {msg:?}");
                link.send(&msg).await.expect("Server Send failed");
            }
        });
        tokio::time::sleep(Duration::from_secs(1)).await; // Required by Linux
        assert!(!handle.is_finished());
        eprintln!("Server process created.");

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let link = EncryptedStream::<100>::connect(stream, &server_verifying)
            .await
            .expect("Client Connect failed");
        println!("EncryptedStream: connect() created, sending data");

        let uuid_vec = (0..link.interval() * 3)
            .map(|_| Uuid::new_v4().to_string())
            .collect::<Vec<_>>();
        let (mut read, mut write) = link.into_split();

        let uuid_vec_clone = uuid_vec.clone();
        let read_process = tokio::spawn(async move {
            for uuid in uuid_vec_clone {
                let mut msg = read.recv().await.expect("Client Receive failed");
                println!("Client Received: {msg:?}");
                msg.reverse();

                let uuid_bytes = uuid.as_bytes();
                assert_eq!(msg, uuid_bytes);
            }
        });

        for uuid in uuid_vec {
            let uuid_bytes = uuid.as_bytes();
            println!("Client Sending: {uuid_bytes:?}");
            write.send(uuid_bytes).await.expect("Client Send failed");
        }

        // We would rekey on the next exchange.
        assert_eq!(write.crypto.read().await.record_count, write.interval());

        read_process.abort();
        handle.abort();
    }
}
