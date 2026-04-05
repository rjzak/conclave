// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::time::Duration;

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, Interest, Ready};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::ZeroizeOnDrop;

/// Protocol version
const VERSION: u8 = 1;

/// Indicates that the client provided a key during the handshake
const USE_CLIENT_KEY: u8 = 1;

/// HKDF info for rekeying
const REKEY_INFO: &[u8] = b"secure-stream-rekey";

/// HKDF info for deriving the key in one direction
const KEY_INFO_1: &[u8] = b"secure-stream";

/// HKDF info for deriving the key in the other direction
const KEY_INFO_2: &[u8] = b"the-other-side";

/// Single-direction crypto state.
#[derive(ZeroizeOnDrop)]
struct DirectionalCrypto<const REKEY_INTERVAL: u16> {
    /// XChaCha20-Poly1305 cipher with a 256-bit key.
    cipher: XChaCha20Poly1305,

    /// Copy of the key bytes used for rekeying.
    key: [u8; 32],

    /// Counter to trigger rekeying
    count: u16,
}

impl<const REKEY_INTERVAL: u16> DirectionalCrypto<REKEY_INTERVAL> {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(Key::from_slice(&key)),
            key,
            count: 0,
        }
    }

    fn rekey(&mut self) -> Result<()> {
        let hk = Hkdf::<Sha256>::new(None, &self.key);
        let mut new_key = [0u8; 32];
        hk.expand(REKEY_INFO, &mut new_key)
            .map_err(|_| anyhow!("Rekey failed"))?;
        self.cipher = XChaCha20Poly1305::new(Key::from_slice(&new_key));
        self.key = new_key;
        self.count = 0;
        Ok(())
    }

    async fn recv<R: AsyncRead + Unpin>(&mut self, stream: &mut R) -> Result<Vec<u8>> {
        if self.count >= REKEY_INTERVAL {
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

        self.count += 1;
        Ok(plaintext)
    }

    async fn send<S: AsyncWrite + Unpin>(&mut self, stream: &mut S, data: &[u8]) -> Result<()> {
        if self.count >= REKEY_INTERVAL {
            self.rekey()?;
        }

        // Generate random 192-bit nonce
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
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

        self.count += 1;
        Ok(())
    }
}

/// Write half of the encrypted stream
pub struct EncryptedWrite<const REKEY_INTERVAL: u16> {
    write: OwnedWriteHalf,
    crypto: DirectionalCrypto<REKEY_INTERVAL>,
    /// The verified client identity, set by the server after a successful client-authenticated handshake.
    client_key: Option<VerifyingKey>,
}

impl<const REKEY_INTERVAL: u16> EncryptedWrite<REKEY_INTERVAL> {
    /// Send data
    ///
    /// # Errors
    ///
    /// Network errors
    #[inline]
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.crypto.send(&mut self.write, data).await
    }

    /// Returns the verified client identity, if the client authenticated during the handshake.
    /// Only populated on the server side after `accept`.
    #[inline]
    #[must_use]
    pub fn client_key(&self) -> Option<&VerifyingKey> {
        self.client_key.as_ref()
    }

    /// Encryption rekey interval by number of messages sent.
    #[inline]
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn interval(&self) -> u16 {
        REKEY_INTERVAL
    }
}

/// Read half of the encrypted stream
pub struct EncryptedRead<const REKEY_INTERVAL: u16> {
    read: OwnedReadHalf,
    crypto: DirectionalCrypto<REKEY_INTERVAL>,
}

impl<const REKEY_INTERVAL: u16> EncryptedRead<REKEY_INTERVAL> {
    /// Receive data
    ///
    /// # Errors
    ///
    /// Network errors
    #[inline]
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.crypto.recv(&mut self.read).await
    }

    /// Encryption rekey interval by number of messages sent.
    #[inline]
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn interval(&self) -> u16 {
        REKEY_INTERVAL
    }
}

/// Default `EncryptedStream`
pub type DefaultEncryptedStream = EncryptedStream<1_000>;

/// Encrypted socket
pub struct EncryptedStream<const REKEY_INTERVAL: u16> {
    stream: TcpStream,
    send_crypto: DirectionalCrypto<REKEY_INTERVAL>,
    recv_crypto: DirectionalCrypto<REKEY_INTERVAL>,
    /// The verified client identity, set by the server after a successful client-authenticated handshake.
    client_key: Option<VerifyingKey>,
}

impl<const REKEY_INTERVAL: u16> EncryptedStream<REKEY_INTERVAL> {
    /// Client: Create an encrypted stream for connecting to a server optionally with a client key
    ///
    /// # Errors
    ///
    /// Network or cryptography errors are possible.
    pub async fn connect(
        mut stream: TcpStream,
        server_identity: &VerifyingKey,
        client_key: Option<&SigningKey>,
    ) -> Result<Self> {
        // --- Client ephemeral ML-KEM keypair ---
        let (client_pubkey, client_seckey) = mlkem1024::keypair();
        let pk_bytes = client_pubkey.as_bytes();

        // Send client public key
        stream.write_all(pk_bytes).await?;

        // --- Receive server ciphertext (encapsulation of client's public key) ---
        let mut ct_buf = [0u8; mlkem1024::ciphertext_bytes()];
        stream.read_exact(&mut ct_buf).await?;
        let ciphertext = mlkem1024::Ciphertext::from_bytes(&ct_buf)
            .map_err(|e| anyhow!("Invalid ciphertext: {e:?}"))?;

        // --- Receive server signature ---
        let mut sig_buf = [0u8; 64];
        stream.read_exact(&mut sig_buf).await?;
        let sig = Signature::from_bytes(&sig_buf);

        // Verify server signed transcript = client_pk || ciphertext
        let mut transcript = Vec::with_capacity(pk_bytes.len() + ct_buf.len());
        transcript.extend_from_slice(pk_bytes);
        transcript.extend_from_slice(&ct_buf);

        server_identity
            .verify(&transcript, &sig)
            .map_err(|e| anyhow!("Failed to verify signature: {e}"))?;

        // --- Decapsulate to recover shared secret ---
        let shared = mlkem1024::decapsulate(&ciphertext, &client_seckey);

        if let Some(client_key) = client_key {
            // Signal: verifying key and signature follow
            stream.write_u8(USE_CLIENT_KEY).await?;
            stream
                .write_all(client_key.verifying_key().as_bytes())
                .await?;
            let client_sig = client_key.sign(&transcript);
            stream.write_all(&client_sig.to_bytes()).await?;
        } else {
            stream.write_u8(0).await?;
        }

        let send_key = derive_key(KEY_INFO_1, shared.as_bytes());
        let recv_key = derive_key(KEY_INFO_2, shared.as_bytes());

        Ok(Self {
            stream,
            send_crypto: DirectionalCrypto::new(send_key),
            recv_crypto: DirectionalCrypto::new(recv_key),
            client_key: None,
        })
    }

    /// Server: Accept an encrypted stream from a client
    ///
    /// # Errors
    ///
    /// Network or cryptography errors are possible.
    pub async fn accept(mut stream: TcpStream, server_identity: &SigningKey) -> Result<Self> {
        // Receive client ML-KEM public key
        let mut pk_buf = [0u8; mlkem1024::public_key_bytes()];
        stream.read_exact(&mut pk_buf).await?;
        let client_pk = mlkem1024::PublicKey::from_bytes(&pk_buf)
            .map_err(|e| anyhow!("Invalid client public key: {e:?}"))?;

        // Encapsulate using client's public key → (shared_secret, ciphertext)
        let (shared, ciphertext) = mlkem1024::encapsulate(&client_pk);
        let ct_bytes = ciphertext.as_bytes();

        // Build transcript = client_pk || ciphertext and sign it
        let mut transcript = Vec::with_capacity(pk_buf.len() + ct_bytes.len());
        transcript.extend_from_slice(&pk_buf);
        transcript.extend_from_slice(ct_bytes);

        let sig = server_identity.sign(&transcript);

        // Send ciphertext then signature
        stream.write_all(ct_bytes).await?;
        stream.write_all(&sig.to_bytes()).await?;

        // Read client auth flag; if set, verify the client's verifying key and signature
        let client_key = if stream.read_u8().await? == USE_CLIENT_KEY {
            let mut vk_buf = [0u8; 32];
            stream.read_exact(&mut vk_buf).await?;
            let verifying_key = VerifyingKey::from_bytes(&vk_buf)
                .map_err(|e| anyhow!("Invalid client verifying key: {e}"))?;

            let mut client_sig_buf = [0u8; 64];
            stream.read_exact(&mut client_sig_buf).await?;
            let client_sig = Signature::from_bytes(&client_sig_buf);

            verifying_key
                .verify(&transcript, &client_sig)
                .map_err(|e| anyhow!("Failed to verify client signature: {e}"))?;

            Some(verifying_key)
        } else {
            None
        };

        let recv_key = derive_key(KEY_INFO_1, shared.as_bytes());
        let send_key = derive_key(KEY_INFO_2, shared.as_bytes());

        Ok(Self {
            stream,
            send_crypto: DirectionalCrypto::new(send_key),
            recv_crypto: DirectionalCrypto::new(recv_key),
            client_key,
        })
    }

    /// Send data over the encrypted socket
    ///
    /// # Errors
    ///
    /// Networking errors may result
    #[inline]
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.send_crypto.send(&mut self.stream, data).await
    }

    /// Receive data over the encrypted socket
    ///
    /// # Errors
    ///
    /// Networking errors may result
    #[inline]
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        self.recv_crypto.recv(&mut self.stream).await
    }

    /// Close the connection
    ///
    /// # Errors
    ///
    /// Network errors are possible
    #[inline]
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }

    /// Check on socket's readiness
    ///
    /// # Errors
    ///
    /// Network errors are possible
    #[inline]
    pub async fn ready(&self, interest: Interest) -> io::Result<Ready> {
        self.stream.ready(interest).await
    }

    /// Get the peer address
    ///
    /// # Errors
    ///
    /// Network errors are possible but improbable.
    #[inline]
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    /// Reads the linger duration for the socket
    ///
    /// # Errors
    ///
    /// Network errors are possible but improbable.
    #[inline]
    pub fn linger(&self) -> io::Result<Option<Duration>> {
        self.stream.linger()
    }

    /// Wait for the socket to become readable
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    #[inline]
    pub async fn readable(&self) -> io::Result<()> {
        self.stream.readable().await
    }

    /// Wait for the socket to become writable
    ///
    /// # Errors
    ///
    /// Network errors are possible.
    #[inline]
    pub async fn writable(&self) -> io::Result<()> {
        self.stream.writable().await
    }

    /// Get the `TCP_NODELAY` option on the socket.
    ///
    /// # Errors
    ///
    /// Errors shouldn't happen.
    #[inline]
    pub fn nodelay(&self) -> io::Result<bool> {
        self.stream.nodelay()
    }

    /// Set the `TCP_NODELAY` option on the socket
    ///
    /// # Errors
    ///
    /// Shouldn't be any errors
    #[inline]
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    /// Returns the verified client identity, if the client authenticated during the handshake.
    /// Only populated on the server side after `accept`.
    #[inline]
    #[must_use]
    pub fn client_key(&self) -> Option<&VerifyingKey> {
        self.client_key.as_ref()
    }

    /// Encryption rekey interval by number of messages sent.
    #[inline]
    #[allow(clippy::unused_self)]
    pub const fn interval(&self) -> u16 {
        REKEY_INTERVAL
    }

    /// Split the encrypted stream into separate read and write halves.
    /// Each half owns its crypto state independently — no shared lock.
    pub fn into_split(
        self,
    ) -> (
        EncryptedRead<REKEY_INTERVAL>,
        EncryptedWrite<REKEY_INTERVAL>,
    ) {
        let (read_half, write_half) = self.stream.into_split();
        (
            EncryptedRead {
                read: read_half,
                crypto: self.recv_crypto,
            },
            EncryptedWrite {
                write: write_half,
                crypto: self.send_crypto,
                client_key: self.client_key,
            },
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
fn derive_key(info: &[u8], shared: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key).unwrap();
    key
}

/// Generate random keypair
#[must_use]
pub fn random_keypair() -> (SigningKey, VerifyingKey) {
    let mut bytes = [0u8; 32];
    let mut rng = OsRng;

    rng.fill_bytes(&mut bytes);
    let signing = SigningKey::from_bytes(&bytes);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use uuid::Uuid;

    /// Ensure basic `EncryptedStream` functionality.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crypto_socket() {
        const PORT: u16 = 12345;

        let (server_signing, server_verifying) = random_keypair();
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
        tokio::time::sleep(Duration::from_millis(10)).await; // Required by Linux
        assert!(!handle.is_finished());
        eprintln!("Server process created.");

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let mut link = EncryptedStream::<100>::connect(stream, &server_verifying, None)
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
        assert_eq!(link.send_crypto.count, link.interval());

        handle.abort();
    }

    /// Ensure basic `EncryptedStream` functionality with a client key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crypto_socket_client_key() {
        const PORT: u16 = 12344;

        let (client_signing, _client_verifying) = random_keypair();
        let (server_signing, server_verifying) = random_keypair();
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
        tokio::time::sleep(Duration::from_millis(10)).await; // Required by Linux
        assert!(!handle.is_finished());
        eprintln!("Server process created.");

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let mut link =
            EncryptedStream::<100>::connect(stream, &server_verifying, Some(&client_signing))
                .await
                .expect("Client Connect failed");
        println!("EncryptedStream: connect_with_key() created, sending data");

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
        assert_eq!(link.send_crypto.count, link.interval());
        handle.abort();
    }

    /// Split the `EncryptedStream` into separate read and write halves. Ensure that this works,
    /// and that both halves rekey correctly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crypto_socket_split() {
        const PORT: u16 = 12399;

        let (server_signing, server_verifying) = random_keypair();

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
        tokio::time::sleep(Duration::from_millis(10)).await; // Required by Linux
        assert!(!handle.is_finished());
        eprintln!("Server process created.");

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let link = EncryptedStream::<100>::connect(stream, &server_verifying, None)
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
        assert_eq!(write.crypto.count, write.interval());

        read_process.abort();
        handle.abort();
    }

    /// Split the `EncryptedStream` into separate read and write halves. Ensure that this works,
    /// and that both halves rekey correctly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crypto_socket_split_client_key() {
        const PORT: u16 = 12398;

        let (client_signing, _client_verifying) = random_keypair();
        let (server_signing, server_verifying) = random_keypair();

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
        tokio::time::sleep(Duration::from_millis(10)).await; // Required by Linux
        assert!(!handle.is_finished());
        eprintln!("Server process created.");

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let link =
            EncryptedStream::<100>::connect(stream, &server_verifying, Some(&client_signing))
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
        assert_eq!(write.crypto.count, write.interval());

        read_process.abort();
        handle.abort();
    }

    /// Ensure that `EncryptedStream` fails to connect if the server isn't using the correct key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_key() {
        const PORT: u16 = 12450;
        let (server_signing, _) = random_keypair();
        let (_, server_verifying) = random_keypair();

        let handle = tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut link = EncryptedStream::<100>::accept(stream, &server_signing)
                .await
                .expect("Server Accept failed");
            loop {
                let mut msg = link.recv().await.expect("Server Receive failed");
                msg.reverse();
                link.send(&msg).await.expect("Server Send failed");
            }
        });
        tokio::time::sleep(Duration::from_millis(10)).await; // Required by Linux
        assert!(!handle.is_finished());

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let link_result = EncryptedStream::<100>::connect(stream, &server_verifying, None).await;
        println!("EncryptedStream: connect() with wrong key: {link_result:?}");
        assert!(
            link_result
                .err()
                .unwrap()
                .to_string()
                .contains("Failed to verify signature: signature error")
        );

        handle.abort();
    }

    /// Make sure the `EncryptedStream` fails if one side rekeys when it's not supposed to.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incorrect_rekey() {
        const PORT: u16 = 12460;
        let (server_signing, server_verifying) = random_keypair();

        let handle = tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{PORT}"))
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut link = EncryptedStream::<100>::accept(stream, &server_signing)
                .await
                .expect("Server Accept failed");
            loop {
                // The first iteration is fine, but the second is after an unexpected rekeying operation,
                // resulting in an error. But we're not asserting it yet.
                let mut msg = link.recv().await.expect("Server Receive failed");
                msg.reverse();
                link.send(&msg).await.expect("Server Send failed");
            }
        });
        tokio::time::sleep(Duration::from_millis(10)).await; // Required by Linux
        assert!(!handle.is_finished());

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let mut link = EncryptedStream::<100>::connect(stream, &server_verifying, None)
            .await
            .unwrap();

        link.send(b"test").await.unwrap();
        assert_eq!(link.recv().await.unwrap(), b"tset");

        link.send_crypto.rekey().unwrap();
        let result = link.send(b"test").await;
        println!("EncryptedStream: send() with too early rekey: {result:?}");

        let response = link.recv().await;
        println!("EncryptedStream: recv() with too early rekey: {response:?}");
        assert!(response.is_err());

        handle.abort();
    }
}
