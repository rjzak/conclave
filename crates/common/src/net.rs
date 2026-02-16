// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};

/// Encrypted socket
pub struct EncryptedStream {
    stream: TcpStream,
    cipher: ChaCha20Poly1305,
    send_nonce: u64,
    recv_nonce: u64,
}

impl EncryptedStream {
    /// Protocol version
    const VERSION: u8 = 1;

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
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            send_nonce: 0,
            recv_nonce: 0,
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
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            send_nonce: 0,
            recv_nonce: 0,
        })
    }

    /// Send data over the encrypted socket
    ///
    /// # Errors
    ///
    /// Networking errors may result
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.send_nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Ciphertext length = plaintext length + 16-byte Poly1305 tag
        let len = u32::try_from(data.len() + 16)?;

        // Prepare AAD = version || len (big endian)
        let mut aad = [0u8; 5];
        aad[0] = Self::VERSION;
        aad[1..].copy_from_slice(&len.to_be_bytes());

        // Encrypt with AAD = version || length
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

        // Write version + length + ciphertext
        self.stream.write_u8(Self::VERSION).await?;
        self.stream.write_u32(len).await?;
        self.stream.write_all(&encrypted).await?;

        self.send_nonce += 1;

        Ok(())
    }

    /// Receive data over the encrypted socket
    ///
    /// # Errors
    ///
    /// Networking errors may result
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let version = self.stream.read_u8().await?;
        if version != Self::VERSION {
            return Err(anyhow!("Unsupported protocol version: {version}"));
        }

        let len = self.stream.read_u32().await?;
        let mut buf = vec![0u8; len as usize]; // TODO: consider buffer reuse
        self.stream.read_exact(&mut buf).await?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.recv_nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AAD = version || len
        let mut aad = [0u8; 5];
        aad[0] = version;
        aad[1..].copy_from_slice(&len.to_be_bytes());

        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: buf.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("Decryption failed: {e}"))?;

        self.recv_nonce += 1;

        Ok(plaintext)
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
            let mut link = EncryptedStream::accept(stream, &server_signing)
                .await
                .unwrap();
            println!("EncryptedStream: accept() created, waiting for data");
            let msg = link.recv().await.unwrap();
            assert_eq!(msg, b"Hello server");
            println!("Received: {msg:?}");

            link.send(b"Hello client").await.unwrap();
        });
        assert!(!handle.is_finished());
        eprintln!("Server process created.");

        let stream = TcpStream::connect(format!("127.0.0.1:{PORT}"))
            .await
            .unwrap();
        let mut link = EncryptedStream::connect(stream, &server_verifying)
            .await
            .unwrap();
        println!("EncryptedStream: connect() created, sending data");
        link.send(b"Hello server").await.unwrap();
        let msg = link.recv().await.unwrap();
        println!("Received: {msg:?}");
        assert_eq!(msg, b"Hello client");

        handle.abort();
    }
}
