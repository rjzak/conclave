// SPDX-License-Identifier: Apache-2.0

//! Threaded discussion (forum) data types shared between client and server.
//!
//! Forums are organised as topics → threads → posts. Topics are created by
//! administrators and gated by group membership, like chatrooms. A thread has a
//! subject and a tree of posts: the opening post has no parent, and every reply
//! names the post it replies to. Posts may optionally be signed by the author's
//! ed25519 identity key so other users can verify authorship.

use crate::net::{SigningKey, VerifyingKey};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

/// A forum topic (board) the user is allowed to see.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForumTopic {
    /// Database id of the topic
    pub id: u32,

    /// Topic name
    pub name: String,

    /// Longer description of the topic
    pub description: String,
}

/// Summary of a discussion thread within a topic.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForumThreadInfo {
    /// Database id of the thread
    pub id: u32,

    /// Topic this thread belongs to
    pub topic: u32,

    /// Thread subject
    pub subject: String,

    /// Display name of the thread's author
    pub author_name: String,

    /// When the thread was created (UTC)
    pub created_at: DateTime<Utc>,

    /// When the most recent post in the thread was made (UTC)
    pub last_activity: DateTime<Utc>,

    /// Number of replies (posts excluding the opening post)
    pub reply_count: u32,
}

/// An ed25519 signature over a post body, plus the signer's public key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForumSignature {
    /// Signer's ed25519 public key (compressed, 32 bytes)
    pub public_key: [u8; 32],

    /// Signature over the post body's UTF-8 bytes (64 bytes)
    pub signature: Vec<u8>,
}

impl ForumSignature {
    /// Sign a post body with the author's identity key.
    #[must_use]
    pub fn sign(signing_key: &SigningKey, body: &str) -> Self {
        let signature = signing_key.sign(body.as_bytes());
        Self {
            public_key: signing_key.verifying_key().to_bytes(),
            signature: signature.to_bytes().to_vec(),
        }
    }

    /// Verify this signature against a post body. Returns `false` if the public
    /// key or signature bytes are malformed, or if verification fails.
    #[must_use]
    pub fn verify(&self, body: &str) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(&self.public_key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        verifying_key.verify(body.as_bytes(), &signature).is_ok()
    }
}

/// A single post within a thread. `reply_to` is `None` for the thread's opening
/// post and otherwise names the post being replied to, forming a tree.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForumPost {
    /// Database id of the post
    pub id: u32,

    /// Thread this post belongs to
    pub thread: u32,

    /// Parent post id, or `None` for the thread's opening post
    pub reply_to: Option<u32>,

    /// Author's display name
    pub author_name: String,

    /// Author's user id, if they were authenticated
    pub author_user: Option<u32>,

    /// Post body (plain text, or markdown when `markdown` is set)
    pub body: String,

    /// Whether the body should be rendered as markdown
    pub markdown: bool,

    /// When the post was made (UTC)
    pub created_at: DateTime<Utc>,

    /// The author's signature over the body, if they signed it
    pub signature: Option<ForumSignature>,
}

/// A request to start a new thread within a topic.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewForumThread {
    /// Topic to post in
    pub topic: u32,

    /// Thread subject
    pub subject: String,

    /// Opening post body
    pub body: String,

    /// Whether the body is markdown
    pub markdown: bool,

    /// Optional signature over the body
    pub signature: Option<ForumSignature>,
}

/// A request to reply within a thread.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewForumPost {
    /// Thread to post in
    pub thread: u32,

    /// Parent post being replied to, or `None` to reply at the thread root
    pub reply_to: Option<u32>,

    /// Post body
    pub body: String,

    /// Whether the body is markdown
    pub markdown: bool,

    /// Optional signature over the body
    pub signature: Option<ForumSignature>,
}
