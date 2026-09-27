-- SPDX-License-Identifier: Apache-2.0

PRAGMA foreign_keys = ON;

CREATE TABLE SERVER_CONFIG (
    name text NOT NULL,
    description text NOT NULL,
    key text NOT NULL, -- hex: secret and public keys
    version text NOT NULL,
    advertised_domain text,
    allow_anonymous_clients boolean DEFAULT TRUE NOT NULL,
    chat_enabled boolean DEFAULT TRUE NOT NULL,
    forums_enabled boolean DEFAULT TRUE NOT NULL,
    max_upload_size integer, -- NULL means uploads are uncapped
    max_connections integer, -- NULL means unlimited concurrent connections
    banner blob -- optional banner image (PNG, exactly 512x128), or NULL
);

CREATE TABLE TRACKER (
    host text NOT NULL,
    port integer NOT NULL,
    key text NOT NULL,
    enabled boolean DEFAULT TRUE NOT NULL,
    PRIMARY KEY (host, port)
);

-- Only one record for the server configuration is permitted.
CREATE UNIQUE INDEX server_one_row_index ON SERVER_CONFIG (( true ));

CREATE TABLE USER (
    id INTEGER PRIMARY KEY,
    username text NOT NULL,
    password text,
    created DEFAULT CURRENT_TIMESTAMP NOT NULL,
    readonly boolean DEFAULT FALSE NOT NULL
);

CREATE TABLE GRP (
    id INTEGER PRIMARY KEY,
    name text NOT NULL UNIQUE,
    description text,
    parent INTEGER,
    color integer, -- 0xRRGGBB, or NULL for no colour
    FOREIGN KEY (parent) REFERENCES GRP(id)
);

CREATE TABLE USERGROUP (
    uid integer NOT NULL,
    gid integer NOT NULL,
    added DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (uid, gid),
    FOREIGN KEY (uid) REFERENCES USER(id),
    FOREIGN KEY (gid) REFERENCES GRP(id)
);

CREATE TABLE CHATROOM (
    id INTEGER PRIMARY KEY,
    name text NOT NULL UNIQUE
);

-- Restricts a chatroom to members of a group. No entries = public. Multiple rows = any of the groups.
CREATE TABLE CHATROOM_GROUP (
    room integer NOT NULL,
    gid integer NOT NULL,
    PRIMARY KEY (room, gid),
    FOREIGN KEY (room) REFERENCES CHATROOM(id),
    FOREIGN KEY (gid) REFERENCES GRP(id)
);

-- Forum topics (boards), created by administrators.
CREATE TABLE FORUM_TOPIC (
    id INTEGER PRIMARY KEY,
    name text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT ''
);

-- Restricts a topic to members of a group. No entries = public. Multiple rows = any of the groups.
CREATE TABLE FORUM_TOPIC_GROUP (
    topic integer NOT NULL,
    gid integer NOT NULL,
    PRIMARY KEY (topic, gid),
    FOREIGN KEY (topic) REFERENCES FORUM_TOPIC(id) ON DELETE CASCADE,
    FOREIGN KEY (gid) REFERENCES GRP(id)
);

-- A discussion thread within a topic.
CREATE TABLE FORUM_THREAD (
    id INTEGER PRIMARY KEY,
    topic integer NOT NULL,
    subject text NOT NULL,
    author_user integer, -- NULL for anonymous authors
    author_name text NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (topic) REFERENCES FORUM_TOPIC(id) ON DELETE CASCADE,
    FOREIGN KEY (author_user) REFERENCES USER(id)
);

-- A post within a thread. reply_to is NULL for the opening post, otherwise the
-- id of the post being replied to, forming a tree.
CREATE TABLE FORUM_POST (
    id INTEGER PRIMARY KEY,
    thread integer NOT NULL,
    reply_to integer, -- NULL for the thread's opening post
    author_user integer, -- NULL for anonymous authors
    author_name text NOT NULL,
    body text NOT NULL,
    is_markdown boolean DEFAULT FALSE NOT NULL,
    public_key blob, -- signer's ed25519 public key, if signed
    signature blob, -- signature over the body bytes, if signed
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (thread) REFERENCES FORUM_THREAD(id) ON DELETE CASCADE,
    FOREIGN KEY (reply_to) REFERENCES FORUM_POST(id),
    FOREIGN KEY (author_user) REFERENCES USER(id)
);

-- An emoji somebody put on a post. Who reacted is kept and shown.
CREATE TABLE FORUM_POST_REACTION (
    post integer NOT NULL,
    emoji text NOT NULL, -- exactly one character; text so the table reads plainly
    reactor blob NOT NULL, -- reactor's ed25519 identity key, which anonymous users have too
    reactor_name text NOT NULL, -- display name at the time, for the list of who reacted
    reactor_user integer, -- NULL for anonymous reactors
    reacted_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (post, emoji, reactor),
    FOREIGN KEY (post) REFERENCES FORUM_POST(id) ON DELETE CASCADE,
    FOREIGN KEY (reactor_user) REFERENCES USER(id)
);

-- An optional poll attached to a thread
CREATE TABLE FORUM_POLL (
    id INTEGER PRIMARY KEY,
    thread integer NOT NULL UNIQUE,
    question text NOT NULL,
    multiple_choice boolean DEFAULT FALSE NOT NULL,
    public_results boolean DEFAULT TRUE NOT NULL,
    author_user integer,
    author_key blob NOT NULL,
    closes_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (thread) REFERENCES FORUM_THREAD(id) ON DELETE CASCADE,
    FOREIGN KEY (author_user) REFERENCES USER(id)
);

-- One choice on a poll. The tally lives here, as a counter.
CREATE TABLE FORUM_POLL_OPTION (
    id INTEGER PRIMARY KEY,
    poll integer NOT NULL,
    position integer NOT NULL, -- display order
    text text NOT NULL,
    votes integer DEFAULT 0 NOT NULL,
    FOREIGN KEY (poll) REFERENCES FORUM_POLL(id) ON DELETE CASCADE
);

-- Records THAT someone voted, never what they voted for. Use user_id for authenticated
-- users, or key ID blob for anonymous users.
CREATE TABLE FORUM_POLL_VOTER (
    poll integer NOT NULL,
    voter_user integer, -- account id; NULL for an anonymous voter
    voter_key blob, -- ed25519 identity key; NULL for an authenticated voter
    voted_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CHECK ((voter_user IS NULL) <> (voter_key IS NULL)),
    FOREIGN KEY (poll) REFERENCES FORUM_POLL(id) ON DELETE CASCADE,
    FOREIGN KEY (voter_user) REFERENCES USER(id)
);

-- One vote each, enforced here.
CREATE UNIQUE INDEX poll_one_vote_per_account ON FORUM_POLL_VOTER (poll, voter_user)
    WHERE voter_user IS NOT NULL;
CREATE UNIQUE INDEX poll_one_vote_per_key ON FORUM_POLL_VOTER (poll, voter_key)
    WHERE voter_key IS NOT NULL;

INSERT INTO USER VALUES(0, 'admin', NULL, CURRENT_TIMESTAMP, false);
-- The admin group is red (16711680 = 0xFF0000); red is reserved for admins.
INSERT INTO GRP VALUES(0, 'admin', 'Administrative users', NULL, 16711680);
INSERT INTO USERGROUP VALUES(0, 0, CURRENT_TIMESTAMP);
INSERT INTO CHATROOM VALUES(0, 'Public');
