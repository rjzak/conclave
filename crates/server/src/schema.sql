-- SPDX-License-Identifier: Apache-2.0

PRAGMA foreign_keys = ON;

CREATE TABLE SERVER_CONFIG (
    name text NOT NULL,
    description text NOT NULL,
    key text NOT NULL, -- hex: secret and public keys
    version text NOT NULL,
    advertised_domain text,
    allow_anonymous_clients boolean DEFAULT TRUE NOT NULL,
    chat_enabled boolean DEFAULT TRUE NOT NULL
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

INSERT INTO USER VALUES(0, 'admin', NULL, CURRENT_TIMESTAMP, false);
-- The admin group is red (16711680 = 0xFF0000); red is reserved for admins.
INSERT INTO GRP VALUES(0, 'admin', 'Administrative users', NULL, 16711680);
INSERT INTO USERGROUP VALUES(0, 0, CURRENT_TIMESTAMP);
INSERT INTO CHATROOM VALUES(0, 'Public');
