-- SPDX-License-Identifier: Apache-2.0

PRAGMA foreign_keys = ON;

CREATE TABLE SERVER_CONFIG (
    name text NOT NULL,
    description text NOT NULL,
    key text NOT NULL, -- hex: secret and public keys
    version text NOT NULL,
    trackers text
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

INSERT INTO USER VALUES(0, 'admin', NULL, CURRENT_TIMESTAMP, false);
INSERT INTO GRP VALUES(0, 'admin', 'Administrative users', NULL);
INSERT INTO USERGROUP VALUES(0, 0, CURRENT_TIMESTAMP);
