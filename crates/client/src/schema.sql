-- SPDX-License-Identifier: Apache-2.0

PRAGMA foreign_keys = ON;

CREATE TABLE CLIENT_CONFIG (
    default_display_name TEXT NOT NULL DEFAULT 'Unnamed',
    version text NOT NULL
);

CREATE UNIQUE INDEX server_one_row_index ON CLIENT_CONFIG (( true ));

CREATE TABLE trackers (
    id INTEGER PRIMARY KEY,
    server TEXT NOT NULL,
    port INTEGER NOT NULL
);

CREATE TABLE server_bookmarks (
    id INTEGER PRIMARY KEY,
    server_name TEXT NOT NULL,
    server_url TEXT NOT NULL,
    username TEXT,
    password TEXT,
    server_key TEXT, -- hex encoded public key
    added DEFAULT CURRENT_TIMESTAMP
);
