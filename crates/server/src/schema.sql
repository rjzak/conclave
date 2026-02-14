-- SPDX-License-Identifier: Apache-2.0

PRAGMA foreign_keys = ON;

CREATE TABLE SERVER_CONFIG (
    name text NOT NULL,
    description text NOT NULL,
    key text NOT NULL,
    version text NOT NULL,
    trackers text
);

CREATE UNIQUE INDEX server_one_row_index ON SERVER_CONFIG (( true ));
