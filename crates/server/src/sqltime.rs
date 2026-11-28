// SPDX-License-Identifier: Apache-2.0

//! Moving [`jiff::Timestamp`]s in and out of SQLite.
//!
//! `rusqlite`'s own `jiff` feature is built against jiff 0.2, so its
//! `FromSql`/`ToSql` impls don't apply to jiff 1.x types. This will be removed
//! once `async-sqlite` and `rusqlite` update to `jiff` 1.x.
//!
//! Reading has to accept everything already sitting in existing databases:
//!
//! * `"YYYY-MM-DD HH:MM:SS"` with no offset, written by SQLite's
//!   `CURRENT_TIMESTAMP` defaults (always UTC),
//! * `"YYYY-MM-DD HH:MM:SS.fff+00:00"`, written by the old chrono `ToSql`,
//! * RFC 3339 with a `T` separator and/or `Z`, and
//! * integer Unix seconds.
//!
//! Writing uses the chrono layout, so new rows sort and compare (as text)
//! consistently with older ones and with `CURRENT_TIMESTAMP`.

use async_sqlite::rusqlite::Result;
use async_sqlite::rusqlite::types::{
    FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef,
};
use jiff::Timestamp;
use jiff::civil::DateTime;
use jiff::tz::TimeZone;

/// A [`Timestamp`] that can be bound to, or read from, an SQLite column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DbTimestamp(pub Timestamp);

impl From<DbTimestamp> for Timestamp {
    #[inline]
    fn from(value: DbTimestamp) -> Self {
        value.0
    }
}

impl From<Timestamp> for DbTimestamp {
    #[inline]
    fn from(value: Timestamp) -> Self {
        Self(value)
    }
}

impl FromSql for DbTimestamp {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        if let ValueRef::Integer(secs) = value {
            return Timestamp::from_second(secs)
                .map(Self)
                .map_err(FromSqlError::other);
        }
        let text = value.as_str()?;
        // With an offset (chrono's output, or RFC 3339).
        if let Ok(ts) = text.parse::<Timestamp>() {
            return Ok(Self(ts));
        }
        // Without one: SQLite's CURRENT_TIMESTAMP, which is UTC.
        text.parse::<DateTime>()
            .and_then(|dt| dt.to_zoned_datetime(TimeZone::UTC))
            .map(|zdt| Self(zdt.timestamp()))
            .map_err(FromSqlError::other)
    }
}

impl ToSql for DbTimestamp {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(
            self.0
                .to_zoned_datetime(TimeZone::UTC)
                .strftime("%Y-%m-%d %H:%M:%S%.f%:z")
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::DbTimestamp;

    use async_sqlite::rusqlite::Connection;
    use jiff::Timestamp;

    fn read(conn: &Connection, sql: &str) -> Timestamp {
        conn.query_row(sql, [], |row| row.get::<_, DbTimestamp>(0))
            .unwrap()
            .0
    }

    #[test]
    fn reads_legacy_formats() {
        let conn = Connection::open_in_memory().unwrap();
        let expected: Timestamp = "2024-03-05T06:07:08Z".parse().unwrap();

        // CURRENT_TIMESTAMP style, no offset.
        assert_eq!(read(&conn, "SELECT '2024-03-05 06:07:08'"), expected);
        // chrono style.
        assert_eq!(read(&conn, "SELECT '2024-03-05 06:07:08+00:00'"), expected);
        // RFC 3339.
        assert_eq!(read(&conn, "SELECT '2024-03-05T06:07:08Z'"), expected);
        // Unix seconds.
        assert_eq!(
            read(&conn, &format!("SELECT {}", expected.as_second())),
            expected
        );
        // A real CURRENT_TIMESTAMP parses.
        let _ = read(&conn, "SELECT CURRENT_TIMESTAMP");
        // Garbage doesn't.
        assert!(
            conn.query_row("SELECT 'not a time'", [], |row| row
                .get::<_, DbTimestamp>(0))
                .is_err()
        );
    }

    #[test]
    fn round_trips_and_matches_chrono_layout() {
        let conn = Connection::open_in_memory().unwrap();
        let ts: Timestamp = "2024-03-05T06:07:08.123456789Z".parse().unwrap();

        let text: String = conn
            .query_row("SELECT ?1", [DbTimestamp(ts)], |row| row.get(0))
            .unwrap();
        assert_eq!(text, "2024-03-05 06:07:08.123456789+00:00");

        let back = conn
            .query_row("SELECT ?1", [DbTimestamp(ts)], |row| {
                row.get::<_, DbTimestamp>(0)
            })
            .unwrap();
        assert_eq!(back.0, ts);

        // Whole seconds carry no trailing fraction, like chrono.
        let whole: Timestamp = "2024-03-05T06:07:08Z".parse().unwrap();
        let text: String = conn
            .query_row("SELECT ?1", [DbTimestamp(whole)], |row| row.get(0))
            .unwrap();
        assert_eq!(text, "2024-03-05 06:07:08+00:00");
    }

    /// Rows from `CURRENT_TIMESTAMP`, from the old chrono code and from
    /// [`DbTimestamp`] all live in the same columns. They must read back as the
    /// same UTC instants and order the same way in SQL (`MAX`, `ORDER BY`
    /// compare the text), as they did under chrono.
    #[test]
    fn mixed_rows_read_and_sort_consistently() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER, at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL);
             INSERT INTO t VALUES (1, '2024-03-05 06:07:08');
             INSERT INTO t VALUES (2, '2024-03-05 06:07:08.5+00:00');",
        )
        .unwrap();
        let newer: Timestamp = "2024-03-05T06:07:09Z".parse().unwrap();
        conn.execute("INSERT INTO t VALUES (3, ?1)", [DbTimestamp(newer)])
            .unwrap();
        conn.execute("INSERT INTO t (id) VALUES (4)", []).unwrap();

        let mut stmt = conn.prepare("SELECT id, at FROM t ORDER BY at").unwrap();
        let rows: Vec<(u32, Timestamp)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get::<_, DbTimestamp>(1)?.0)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.iter().map(|r| r.0).collect::<Vec<_>>(), [1, 2, 3, 4]);
        assert!(rows.windows(2).all(|w| w[0].1 < w[1].1));
        assert_eq!(rows[0].1, "2024-03-05T06:07:08Z".parse().unwrap());
        assert_eq!(rows[1].1, "2024-03-05T06:07:08.5Z".parse().unwrap());
        assert_eq!(rows[2].1, newer);
        // CURRENT_TIMESTAMP is UTC; it must land within a minute of now.
        let drift = (Timestamp::now() - rows[3].1).abs();
        assert!(drift < jiff::SignedDuration::from_mins(1), "{drift:?}");

        let max = conn
            .query_row("SELECT MAX(at) FROM t WHERE id < 4", [], |row| {
                row.get::<_, DbTimestamp>(0)
            })
            .unwrap();
        assert_eq!(max.0, newer);
    }
}
