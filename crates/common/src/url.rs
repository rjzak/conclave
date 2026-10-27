// SPDX-License-Identifier: Apache-2.0

//! `conclave://` links: where a server is, written so it can be clicked.
//!
//! A link names a host and, optionally, a port: `conclave://example.com:9123`,
//! `conclave://localhost`, `conclave://[::1]:9123`. Without a port it means
//! [`crate::SERVER_DEFAULT_PORT`]. Anything after the address — a path, a query,
//! a fragment — is left for later versions to give a meaning to, and ignored
//! here, so a link written for a newer client still gets an older one as far as
//! the right server.
//!
//! A link may also carry a user name, and a password with it, in the usual
//! place: `conclave://ada:secret@example.com`. Either may be percent-encoded,
//! for a `:`, `@` or `/` in it. They only fill in the login window; opening a
//! link never connects by itself, so a link from somewhere untrustworthy is
//! never enough to log in as anybody.

use anyhow::{Context, Result, bail, ensure};

/// Longest a host name may be: the DNS limit.
const MAX_HOST_LEN: usize = 253;

/// A server address read out of a `conclave://` link, with any credentials
/// the link carried.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerUrl {
    /// The host, as it goes in front of `:port` when connecting: a name, an
    /// IPv4 address, or an IPv6 address in its brackets (`[::1]`)
    pub host: String,

    /// The port
    pub port: u16,

    /// The username the link carried, decoded
    pub username: Option<String>,

    /// The password the link carried, decoded; only ever with a user name
    pub password: Option<String>,
}

/// Prints the link without its credentials, so it is safe to log or show.
impl std::fmt::Display for ServerUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}:{}", crate::URL_PROTOCOL, self.host, self.port)
    }
}

/// Leaves the password out, so a stray `{:?}` cannot log it.
impl std::fmt::Debug for ServerUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerUrl")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "…"))
            .finish()
    }
}

/// Whether `host` is something that can be connected to: a DNS name or IPv4
/// address, or an IPv6 address in brackets.
fn valid_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

impl TryFrom<&str> for ServerUrl {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(url: &str) -> Result<Self, Self::Error> {
        parse_server_url(url)
    }
}

/// Split a link's address part into the credentials before its `@`, if any,
/// and the host and port after it.
#[inline]
fn split_credentials(authority: &str) -> Result<(Option<String>, Option<String>, &str)> {
    // The last `@` ends the credentials: one in a password may have been left
    // unencoded, but none can be in a host.
    let Some((userinfo, host_port)) = authority.rsplit_once('@') else {
        return Ok((None, None, authority));
    };
    let decode = |part: &str, what: &str| -> Result<Option<String>> {
        let decoded = percent_encoding::percent_decode_str(part)
            .decode_utf8()
            .with_context(|| format!("The link's {what} is not text"))?;
        Ok((!decoded.is_empty()).then(|| decoded.into_owned()))
    };
    // The first `:` ends the user name; a password may hold more of them.
    let (username, password) = match userinfo.split_once(':') {
        Some((username, password)) => (username, Some(password)),
        None => (userinfo, None),
    };
    let username = decode(username, "user name")?;
    let password = password
        .map(|p| decode(p, "password"))
        .transpose()?
        .flatten();
    ensure!(
        username.is_some() || password.is_none(),
        "A link with a password needs a user name too"
    );
    Ok((username, password, host_port))
}

/// Take any credentials out of a link, to log or show it: everything else is
/// left as it was, whether or not it makes sense.
#[must_use]
pub fn without_credentials(url: &str) -> std::borrow::Cow<'_, str> {
    let Some(scheme_end) = url.find("://").map(|i| i + 3) else {
        return url.into();
    };
    let authority_end = url[scheme_end..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| scheme_end + i);
    match url[scheme_end..authority_end].rfind('@') {
        Some(at) => format!("{}{}", &url[..scheme_end], &url[scheme_end + at + 1..]).into(),
        None => url.into(),
    }
}

/// Read the server address, and any credentials, out of a `conclave://` link.
///
/// # Errors
///
/// Returns an error if `url` is not a `conclave://` link, if its credentials
/// are not percent-encoded UTF-8 or are a password without a user name, or if
/// its host or port is not one that could be connected to. No error message
/// repeats the credentials.
pub fn parse_server_url(url: &str) -> Result<ServerUrl> {
    let url = url.trim();
    let scheme_len = crate::URL_PROTOCOL.len();
    ensure!(
        url.get(..scheme_len)
            .is_some_and(|s| s.eq_ignore_ascii_case(crate::URL_PROTOCOL)),
        "Not a Conclave link"
    );
    let rest = url.get(scheme_len..).unwrap_or_default();

    // The address runs up to whatever starts the part later versions may use.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (username, password, authority) = split_credentials(authority)?;

    // A colon after the closing bracket of an IPv6 address, or any colon in
    // anything else, starts the port.
    let port_colon = if authority.starts_with('[') {
        authority.find(']').and_then(|end| {
            authority
                .get(end + 1..)?
                .starts_with(':')
                .then_some(end + 1)
        })
    } else {
        authority.rfind(':')
    };
    let (host, port) = match port_colon {
        Some(colon) => {
            let port = authority.get(colon + 1..).unwrap_or_default();
            let Ok(port) = port.parse::<u16>() else {
                bail!("\"{port}\" is not a port");
            };
            ensure!(port != 0, "Port 0 is not a port");
            (authority.get(..colon).unwrap_or_default(), port)
        }
        None => (authority, crate::SERVER_DEFAULT_PORT),
    };
    ensure!(valid_host(host), "\"{host}\" is not a host to connect to");

    Ok(ServerUrl {
        host: host.to_ascii_lowercase(),
        port,
        username,
        password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SERVER_DEFAULT_PORT;

    fn parsed(url: &str) -> (String, u16, Option<String>, Option<String>) {
        let ServerUrl {
            host,
            port,
            username,
            password,
        } = parse_server_url(url).unwrap_or_else(|e| panic!("{url} rejected: {e}"));
        (host, port, username, password)
    }

    #[test]
    fn a_host_and_port_are_read() {
        assert_eq!(
            parsed("conclave://localhost:9123"),
            ("localhost".into(), 9123, None, None)
        );
        assert_eq!(
            parsed("conclave://127.0.0.1:4000"),
            ("127.0.0.1".into(), 4000, None, None)
        );
        assert_eq!(
            parsed("conclave://chat.example.com:1"),
            ("chat.example.com".into(), 1, None, None)
        );
        // An IPv6 address keeps its brackets, which connecting needs.
        assert_eq!(
            parsed("conclave://[::1]:9123"),
            ("[::1]".into(), 9123, None, None)
        );
        assert_eq!(
            parsed("conclave://[fe80::1]"),
            ("[fe80::1]".into(), SERVER_DEFAULT_PORT, None, None)
        );
    }

    #[test]
    fn no_port_means_the_default_one() {
        assert_eq!(
            parsed("conclave://localhost"),
            ("localhost".into(), SERVER_DEFAULT_PORT, None, None)
        );
    }

    #[test]
    fn what_a_browser_or_a_newer_client_adds_is_tolerated() {
        // Browsers and shells add a trailing slash, change the scheme's case,
        // and leave whitespace about.
        assert_eq!(
            parsed("conclave://localhost:9123/"),
            ("localhost".into(), 9123, None, None)
        );
        assert_eq!(
            parsed("CONCLAVE://LocalHost:9123"),
            ("localhost".into(), 9123, None, None)
        );
        assert_eq!(
            parsed("  conclave://localhost:9123\n"),
            ("localhost".into(), 9123, None, None)
        );
        // A path, query or fragment is for later versions; the server is still
        // the server.
        assert_eq!(
            parsed("conclave://localhost:9123/chat/general?x=1#y"),
            ("localhost".into(), 9123, None, None)
        );
    }

    #[test]
    fn what_cannot_be_connected_to_is_refused() {
        for url in [
            "",
            "localhost:9123",
            "https://localhost:9123",
            "conclave://",
            "conclave://:9123",
            "conclave://localhost:",
            "conclave://localhost:0",
            "conclave://localhost:65536",
            "conclave://localhost:http",
            "conclave://local host:9123",
            "conclave://-bad.example",
            "conclave://bad..example",
            "conclave://[::1",
            "conclave://[not-ipv6]:9123",
            "conclave://::1:9123",
        ] {
            assert!(parse_server_url(url).is_err(), "{url:?} should be refused");
        }
    }

    #[test]
    fn credentials_are_read() {
        assert_eq!(
            parsed("conclave://ada:secret@localhost:9123"),
            (
                "localhost".into(),
                9123,
                Some("ada".into()),
                Some("secret".into())
            )
        );
        // A user name alone, for the password to be typed.
        assert_eq!(
            parsed("conclave://ada@[::1]"),
            (
                "[::1]".into(),
                SERVER_DEFAULT_PORT,
                Some("ada".into()),
                None
            )
        );
        // Percent-encoded, and with an unencoded `:` and `@` in the password.
        assert_eq!(
            parsed("conclave://ad%40a:p%2Fa:s@s@localhost/x"),
            (
                "localhost".into(),
                SERVER_DEFAULT_PORT,
                Some("ad@a".into()),
                Some("p/a:s@s".into())
            )
        );
        // Empty is the same as missing.
        assert_eq!(
            parsed("conclave://ada:@localhost"),
            (
                "localhost".into(),
                SERVER_DEFAULT_PORT,
                Some("ada".into()),
                None
            )
        );
        assert_eq!(
            parsed("conclave://@localhost"),
            ("localhost".into(), SERVER_DEFAULT_PORT, None, None)
        );
    }

    #[test]
    fn bad_credentials_are_refused_without_repeating_them() {
        let err = parse_server_url("conclave://:secret@localhost").unwrap_err();
        assert!(!format!("{err:#}").contains("secret"), "{err:#}");
        let err = parse_server_url("conclave://ada:%FFsecret@localhost").unwrap_err();
        assert!(!format!("{err:#}").contains("secret"), "{err:#}");
    }

    #[test]
    fn credentials_stay_out_of_logs() {
        let url = parse_server_url("conclave://ada:secret@localhost").unwrap();
        assert_eq!(url.to_string(), "conclave://localhost:9123");
        assert!(!format!("{url:?}").contains("secret"));
        assert_eq!(
            without_credentials("conclave://ada:s@cret@localhost:1/a@b"),
            "conclave://localhost:1/a@b"
        );
        assert_eq!(
            without_credentials("conclave://localhost"),
            "conclave://localhost"
        );
        assert_eq!(without_credentials("ada:secret"), "ada:secret");
    }

    #[test]
    fn a_parsed_link_prints_back_as_one() {
        let url = parse_server_url("conclave://[::1]:9123/").unwrap();
        assert_eq!(url.to_string(), "conclave://[::1]:9123");
        assert_eq!(parse_server_url(&url.to_string()).unwrap(), url);
    }
}
