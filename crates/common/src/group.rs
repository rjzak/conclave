// SPDX-License-Identifier: Apache-2.0

//! How a group is named to the users a group restricts.

use serde::{Deserialize, Serialize};

/// A group named on something it gates — a chatroom or a forum topic — carrying
/// as much as a member needs to know who else is in the room: the group's name,
/// and its colour when it has one.
///
/// Sent in place of the group's database id, which would mean nothing to a
/// client that never sees the group table. A list of these is empty when
/// nothing is restricted, which is the ordinary case.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GroupTag {
    /// Group name, as shown to users
    pub name: String,

    /// The group's colour, if it has one. Members' names are tinted with it
    /// too, so the same colour identifies the same group wherever it appears.
    pub color: Option<[u8; 3]>,
}

/// A sentence naming who can read what is posted somewhere `groups` restricts:
/// everyone on the server when it is empty, otherwise the groups by name.
#[must_use]
pub fn audience(groups: &[GroupTag]) -> String {
    match groups {
        [] => "Visible to everyone on this server".to_string(),
        [one] => format!("Visible to {} members only", one.name),
        _ => {
            let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
            format!("Visible to members of {} only", names.join(", "))
        }
    }
}
