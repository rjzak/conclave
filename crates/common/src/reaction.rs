// SPDX-License-Identifier: Apache-2.0

//! Reactions: an emoji somebody put on a message or a post.
//!
//! A reaction is one [`char`] — see [`is_emoji`] for what that does and does
//! not cover — from one person on one thing, and the same person cannot put the
//! same emoji on twice: reacting again takes it back. What
//! travels is a tally per emoji, with the names of the people who reacted,
//! because a reaction is a public gesture: unlike a vote in a poll (see
//! [`crate::poll`]), who reacted is the interesting half.
//!
//! Where the tally lives depends on what it is attached to. A forum post is
//! permanent, so its reactions are stored and arrive with the post. A chat
//! message is not: the server relays reactions to the room and each client adds
//! up what it saw, which is exactly as much as it saw of the conversation.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Most distinct emoji one message or post may collect. Past this the reaction
/// row is longer than what it reacts to; further emoji are turned away, while
/// the ones already there can still be joined.
pub const MAX_REACTIONS_PER_ITEM: usize = 24;

/// The emoji the picker offers, each with what it is for.
///
/// Not the emoji a reaction *may* be — [`is_emoji`] decides that, and accepts
/// far more — but the ones worth a button. They are chosen from what the fonts
/// the client ships with can actually draw, which rules out the obvious
/// candidates (👍, 🎉, a smiling face): the bundled emoji font covers much less
/// than its name suggests. `the_palette_renders_in_the_bundled_fonts` in the
/// client holds this list to what can be put on screen.
///
/// The picker also takes a typed or pasted emoji, so this list is a shortcut
/// rather than the limit.
pub const REACTION_PALETTE: &[(char, &str)] = &[
    ('★', "Good"),
    ('♡', "Love it"),
    ('✪', "Stands out"),
    ('✿', "Nice"),
    ('🏅', "Well done"),
    ('👁', "Seen"),
    ('☹', "Sorry to hear it"),
    ('☠', "Yikes"),
    ('⚑', "Flagged"),
    ('⚙', "Working on it"),
    ('🛠', "Needs work"),
    ('⛏', "Digging into it"),
    ('🕵', "Investigating"),
    ('⏱', "Waiting"),
    ('⏸', "On hold"),
    ('⛓', "Blocked"),
    ('🕸', "Gone stale"),
    ('🗑', "Bin it"),
    ('⚖', "Weighing it up"),
    ('⚔', "Disagree"),
    ('🛡', "Covered"),
    ('☘', "Good luck"),
    ('🕊', "Peace"),
    ('⚛', "Science"),
    ('☢', "Toxic"),
    ('🕶', "Cool"),
    ('📸', "Screenshot"),
    ('🖥', "On my machine"),
    ('🗺', "Mapped out"),
    ('🍽', "Lunch"),
];

/// Whether `c` is an emoji.
///
/// A reaction is one [`char`] — one Unicode scalar — which is what almost every
/// emoji is, 👍 😀 🎉 ❤ ✅ among them. What a single scalar cannot hold is a
/// *sequence*: a skin tone (👍🏽), a flag (🇬🇧), a joined family (👩‍👩‍👧‍👦) or a
/// keycap (1️⃣), each of which is two or more scalars glued together. None of
/// those can be drawn by the fonts the client ships with either, so nothing is
/// lost today that could have been shown; picking them up again would mean
/// carrying a string here and validating its shape.
///
/// Without a Unicode table to consult this leans on the blocks the emoji live
/// in. It is a filter against text arriving where an emoji belongs, not a
/// Unicode conformance check: it keeps out letters, digits, punctuation and
/// control characters, which is what it is for.
#[must_use]
pub fn is_emoji(c: char) -> bool {
    matches!(u32::from(c),
        0x1F000..=0x1FAFF   // pictographs, emoticons, transport, symbols, extended-A
        | 0x2190..=0x21FF   // arrows
        | 0x2300..=0x23FF   // technical (⌚, ⏰, ⏳)
        | 0x25A0..=0x25FF   // geometric shapes
        | 0x2600..=0x27BF   // miscellaneous symbols and dingbats
        | 0x2B00..=0x2BFF   // miscellaneous symbols and arrows
        | 0x00A9 | 0x00AE   // © ®
        | 0x203C | 0x2049   // ‼ ⁉
        | 0x2122 | 0x2139   // ™ ℹ
        | 0x3030 | 0x303D | 0x3297 | 0x3299
    )
}

/// The first emoji in `text`, if it holds one.
///
/// What a picker's free-entry field needs: somebody pasting an emoji tends to
/// bring a space or a stray character along with it, and the emoji is the part
/// they meant.
#[must_use]
pub fn first_emoji(text: &str) -> Option<char> {
    text.chars().find(|c| is_emoji(*c))
}

/// Check that `emoji` is an emoji, for the sake of the message when it is not.
///
/// Both sides call this: the client so the picker cannot offer nonsense, the
/// server because a client is not to be trusted about what it sends. A reaction
/// is rendered as-is wherever it lands, so this is what stops a "reaction"
/// being a letter, a digit or a control character.
///
/// # Errors
///
/// Returns an error if `emoji` is not an emoji.
pub fn validate_emoji(emoji: char) -> Result<()> {
    ensure!(is_emoji(emoji), "A reaction has to be an emoji");
    Ok(())
}

/// One emoji on one message or post, and who put it there.
///
/// The viewer this was rendered for is never in `who`: they are `mine`. Keeping
/// them out of the list is what lets them be named "you" without being named
/// twice, and means the names in `who` are always somebody else.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReactionTally {
    /// The emoji
    pub emoji: char,

    /// Display names of the *other* people who reacted, oldest first
    pub who: Vec<String>,

    /// Whether the viewer this was rendered for also reacted, so their own
    /// reaction can be drawn as pressed and clicking it takes it back
    pub mine: bool,
}

impl ReactionTally {
    /// How many people reacted with this emoji, the viewer included.
    #[must_use]
    pub fn count(&self) -> usize {
        self.who.len() + usize::from(self.mine)
    }

    /// The hover text naming the reactors, e.g. `"👍 Ada, Grace and you"`.
    #[must_use]
    pub fn who_line(&self) -> String {
        let mut names: Vec<&str> = self.who.iter().map(String::as_str).collect();
        if self.mine {
            // "you" reads last, however the other names happen to be ordered.
            names.push("you");
        }
        let joined = match names.as_slice() {
            [] => "nobody".to_string(),
            [one] => (*one).to_string(),
            [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        };
        format!("{} {joined}", self.emoji)
    }
}

/// Fold reaction rows — `(emoji, reactor's display name, whether it is the
/// viewer's own)`, in the order people reacted — into one tally per emoji, the
/// first emoji reacted with first.
///
/// The viewer's own reaction sets `mine` instead of adding their name to the
/// list, so they are counted once and named once. Both sides use this so both
/// produce the same shape: the server folds rows out of the database for a
/// forum post, the client folds the events it saw for a chat message.
#[must_use]
pub fn tally_reactions<I>(rows: I) -> Vec<ReactionTally>
where
    I: IntoIterator<Item = (char, String, bool)>,
{
    let mut tallies: Vec<ReactionTally> = Vec::new();
    for (emoji, who, mine) in rows {
        let index = tallies
            .iter()
            .position(|t| t.emoji == emoji)
            .unwrap_or_else(|| {
                tallies.push(ReactionTally {
                    emoji,
                    who: Vec::new(),
                    mine: false,
                });
                tallies.len() - 1
            });
        if let Some(tally) = tallies.get_mut(index) {
            if mine {
                tally.mine = true;
            } else {
                tally.who.push(who);
            }
        }
    }
    tallies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_palette_is_made_of_emoji() {
        for (emoji, meaning) in REACTION_PALETTE {
            validate_emoji(*emoji).unwrap_or_else(|e| panic!("{emoji} rejected: {e}"));
            assert!(!meaning.is_empty(), "{emoji} has nothing to say it means");
        }
    }

    #[test]
    fn an_emoji_is_accepted_and_text_is_not() {
        for emoji in ['👍', '🎉', '❤', '⌚', '⏳', '★', '☠'] {
            assert!(is_emoji(emoji), "{emoji} should be a reaction");
        }

        // Letters, digits, punctuation, whitespace, control characters — and
        // the glue that only ever joins an emoji sequence together, which is
        // not an emoji by itself.
        for c in [
            'a', 'Z', '1', '#', ' ', '\n', '<', '\u{0}', '\u{200d}', '\u{fe0f}', '\u{20e3}',
        ] {
            assert!(!is_emoji(c), "{c:?} should not be a reaction");
            assert!(validate_emoji(c).is_err());
        }
    }

    #[test]
    fn the_first_emoji_is_picked_out_of_what_was_typed() {
        assert_eq!(first_emoji("👍"), Some('👍'));
        assert_eq!(first_emoji(" 🎉 "), Some('🎉'));
        assert_eq!(first_emoji("nice 🎉!"), Some('🎉'));
        // The first emoji, not the first character.
        assert_eq!(first_emoji("a★b♡"), Some('★'));
        assert_eq!(first_emoji(""), None);
        assert_eq!(first_emoji("lgtm"), None);
    }

    #[test]
    fn a_tally_counts_people_and_names_them() {
        let row = |emoji: char, who: &str, mine: bool| (emoji, who.to_string(), mine);
        let tallies = tally_reactions(vec![
            row('👍', "Ada", false),
            row('🎉', "Ada", false),
            row('👍', "Grace", false),
            row('👍', "You", true),
        ]);

        // One tally per emoji, in the order the emoji first appeared.
        assert_eq!(tallies.len(), 2);
        assert_eq!(tallies[0].emoji, '👍');
        assert_eq!(tallies[0].count(), 3);
        assert!(tallies[0].mine);
        // Counted three, named three, and the viewer named once as "you"
        // rather than twice under both names.
        assert_eq!(tallies[0].who, vec!["Ada".to_string(), "Grace".to_string()]);
        assert_eq!(tallies[0].who_line(), "👍 Ada, Grace and you");
        assert_eq!(tallies[1].emoji, '🎉');
        assert!(!tallies[1].mine);
        assert_eq!(tallies[1].who_line(), "🎉 Ada");
    }

    #[test]
    fn who_reads_as_a_sentence() {
        let tally = |who: Vec<&str>, mine: bool| ReactionTally {
            emoji: '👍',
            who: who.into_iter().map(ToString::to_string).collect(),
            mine,
        };
        assert_eq!(tally(vec!["Ada"], false).who_line(), "👍 Ada");
        assert_eq!(tally(vec![], true).who_line(), "👍 you");
        assert_eq!(tally(vec![], true).count(), 1);
        assert_eq!(tally(vec!["Ada"], true).who_line(), "👍 Ada and you");
        assert_eq!(tally(vec!["Ada"], true).count(), 2);
        assert_eq!(
            tally(vec!["Ada", "Grace", "Alan"], false).who_line(),
            "👍 Ada, Grace and Alan"
        );
    }
}
