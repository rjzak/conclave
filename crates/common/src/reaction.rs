// SPDX-License-Identifier: Apache-2.0

//! Reactions: an emoji somebody put on a message or a post.
//!
//! A reaction is one emoji — see [`is_emoji`] for what that covers, skin tones,
//! flags and joined sequences among it — from one person on one thing, and the
//! same person cannot put the same emoji on twice: reacting again takes it
//! back. What travels is a tally per emoji, with the names of the people who
//! reacted, because a reaction is a public gesture: unlike a vote in a poll
//! (see [`crate::poll`]), who reacted is the interesting half.
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

/// Longest one emoji may be, in bytes.
///
/// The longest real sequences — a family of four, a kiss between two people
/// each with a skin tone, a subdivision flag such as 🏴󠁧󠁢󠁳󠁣󠁴󠁿 — come to about 35
/// bytes. This leaves room for those and none for a paragraph of joiners.
pub const MAX_EMOJI_LEN: usize = 48;

/// One emoji the picker offers.
#[derive(Clone, Copy, Debug)]
pub struct PaletteEmoji {
    /// The emoji, in the form [`normalize_emoji`] gives it
    pub emoji: &'static str,

    /// What it is for, shown on hover
    pub meaning: &'static str,

    /// Whether it is a person or a hand, and so takes a skin tone
    pub toned: bool,
}

/// Shorthand for the palette below.
const fn pick(emoji: &'static str, meaning: &'static str) -> PaletteEmoji {
    PaletteEmoji {
        emoji,
        meaning,
        toned: false,
    }
}

/// Shorthand for a palette entry that takes a skin tone.
const fn hand(emoji: &'static str, meaning: &'static str) -> PaletteEmoji {
    PaletteEmoji {
        emoji,
        meaning,
        toned: true,
    }
}

/// The emoji the picker offers, each with what it is for.
///
/// Not the emoji a reaction *may* be — [`is_emoji`] decides that, and accepts
/// far more — but the ones worth a button. The client ships a colour emoji
/// font that draws all of these, and `the_palette_renders_in_colour` in the
/// client holds this list to it.
///
/// The picker also takes a typed or pasted emoji, so this list is a shortcut
/// rather than the limit.
pub const REACTION_PALETTE: &[PaletteEmoji] = &[
    hand("👍", "Agree"),
    hand("👎", "Disagree"),
    pick("❤", "Love it"),
    pick("😂", "Funny"),
    pick("😮", "Surprised"),
    pick("😢", "Sorry to hear it"),
    pick("😡", "Not happy"),
    pick("🎉", "Celebrate"),
    hand("👏", "Well done"),
    hand("🙌", "Hooray"),
    hand("🙏", "Thanks"),
    pick("👀", "Looking at it"),
    pick("🤔", "Thinking about it"),
    pick("🔥", "On fire"),
    pick("🚀", "Ship it"),
    pick("✅", "Done"),
    pick("❌", "No"),
    pick("⚠", "Careful"),
    pick("❓", "Question"),
    pick("💯", "Absolutely"),
    hand("💪", "You've got this"),
    hand("👋", "Hello"),
    hand("🤝", "Deal"),
    pick("🤯", "Mind blown"),
    pick("😬", "Yikes"),
    pick("💩", "This stinks"),
    pick("🙃", "Well, then"),
    pick("🫡", "On it"),
    pick("🐛", "Bug"),
    pick("🛠", "Needs work"),
    pick("🕵", "Investigating"),
    pick("⏳", "Waiting"),
    pick("🚧", "Blocked"),
    pick("🔒", "Security"),
    pick("📌", "Pinned"),
    pick("💡", "Good idea"),
    pick("☕", "Coffee"),
    pick("🍕", "Lunch"),
    pick("🌈", "Lovely"),
    pick("⭐", "Star"),
    pick("🏆", "Winner"),
];

/// The skin tones a toned palette emoji can take, lightest first, each with
/// its name. Fitzpatrick types 1–2 share the first.
pub const SKIN_TONES: &[(char, &str)] = &[
    ('\u{1F3FB}', "Light"),
    ('\u{1F3FC}', "Medium-light"),
    ('\u{1F3FD}', "Medium"),
    ('\u{1F3FE}', "Medium-dark"),
    ('\u{1F3FF}', "Dark"),
];

impl PaletteEmoji {
    /// This emoji in the given skin tone, or as it is if it takes none or no
    /// tone was asked for.
    #[must_use]
    pub fn in_tone(&self, tone: Option<char>) -> String {
        match tone {
            Some(tone) if self.toned && is_skin_tone(tone) => format!("{}{tone}", self.emoji),
            _ => self.emoji.to_string(),
        }
    }
}

/// Zero width joiner: glues the parts of a sequence such as 👩‍💻 together.
const ZWJ: char = '\u{200D}';

/// Variation selector 16: asks for the emoji, rather than text, form of the
/// character before it.
const VS16: char = '\u{FE0F}';

/// Combining enclosing keycap, the box around 1️⃣.
const KEYCAP: char = '\u{20E3}';

/// Ends the tag run that spells out a subdivision flag such as 🏴󠁧󠁢󠁥󠁮󠁧󠁿.
const CANCEL_TAG: char = '\u{E007F}';

/// Whether `c` is a picture in its own right: what an emoji starts with.
///
/// Without a Unicode table to consult this leans on the blocks the emoji live
/// in, minus the characters that only ever modify one (skin tones) or pair up
/// (regional indicators, which are only a flag two at a time).
fn is_pictograph(c: char) -> bool {
    !is_skin_tone(c)
        && !is_regional_indicator(c)
        && matches!(u32::from(c),
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

/// One of the five Fitzpatrick skin-tone modifiers.
fn is_skin_tone(c: char) -> bool {
    matches!(u32::from(c), 0x1F3FB..=0x1F3FF)
}

/// One of the 26 regional indicator letters a flag is spelled with.
fn is_regional_indicator(c: char) -> bool {
    matches!(u32::from(c), 0x1F1E6..=0x1F1FF)
}

/// A tag character, spelling a subdivision code after 🏴.
fn is_tag(c: char) -> bool {
    matches!(u32::from(c), 0xE0020..=0xE007E)
}

/// What can wear a keycap: a digit, `#` or `*`.
fn is_keycap_base(c: char) -> bool {
    c.is_ascii_digit() || c == '#' || c == '*'
}

/// How many of `chars` the one emoji element at their start takes up, if they
/// start with one: a flag, a keycap, or a pictograph with whatever qualifies
/// it (an emoji-style selector, a skin tone, a subdivision tag run).
fn element_len(chars: &[char]) -> Option<usize> {
    match *chars {
        [a, b, ..] if is_regional_indicator(a) && is_regional_indicator(b) => Some(2),
        [base, VS16, KEYCAP, ..] if is_keycap_base(base) => Some(3),
        [base, KEYCAP, ..] if is_keycap_base(base) => Some(2),
        [base, ..] if is_pictograph(base) => {
            let mut len = 1;
            match chars.get(len) {
                Some(&VS16) => len += 1,
                Some(&tone) if is_skin_tone(tone) => len += 1,
                _ => {}
            }
            let tags = chars
                .get(len..)
                .unwrap_or_default()
                .iter()
                .take_while(|c| is_tag(**c))
                .count();
            if tags > 0 && chars.get(len + tags) == Some(&CANCEL_TAG) {
                len += tags + 1;
            }
            Some(len)
        }
        _ => None,
    }
}

/// How many bytes of `text` the one emoji at its start takes up, if it starts
/// with one: elements joined by zero width joiners, as far as they go.
fn emoji_len(text: &str) -> Option<usize> {
    // Nothing longer than an emoji may be is worth looking at, and the bound
    // keeps a pasted wall of text from being turned into a wall of chars.
    let chars: Vec<char> = text.chars().take(MAX_EMOJI_LEN).collect();
    let mut len = element_len(&chars)?;
    while chars.get(len) == Some(&ZWJ) {
        match chars.get(len + 1..).and_then(element_len) {
            Some(next) => len += 1 + next,
            None => break,
        }
    }
    Some(chars.iter().take(len).map(|c| c.len_utf8()).sum())
}

/// Whether `text` is exactly one emoji.
///
/// One emoji may be several Unicode scalars: a skin tone (👍🏽), a flag (🇳🇿), a
/// subdivision flag (🏴󠁧󠁢󠁷󠁬󠁳󠁿), a keycap (1️⃣) or a sequence glued together with
/// zero width joiners (👩🏽‍💻, 🏳️‍🌈). The shape is checked, not the dictionary:
/// a joined pair no font has a picture for still passes, and a client draws
/// it as the pieces it is made of.
///
/// Without a Unicode table to consult this leans on the blocks the emoji live
/// in. It is a filter against text arriving where an emoji belongs, not a
/// Unicode conformance check: it keeps out letters, digits, punctuation and
/// control characters, which is what it is for.
#[must_use]
pub fn is_emoji(text: &str) -> bool {
    text.len() <= MAX_EMOJI_LEN && emoji_len(text) == Some(text.len())
}

/// The one form of an emoji that is kept and compared.
///
/// A lone character followed by the emoji-style selector (❤️) is the same
/// reaction as the character alone (❤): which of the two arrives depends on
/// the keyboard it was typed on, and without this they would be counted as two
/// reactions that look the same. Sequences keep their selectors, which is
/// how fonts expect to find them.
fn canonical(emoji: &str) -> &str {
    match emoji.strip_suffix(VS16) {
        Some(base) if base.chars().count() == 1 => base,
        _ => emoji,
    }
}

/// The first emoji in `text`, if it holds one, in its normal form.
///
/// What a picker's free-entry field needs: somebody pasting an emoji tends to
/// bring a space or a stray character along with it, and the emoji is the part
/// they meant.
#[must_use]
pub fn first_emoji(text: &str) -> Option<String> {
    text.char_indices().find_map(|(i, _)| {
        let rest = text.get(i..)?;
        let len = emoji_len(rest)?;
        Some(canonical(rest.get(..len)?).to_string())
    })
}

/// Check that `emoji` is one emoji, and give it back in the one form that is
/// kept and compared, so ❤️ and ❤ are a single reaction.
///
/// Both sides call this: the client so the picker cannot offer nonsense, the
/// server because a client is not to be trusted about what it sends. A reaction
/// is rendered as-is wherever it lands, so this is what stops a "reaction"
/// being a word, a digit or a control character.
///
/// # Errors
///
/// Returns an error if `emoji` is not one emoji.
pub fn normalize_emoji(emoji: &str) -> Result<String> {
    ensure!(is_emoji(emoji), "A reaction has to be one emoji");
    Ok(canonical(emoji).to_string())
}

/// One emoji on one message or post, and who put it there.
///
/// The viewer this was rendered for is never in `who`: they are `mine`. Keeping
/// them out of the list is what lets them be named "you" without being named
/// twice, and means the names in `who` are always somebody else.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReactionTally {
    /// The emoji
    pub emoji: String,

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
    I: IntoIterator<Item = (String, String, bool)>,
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
        for entry in REACTION_PALETTE {
            let emoji = entry.emoji;
            let normal = normalize_emoji(emoji).unwrap_or_else(|e| panic!("{emoji} rejected: {e}"));
            assert_eq!(normal, emoji, "{emoji} is not in its normal form");
            assert!(
                !entry.meaning.is_empty(),
                "{emoji} has nothing to say it means"
            );
            for (tone, _) in SKIN_TONES {
                let toned = entry.in_tone(Some(*tone));
                assert!(is_emoji(&toned), "{toned} rejected");
            }
        }
        let mut seen = std::collections::HashSet::new();
        for entry in REACTION_PALETTE {
            assert!(seen.insert(entry.emoji), "{} is offered twice", entry.emoji);
        }
    }

    #[test]
    fn only_a_toned_emoji_takes_a_tone() {
        let thumbs = REACTION_PALETTE.iter().find(|e| e.emoji == "👍").unwrap();
        assert_eq!(thumbs.in_tone(Some('\u{1F3FD}')), "👍🏽");
        assert_eq!(thumbs.in_tone(None), "👍");
        let party = REACTION_PALETTE.iter().find(|e| e.emoji == "🎉").unwrap();
        assert_eq!(party.in_tone(Some('\u{1F3FD}')), "🎉");
        // Something that is not a tone is not glued on either.
        assert_eq!(thumbs.in_tone(Some('x')), "👍");
    }

    #[test]
    fn an_emoji_is_accepted_and_text_is_not() {
        for emoji in [
            "👍",
            "🎉",
            "❤",
            "❤️",
            "⌚",
            "⏳",
            "★",
            "☠",
            "©",
            // Skin tones, flags, keycaps and joined sequences.
            "👍🏽",
            "🇳🇿",
            "🇬🇧",
            "1️⃣",
            "#⃣",
            "👩‍💻",
            "👩🏽‍💻",
            "🏳️‍🌈",
            "👨‍👩‍👧‍👦",
            "🧑🏻‍❤️‍💋‍🧑🏿",
            // A subdivision flag: 🏴 and a tag run spelling "gbsct".
            "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
        ] {
            assert!(is_emoji(emoji), "{emoji} should be a reaction");
        }

        for text in [
            "",
            "a",
            "Z",
            "1",
            "#",
            " ",
            "\n",
            "<",
            "\u{0}",
            "lgtm",
            // The glue that only ever joins a sequence together, which is not
            // an emoji by itself, and the pieces that only modify or pair up.
            "\u{200d}",
            "\u{fe0f}",
            "\u{20e3}",
            "\u{1F3FD}",
            "🇳",
            "\u{E0067}",
            // One emoji is one: two side by side, or one with a tail, are not.
            "👍👍",
            "👍 ",
            " 👍",
            "👍a",
            "👍\u{200d}",
            "🇳🇿🇳",
        ] {
            assert!(!is_emoji(text), "{text:?} should not be a reaction");
            assert!(normalize_emoji(text).is_err());
        }

        // However many joiners somebody can fit in, a reaction is not an essay.
        let long = ["👍"; 20].join("\u{200d}");
        assert!(!is_emoji(&long));
    }

    #[test]
    fn the_same_emoji_is_one_reaction_however_it_was_typed() {
        assert_eq!(normalize_emoji("❤️").unwrap(), "❤");
        assert_eq!(normalize_emoji("❤").unwrap(), "❤");
        // A sequence keeps the selectors the font matches it by.
        assert_eq!(normalize_emoji("🏳️‍🌈").unwrap(), "🏳️‍🌈");
        assert_eq!(normalize_emoji("1️⃣").unwrap(), "1️⃣");
    }

    #[test]
    fn the_first_emoji_is_picked_out_of_what_was_typed() {
        let first = |text: &str| first_emoji(text);
        assert_eq!(first("👍").as_deref(), Some("👍"));
        assert_eq!(first(" 🎉 ").as_deref(), Some("🎉"));
        assert_eq!(first("nice 🎉!").as_deref(), Some("🎉"));
        // The first emoji, not the first character.
        assert_eq!(first("a★b♡").as_deref(), Some("★"));
        // The whole of a sequence, not its first scalar.
        assert_eq!(first(" 👩🏽‍💻 ").as_deref(), Some("👩🏽‍💻"));
        assert_eq!(first("go 🇳🇿").as_deref(), Some("🇳🇿"));
        assert_eq!(first("❤️").as_deref(), Some("❤"));
        // A digit is a digit unless it wears a keycap.
        assert_eq!(first("2 3️⃣").as_deref(), Some("3️⃣"));
        assert_eq!(first(""), None);
        assert_eq!(first("lgtm"), None);
        assert_eq!(first("42"), None);
    }

    #[test]
    fn a_tally_counts_people_and_names_them() {
        let row = |emoji: &str, who: &str, mine: bool| (emoji.to_string(), who.to_string(), mine);
        let tallies = tally_reactions(vec![
            row("👍", "Ada", false),
            row("🎉", "Ada", false),
            row("👍", "Grace", false),
            row("👍", "You", true),
            // A skin tone is a different reaction, not the same one recoloured.
            row("👍🏿", "Alan", false),
        ]);

        // One tally per emoji, in the order the emoji first appeared.
        assert_eq!(tallies.len(), 3);
        assert_eq!(tallies[0].emoji, "👍");
        assert_eq!(tallies[0].count(), 3);
        assert!(tallies[0].mine);
        // Counted three, named three, and the viewer named once as "you"
        // rather than twice under both names.
        assert_eq!(tallies[0].who, vec!["Ada".to_string(), "Grace".to_string()]);
        assert_eq!(tallies[0].who_line(), "👍 Ada, Grace and you");
        assert_eq!(tallies[1].emoji, "🎉");
        assert!(!tallies[1].mine);
        assert_eq!(tallies[1].who_line(), "🎉 Ada");
        assert_eq!(tallies[2].who_line(), "👍🏿 Alan");
    }

    #[test]
    fn who_reads_as_a_sentence() {
        let tally = |who: Vec<&str>, mine: bool| ReactionTally {
            emoji: "👍".to_string(),
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
