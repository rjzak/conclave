// SPDX-License-Identifier: Apache-2.0

//! Polls: a question, a handful of options, and a tally.
//!
//! A poll is deliberately independent of what it is attached to. Forums attach
//! one to a thread and measure its life in days; a chatroom poll, if that turns
//! out to be worth having, would attach to a room and measure its life in
//! minutes, reusing everything here but the attachment.
//!
//! # Who voted for what
//!
//! Nobody ever learns it. A [`Poll`] carries counts, never voters, so there is
//! no wire format in which the answer could travel, and the server records only
//! *that* a voter has voted — enough to turn away a second ballot — with the
//! tally kept as a per-option counter. Nothing, in the database or in flight,
//! joins a voter to an option, so the question cannot be asked of an operator
//! with the database open either.
//!
//! The cost of that is a vote is final: changing one would mean knowing what to
//! take back. It also means a voter is not reminded which option they chose
//! after a reconnect, only that they have voted.

use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Fewest options a poll may offer. A question with one answer is not a poll.
pub const MIN_POLL_OPTIONS: usize = 2;

/// Most options a poll may offer.
pub const MAX_POLL_OPTIONS: usize = 16;

/// Longest a poll question may be, in characters.
pub const MAX_POLL_QUESTION: usize = 200;

/// Longest a single option may be, in characters.
pub const MAX_POLL_OPTION: usize = 100;

/// How long a poll runs for, from creation to close.
///
/// Held as seconds so one type covers a forum poll counted in days and a
/// chatroom poll counted in minutes. Construct it with [`PollDuration::days`]
/// or [`PollDuration::minutes`], both of which reject a length outside
/// [`PollDuration::MIN_SECONDS`]..=[`PollDuration::MAX_SECONDS`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PollDuration(u32);

impl PollDuration {
    /// Shortest poll allowed: 30 minutes.
    pub const MIN_SECONDS: u32 = 60 * 30;

    /// Longest poll allowed: 90 days.
    pub const MAX_SECONDS: u32 = 90 * 24 * 60 * 60;

    /// A duration of `days` days.
    ///
    /// # Errors
    ///
    /// Returns an error if the result falls outside the allowed range.
    pub fn days(days: u16) -> Result<Self> {
        Self::seconds(u32::from(days) * 24 * 60 * 60)
    }

    /// A duration of `minutes` minutes.
    ///
    /// # Errors
    ///
    /// Returns an error if the result falls outside the allowed range.
    pub fn minutes(minutes: u32) -> Result<Self> {
        Self::seconds(minutes.saturating_mul(60))
    }

    /// A duration of `seconds` seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if `seconds` falls outside the allowed range.
    pub fn seconds(seconds: u32) -> Result<Self> {
        ensure!(
            seconds >= Self::MIN_SECONDS,
            "A poll must run for at least a minute"
        );
        ensure!(
            seconds <= Self::MAX_SECONDS,
            "A poll cannot run for longer than a year"
        );
        Ok(Self(seconds))
    }

    /// This duration in seconds.
    #[inline]
    #[must_use]
    pub const fn as_seconds(self) -> u32 {
        self.0
    }

    /// This duration in whole days, rounded down.
    #[inline]
    #[must_use]
    pub const fn whole_days(self) -> u32 {
        self.0 / (24 * 60 * 60)
    }

    /// When a poll created at `from` would close.
    #[must_use]
    pub fn closes_after(self, from: DateTime<Utc>) -> DateTime<Utc> {
        from + Duration::seconds(i64::from(self.0))
    }
}

/// A poll as its creator describes it, before the server gives it an identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewPoll {
    /// The question being asked
    pub question: String,

    /// The options to choose between, in the order they should be shown
    pub options: Vec<String>,

    /// Whether a voter may pick more than one option
    pub multiple_choices: bool,

    /// How long the poll runs for
    pub duration: PollDuration,

    /// Whether everyone may see the running tally before the poll closes. When
    /// this is false, only the poll's creator sees it until the close date; the
    /// rest see a count of nothing but their own participation.
    pub public_results: bool,
}

impl NewPoll {
    /// Check the poll is one the server will accept: a question, between
    /// [`MIN_POLL_OPTIONS`] and [`MAX_POLL_OPTIONS`] distinct non-empty
    /// options, and nothing over length.
    ///
    /// Both sides call this — the client to keep the Create button honest, the
    /// server because a client is not to be trusted about it.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first problem found.
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.question.trim().is_empty(), "A poll needs a question");
        ensure!(
            self.question.chars().count() <= MAX_POLL_QUESTION,
            "Poll question is longer than {MAX_POLL_QUESTION} characters"
        );

        let options: Vec<&str> = self
            .options
            .iter()
            .map(|o| o.trim())
            .filter(|o| !o.is_empty())
            .collect();
        ensure!(
            options.len() >= MIN_POLL_OPTIONS,
            "A poll needs at least {MIN_POLL_OPTIONS} options"
        );
        ensure!(
            options.len() <= MAX_POLL_OPTIONS,
            "A poll cannot have more than {MAX_POLL_OPTIONS} options"
        );
        ensure!(
            options.iter().all(|o| o.chars().count() <= MAX_POLL_OPTION),
            "A poll option is longer than {MAX_POLL_OPTION} characters"
        );

        for (i, option) in options.iter().enumerate() {
            ensure!(
                !options[..i].iter().any(|earlier| earlier == option),
                "Poll options must differ from each other: {option:?} appears twice"
            );
        }
        Ok(())
    }

    /// The options with surrounding whitespace trimmed and blanks dropped, as
    /// [`validate`](Self::validate) counted them and as the server stores them.
    #[must_use]
    pub fn trimmed_options(&self) -> Vec<String> {
        self.options
            .iter()
            .map(|o| o.trim())
            .filter(|o| !o.is_empty())
            .map(ToString::to_string)
            .collect()
    }
}

/// One option of a [`Poll`], with its tally when the viewer is allowed it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PollOption {
    /// Database id of the option, which is what a vote names
    pub id: u32,

    /// The option's text
    pub text: String,

    /// How many voters chose this option, or `None` when the viewer may not yet
    /// see the tally. The count never says *who*: see the module documentation.
    pub votes: Option<u32>,
}

/// A poll as one viewer sees it. What is withheld — the tally, before a poll
/// whose creator kept it private has closed — is absent rather than zeroed, so
/// a client cannot show a number the server did not mean to send.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Poll {
    /// Database id of the poll
    pub id: u32,

    /// The question being asked
    pub question: String,

    /// The options, in the order the creator gave them
    pub options: Vec<PollOption>,

    /// Whether a voter may pick more than one option
    pub multiple_choice: bool,

    /// When voting closes (UTC)
    pub closes_at: DateTime<Utc>,

    /// Whether the creator let everyone see the tally before the close date
    pub public_results: bool,

    /// How many people have voted, when the viewer may see the tally
    pub total_voters: Option<u32>,

    /// Whether *this* viewer has already voted. Which option they picked is not
    /// recorded anywhere, so it cannot be reported back to them.
    pub voted: bool,
}

impl Poll {
    /// Whether the poll is still taking votes as of `now`.
    #[must_use]
    pub fn is_open(&self, now: DateTime<Utc>) -> bool {
        now < self.closes_at
    }

    /// Whether this viewer was given the tally.
    #[must_use]
    pub fn results_visible(&self) -> bool {
        self.total_voters.is_some()
    }

    /// Total votes cast across every option, which exceeds the number of voters
    /// on a multiple-choice poll. `None` when the tally was withheld.
    #[must_use]
    pub fn total_votes(&self) -> Option<u32> {
        self.options.iter().map(|o| o.votes).sum()
    }

    /// Whether this viewer may still cast a ballot as of `now`.
    #[must_use]
    pub fn can_vote(&self, now: DateTime<Utc>) -> bool {
        !self.voted && self.is_open(now)
    }
}

/// A ballot: the options one voter picked, which must be exactly one unless the
/// poll is multiple-choice.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PollVote {
    /// The poll being voted in
    pub poll: u32,

    /// The chosen options, by [`PollOption::id`]
    pub options: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll(options: &[&str]) -> NewPoll {
        NewPoll {
            question: "Lunch?".to_string(),
            options: options.iter().map(ToString::to_string).collect(),
            multiple_choices: false,
            duration: PollDuration::days(3).unwrap(),
            public_results: true,
        }
    }

    #[test]
    fn durations_stay_within_range() {
        assert!(PollDuration::days(0).is_err());
        assert!(PollDuration::days(366).is_err());
        assert_eq!(PollDuration::days(7).unwrap().whole_days(), 7);
        assert_eq!(PollDuration::minutes(30).unwrap().as_seconds(), 1800);
        assert!(PollDuration::minutes(0).is_err());
    }

    #[test]
    fn a_poll_needs_a_question_and_two_distinct_options() {
        assert!(poll(&["Tacos", "Pizza"]).validate().is_ok());

        let mut blank = poll(&["Tacos", "Pizza"]);
        blank.question = "   ".to_string();
        assert!(blank.validate().is_err());

        assert!(poll(&["Tacos"]).validate().is_err());
        assert!(poll(&["Tacos", "  "]).validate().is_err());
        assert!(poll(&["Tacos", " Tacos "]).validate().is_err());

        let many: Vec<String> = (0..=MAX_POLL_OPTIONS).map(|i| format!("#{i}")).collect();
        let mut too_many = poll(&[]);
        too_many.options = many;
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn blank_options_are_dropped_not_counted() {
        let p = poll(&["Tacos", "", "  ", "Pizza"]);
        assert!(p.validate().is_ok());
        assert_eq!(p.trimmed_options(), vec!["Tacos", "Pizza"]);
    }

    #[test]
    fn a_withheld_tally_is_absent_rather_than_zero() {
        let withheld = Poll {
            id: 1,
            question: "Lunch?".to_string(),
            options: vec![
                PollOption {
                    id: 1,
                    text: "Tacos".to_string(),
                    votes: None,
                },
                PollOption {
                    id: 2,
                    text: "Pizza".to_string(),
                    votes: None,
                },
            ],
            multiple_choice: false,
            closes_at: Utc::now() + Duration::days(1),
            public_results: false,
            total_voters: None,
            voted: true,
        };
        assert!(!withheld.results_visible());
        assert_eq!(withheld.total_votes(), None);
        assert!(!withheld.can_vote(Utc::now()));
        assert!(withheld.is_open(Utc::now()));
    }
}
