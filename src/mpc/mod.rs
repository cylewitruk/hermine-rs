//! Experimental four-party Maurer MPC in ideal private-channel/broadcast services.
//!
//! All four participants run key generation; any two subsequently sign. The
//! protocol targets one static malicious participant and permits abort. The local
//! transport is a testing service, not a network security implementation.

use std::{
    error, fmt,
    ops::{Deref, DerefMut},
};

mod engine;
mod gaussian;
mod keygen;
pub mod local;

pub use keygen::{Output, keygen};

/// Number of online participants; identifiers in this module are zero-based.
pub const PARTIES: usize = 4;
/// Maximum words accepted in any individual transport payload.
pub const MAX_WORDS: usize = 1 << 20;

/// A failed MPC invocation. Failure consumes the invocation; restart with a fresh session.
#[derive(Debug)]
pub enum Error {
    /// Unsupported configuration or mismatched invocation context.
    Configuration,
    /// Invalid length, residue, or replicated-share consistency.
    Malformed,
    /// A product check failed or a participant reported failure.
    Aborted,
    /// The ideal transport disconnected or exceeded its deadline.
    Transport,
    /// The private random source failed.
    Random,
    /// Hermine rejected algebra or key material.
    Hermine(crate::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => f.write_str("unsupported or inconsistent MPC configuration"),
            Self::Malformed => f.write_str("malformed MPC message or inconsistent sharing"),
            Self::Aborted => f.write_str("MPC invocation aborted"),
            Self::Transport => f.write_str("MPC transport disconnected or timed out"),
            Self::Random => f.write_str("MPC private randomness failed"),
            Self::Hermine(e) => e.fmt(f),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Hermine(error) => Some(error),
            _ => None,
        }
    }
}
impl From<crate::Error> for Error {
    fn from(error: crate::Error) -> Self {
        Self::Hermine(error)
    }
}

/// A confidential payload whose heap allocation is erased on drop.
#[derive(Clone)]
pub struct Payload(zeroize::Zeroizing<Vec<u64>>);
impl Payload {
    /// Takes ownership of words for confidential transport; Debug redacts them.
    pub fn new(words: Vec<u64>) -> Self {
        Self(zeroize::Zeroizing::new(words))
    }
}
impl Deref for Payload {
    type Target = Vec<u64>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for Payload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("words", &self.len())
            .finish_non_exhaustive()
    }
}

/// Messages delivered in one authenticated, synchronous round.
///
/// Each slot is indexed by authenticated sender. A broadcast must be delivered
/// identically to every honest recipient. Private slots contain only messages
/// addressed to this endpoint. The self slot is included.
#[derive(Debug)]
pub struct Incoming {
    /// Per-sender confidential messages.
    pub private: [Payload; PARTIES],
    /// Per-sender consistently broadcast messages.
    pub broadcast: [Payload; PARTIES],
}

/// Required ideal communication service for one independent participant.
///
/// Implementations must authenticate sender, recipient, fresh session identifier,
/// and round; preserve privacy against other participants; enforce consistent
/// broadcast; bound message sizes; and fail on omissions within a deadline.
/// Pairwise authenticated sends alone do not implement consistent broadcast.
/// Once an operation fails, discard all endpoints for that invocation.
pub trait Transport {
    /// Returns this endpoint's zero-based authenticated identity, in `0..4`.
    fn party(&self) -> usize;
    /// Sends one round and receives messages only for this endpoint.
    fn exchange(
        &mut self,
        round: u64,
        private: [Payload; PARTIES],
        broadcast: Payload,
    ) -> Result<Incoming, Error>;
    /// Terminates the invocation and wakes blocked peers, without publishing secrets.
    fn abort(&mut self);
}

/// Logical communication costs, excluding transport framing and cryptography.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Synchronous exchange calls made by this participant.
    pub rounds: u64,
    /// Words sent to remote recipients, counting each broadcast three times.
    pub sent_words: u64,
    /// Largest aggregate outgoing payload, including self-delivery, in words.
    pub peak_outgoing_words: usize,
    /// Packed Boolean or scalar modular multiplication gates evaluated.
    pub multiplication_gates: u64,
}

#[cfg(test)]
mod tests;
