//! Experimental candidate Hermine distributed key generation with abort.
//!
//! Requires the `experimental-dkg` feature. The consumed rounds return research
//! outputs with an explicit experimental signing bridge. A masked projection is not, by itself,
//! a proof of shortness or knowledge. See `docs/DKG.md` for the construction,
//! source analysis, and open security obligations. No security guarantees or
//! production-use recommendations are made.

mod contribution;
mod rounds;
mod submersion;
mod transcript;

pub mod wire;

pub use crate::protocol::ParticipantKeys;
pub use contribution::{
    CheckedContribution, Contribution, ContributionError, ContributionSet, Masking,
    PrivateContribution, PrivateShare, SharingConfig, SharingSession,
};
pub use rounds::{
    ContributionRound, DkgConfig, DkgOutput, DkgSession, PublicOutput, RoundError, RoundOne,
    RoundTwo, VerificationMessage, VerificationRound,
};
pub use submersion::{Error, Projection, ProjectionParameters};
