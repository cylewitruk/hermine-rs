//! Paper-driven Hermine threshold signatures with trusted-dealer key generation.
//!
//! This research implementation covers the paper's trusted-dealer algorithms.
//! It has no validated security profile, constant-time guarantee, external audit,
//! or official wire compatibility. See the repository's specification and
//! validation notes for source interpretations and remaining limitations.
//!
//! The lifecycle is [`dealer_keygen`], [`SecretShare::preprocess`],
//! [`SigningPackage::new`], [`SecretShare::sign`], [`SigningPackage::aggregate`],
//! and [`PublicKey::verify`]. Private preprocessing states are consumed by signing.
//! [`SigningPackage::identify_abort`] classifies missing and invalid responses
//! under an authenticated-transport assumption.
//! [`dealer_refresh`] produces a [`RefreshProposal`] and confidential tokens.
//! Recipients verify the proposal, then use [`SecretShare::apply_refresh`] to
//! verify and atomically apply their token while preserving lifetime nonce counts.

mod encoding;

pub mod linear;
pub mod parameters;
pub mod ring;
pub mod sampling;
pub mod sharing;
pub mod transcript;

#[cfg(feature = "experimental-dkg")]
pub mod dkg;

mod protocol;
pub use protocol::wire;
pub use protocol::{
    AbortReport, Coefficients, Commitment, Error, Identifier, KeySet, NonceState, PartialSignature,
    PublicKey, PublicKeyPackage, RefreshProposal, RefreshSet, RefreshToken, SecretShare, Signature,
    SigningPackage, VerifiedRefresh, dealer_keygen, dealer_refresh,
};
