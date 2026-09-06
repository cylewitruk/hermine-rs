//! Hermine key packages, preprocessing, signing, and share refresh.

use std::{collections::BTreeMap, error, fmt, sync::Arc};

use crate::{
    linear::{self, Matrix, NttMatrix, Vector},
    parameters::{self, Parameters},
    ring::{self, Polynomial},
    sampling,
    sharing::{self, Index, Shares},
    transcript::{self, Monomial},
};

#[cfg(feature = "experimental-dkg")]
mod dkg;
mod keys;
#[cfg(feature = "experimental-mpc")]
mod mpc;
mod refresh;
mod signing;
mod support;
pub mod wire;

#[cfg(feature = "experimental-dkg")]
pub use dkg::ParticipantKeys;
pub use keys::dealer_keygen;
#[cfg(feature = "experimental-mpc")]
pub use mpc::assemble_mpc;
pub use refresh::dealer_refresh;

/// A 512-bit domain-separated identifier for keys, epochs, or signing sessions.
pub type Identifier = [u8; 64];

/// Row-major integer polynomial coefficients, validated at protocol boundaries.
pub type Coefficients = Vec<Vec<u64>>;

/// A malformed message, failed verification, or local execution failure.
#[derive(Debug)]
pub enum Error {
    /// Dealer generation was requested with a DKG or MPC profile.
    KeyOrigin,
    /// A DKG preprocessing pair exceeds its explicit checked norm bound.
    NonceBound,
    /// Parameter validation failed.
    Parameters(parameters::Error),
    /// Ring arithmetic failed.
    Ring(ring::Error),
    /// Matrix/vector arithmetic failed.
    Linear(linear::Error),
    /// Sharing or signer-set validation failed.
    Sharing(sharing::Error),
    /// Random-oracle extraction failed.
    Transcript(transcript::Error),
    /// Entropy generation or sampling failed, preserving its underlying cause.
    Random(Box<dyn error::Error + Send + Sync>),
    /// A protocol message has invalid dimensions or noncanonical coefficients.
    Malformed,
    /// A participant is outside the required signer set or occurs more than once.
    Participant,
    /// The key or public share package does not match local secret material.
    KeyMismatch,
    /// Material belongs to a different refresh epoch.
    EpochMismatch,
    /// A response belongs to a different signing session.
    SessionMismatch,
    /// The request does not contain the signer's exact preprocessing commitment.
    CommitmentMismatch,
    /// A configured lifetime operation limit was reached.
    Limit,
    /// A participant's response failed the partial verification norm check.
    InvalidShare {
        /// Authenticated sender of the invalid response.
        participant: u8,
    },
    /// The final signature failed verification.
    InvalidSignature,
    /// A confidential refresh token fails its individual norm check.
    InvalidRefresh {
        /// Intended owner of the invalid token.
        participant: u8,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyOrigin => f.write_str("key generation does not match parameter provenance"),
            Self::NonceBound => f.write_str("preprocessing pair exceeds the DKG nonce bound"),
            Self::Parameters(e) => e.fmt(f),
            Self::Ring(e) => e.fmt(f),
            Self::Linear(e) => e.fmt(f),
            Self::Sharing(e) => e.fmt(f),
            Self::Transcript(e) => e.fmt(f),
            Self::Random(e) => write!(f, "randomness or sampling failed: {e}"),
            Self::Malformed => f.write_str("malformed protocol message"),
            Self::Participant => f.write_str("unexpected or duplicate participant"),
            Self::KeyMismatch => f.write_str("key material does not match public package"),
            Self::EpochMismatch => f.write_str("material belongs to a different epoch"),
            Self::SessionMismatch => f.write_str("response belongs to a different signing session"),
            Self::CommitmentMismatch => {
                f.write_str("preprocessing commitment does not match local state")
            }
            Self::Limit => f.write_str("protocol usage limit reached"),
            Self::InvalidShare { participant } => {
                write!(f, "invalid response from participant {participant}")
            }
            Self::InvalidSignature => f.write_str("invalid signature"),
            Self::InvalidRefresh { participant } => {
                write!(f, "invalid refresh token for participant {participant}")
            }
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Parameters(e) => Some(e),
            Self::Ring(e) => Some(e),
            Self::Linear(e) => Some(e),
            Self::Sharing(e) => Some(e),
            Self::Transcript(e) => Some(e),
            Self::Random(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<parameters::Error> for Error {
    fn from(e: parameters::Error) -> Self {
        Self::Parameters(e)
    }
}
impl From<ring::Error> for Error {
    fn from(e: ring::Error) -> Self {
        Self::Ring(e)
    }
}
impl From<linear::Error> for Error {
    fn from(e: linear::Error) -> Self {
        Self::Linear(e)
    }
}
impl From<sharing::Error> for Error {
    fn from(e: sharing::Error) -> Self {
        Self::Sharing(e)
    }
}
impl From<transcript::Error> for Error {
    fn from(e: transcript::Error) -> Self {
        Self::Transcript(e)
    }
}
impl<E: error::Error + Send + Sync + 'static> From<sampling::Error<E>> for Error {
    fn from(e: sampling::Error<E>) -> Self {
        Self::Random(Box::new(e))
    }
}

/// The long-term verification key (A, t_top) with its explicit parameters.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Validated local parameter configuration.
    parameters: Parameters,
    /// Public sampled or transcript-derived matrix A.
    matrix: Matrix,
    /// Precomputed public matrix transform.
    transformed: NttMatrix,
    /// Integer-rounded full public key, without q_nu reduction.
    rounded_key: Coefficients,
    /// Identifier of all public verification inputs.
    id: Identifier,
}

/// Immutable per-epoch public information needed for partial verification.
#[derive(Clone, Debug)]
pub struct PublicKeyPackage {
    /// Long-term verification key, unchanged by refresh.
    key: Arc<PublicKey>,
    /// Refresh generation.
    epoch: u64,
    /// Per-party, per-path full-resolution public verification shares.
    verification_shares: Arc<Shares<Vector>>,
    /// Full-resolution reconstructed public key.
    full_key: Vector,
    /// Identifier binding the epoch and every partial public key.
    id: Identifier,
}

/// A signer's private shares and lifetime preprocessing counter.
///
/// This type is intentionally neither Clone nor serializable through Debug.
/// Polynomial storage is zeroized on drop. Backups or process rollback require
/// application-level durable nonce accounting before they can be supported safely.
pub struct SecretShare {
    /// One-based party identifier.
    participant: u8,
    /// Current refresh generation.
    epoch: u64,
    /// Current public package identity.
    package_id: Identifier,
    /// Secret vectors indexed by Figure 5 paths.
    shares: BTreeMap<Index, Vector>,
    /// Lifetime preprocessing reservations, including failed or discarded attempts.
    issued: u128,
}

impl fmt::Debug for SecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretShare")
            .field("participant", &self.participant)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Trusted-dealer output; distribute each private share only to its owner.
#[derive(Debug)]
pub struct KeySet {
    /// Public key and per-party verification material.
    pub public: PublicKeyPackage,
    /// One private share per participant in increasing identifier order.
    pub shares: Vec<SecretShare>,
}

/// A public preprocessing token independent of message and signer set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    /// One-based authenticated sender.
    pub participant: u8,
    /// Refresh generation under which the nonce was generated.
    pub epoch: u64,
    /// Public share package used to generate the nonce.
    pub package_id: Identifier,
    /// Unique lifetime reservation number for this participant.
    pub sequence: u128,
    /// Integer-rounded commitments, in repetition/row/coefficient order.
    pub values: Vec<Coefficients>,
}

/// Private one-shot preprocessing state; signing consumes it even on error.
///
/// ```rust,compile_fail
/// use hermine::{NonceState, PublicKeyPackage, SecretShare, SigningPackage};
/// fn reuse(s: &SecretShare, k: &PublicKeyPackage, p: &SigningPackage, n: NonceState) {
///     let _ = s.sign(k, p, n);
///     let _ = s.sign(k, p, n); // n was consumed by the first call.
/// }
/// ```
pub struct NonceState {
    /// Exact public token corresponding to these private vectors.
    commitment: Commitment,
    /// One private masking vector r per repetition.
    nonces: Vec<Vector>,
}

impl fmt::Debug for NonceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonceState")
            .field("participant", &self.commitment.participant)
            .field("sequence", &self.commitment.sequence)
            .finish_non_exhaustive()
    }
}

/// Validated common signing inputs and their deterministic challenge.
#[derive(Clone, Debug)]
pub struct SigningPackage {
    /// Public share package that all signers must use.
    package_id: Identifier,
    /// Refresh generation of the request.
    epoch: u64,
    /// Message bytes, shared when the request is cloned.
    message: Arc<[u8]>,
    /// Selected public tokens in increasing sender order.
    commitments: Vec<Commitment>,
    /// Selected share path for each participating party.
    indices: Vec<(u8, Index)>,
    /// Deterministic signed binding monomials.
    factors: Vec<Monomial>,
    /// Combined full-resolution commitment for each selected party.
    combined: Vec<Vector>,
    /// Rounded aggregate commitment modulo q_nu_w.
    rounded_commitment: Coefficients,
    /// Sparse signature challenge.
    challenge: Polynomial,
    /// Identifier binding all common session inputs.
    id: Identifier,
}

/// A message-dependent signature contribution sent by one participant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialSignature {
    /// One-based authenticated sender.
    pub participant: u8,
    /// Signing request to which this response belongs.
    pub session_id: Identifier,
    /// Response vector z_i.
    pub response: Vector,
}

/// A final Hermine/Raccoon-style signature, independent of the signer subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    /// Sparse challenge polynomial c.
    pub challenge: Polynomial,
    /// Aggregated response vector z.
    pub response: Vector,
    /// Canonical hint coefficients modulo q_nu_w.
    pub hint: Coefficients,
}

/// Partial-verification failures, assuming authenticated, reliably delivered messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortReport {
    /// Participants whose supplied responses failed verification.
    pub invalid: Vec<u8>,
    /// Selected participants from whom no response was supplied.
    pub missing: Vec<u8>,
}

/// Untrusted public material proposed for the next refresh epoch.
#[derive(Clone, Debug)]
pub struct RefreshProposal {
    /// Identity of the public package being refreshed.
    pub source_id: Identifier,
    /// Epoch of the public package being refreshed.
    pub source_epoch: u64,
    /// Proposed indexed verification shares for the next epoch.
    pub verification_shares: Shares<Vector>,
}

/// A confidential per-participant refresh token, transported only to its owner.
///
/// The public fields support transport integration. This type omits Clone and
/// redacts its vectors in Debug; contained polynomial storage zeroizes on drop.
pub struct RefreshToken {
    /// One-based intended recipient.
    pub participant: u8,
    /// Public package from which the update starts.
    pub source_id: Identifier,
    /// Public package to which the update is bound.
    pub target_id: Identifier,
    /// Indexed secret increments, one per expected share path.
    pub updates: BTreeMap<Index, Vector>,
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshToken")
            .field("participant", &self.participant)
            .finish_non_exhaustive()
    }
}

/// Dealer output: a common public proposal and N confidential update tokens.
#[derive(Debug)]
pub struct RefreshSet {
    /// Proposed next-epoch public verification material.
    pub public: RefreshProposal,
    /// A private token for each participant in identifier order.
    pub tokens: Vec<RefreshToken>,
}

/// A globally verified refresh that preserves the full long-term public key.
#[derive(Clone, Debug)]
pub struct VerifiedRefresh {
    /// Identity of the source epoch's public package.
    source_id: Identifier,
    /// Fully validated target public package.
    next: PublicKeyPackage,
}
