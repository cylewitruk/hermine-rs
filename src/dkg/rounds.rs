//! Consumed rounds for the candidate DKG with abort and external broadcast.

use std::{collections::BTreeMap, error, fmt, ops::RangeInclusive, sync::Arc};

use rand_core::TryCryptoRng;

use super::{
    Contribution, ContributionError, PrivateContribution, SharingConfig, SharingSession,
    transcript::{append_polynomial, transcript},
};
use crate::{
    Identifier,
    linear::{self, Matrix, Vector},
    ring::{self, Ntt, Polynomial},
    sharing::{self, Index, Shares},
    transcript::{self as oracle, Domain, Transcript},
};

/// Upper bound on projection terms for generating all committee contributions.
const MAX_SESSION_TERMS: u128 = 1 << 29;
/// Upper bound on private coefficient storage across all simulated contributors.
const MAX_SESSION_COEFFICIENTS: u128 = 1 << 23;

/// A rejected round transition; errors do not constitute public blame evidence.
#[derive(Debug)]
pub enum RoundError {
    /// The underlying contribution configuration is unsupported.
    Configuration(ContributionError),
    /// Secret/error dimensions are invalid for the configured projection.
    Parameters,
    /// The committee exceeds the whole-session resource budget.
    Limit,
    /// A required authenticated sender is missing, unexpected, or mislabeled.
    Participants,
    /// Parties did not acknowledge the same complete contribution transcript.
    Binding,
    /// The broadcast delivery changed this party's own original message.
    OwnMessage,
    /// Public verification shares have invalid paths, dimensions, or rings.
    Shape,
    /// A named contributor's public or private checks failed.
    Contribution {
        /// Authenticated sender associated with the rejected message.
        participant: u8,
        /// Underlying rejection or entropy failure.
        error: ContributionError,
    },
    /// Vector or matrix construction failed.
    Linear(linear::Error),
    /// Polynomial arithmetic or NTT validation failed.
    Ring(ring::Error),
    /// Public verification shares failed VandCheck.
    Sharing(sharing::Error),
    /// Public matrix extraction failed.
    Transcript(oracle::Error),
}

impl fmt::Display for RoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => error.fmt(f),
            Self::Parameters => f.write_str("invalid DKG secret/error dimensions"),
            Self::Limit => f.write_str("DKG session exceeds resource budget"),
            Self::Participants => f.write_str("DKG authenticated participant set mismatch"),
            Self::Binding => f.write_str("DKG contribution transcript disagreement"),
            Self::OwnMessage => f.write_str("DKG delivery changed the local broadcast"),
            Self::Shape => f.write_str("malformed DKG verification share"),
            Self::Contribution { participant, error } => {
                write!(f, "DKG contribution from party {participant}: {error}")
            }
            Self::Linear(error) => error.fmt(f),
            Self::Ring(error) => error.fmt(f),
            Self::Sharing(error) => error.fmt(f),
            Self::Transcript(error) => error.fmt(f),
        }
    }
}

impl error::Error for RoundError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Contribution { error, .. } => Some(error),
            Self::Linear(error) => Some(error),
            Self::Ring(error) => Some(error),
            Self::Sharing(error) => Some(error),
            Self::Transcript(error) => Some(error),
            _ => None,
        }
    }
}

/// Explicit candidate DKG parameters, separate from dealer signing parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DkgConfig {
    /// Distribution, committee, and contribution acceptance limits.
    pub sharing: SharingConfig,
    /// Primitive 2n-th root for public matrix multiplication.
    pub root: u64,
    /// Number of secret components; remaining input components are errors.
    pub columns: usize,
}

/// Validated candidate DKG context; cloning this does not clone private state.
#[derive(Clone, Debug)]
pub struct DkgSession {
    /// Explicit source configuration.
    config: DkgConfig,
    /// Contribution context, including the DKG dimensions and caller session.
    sharing: SharingSession,
    /// Validated polynomial transform.
    ntt: Ntt,
}

/// Initial outgoing messages and the unique state awaiting contributions.
#[derive(Debug)]
pub struct RoundOne {
    /// Consumed when all authenticated contribution deliveries are available.
    pub state: ContributionRound,
    /// Public statement to deliver through consistent authenticated broadcast.
    pub broadcast: Contribution,
    /// Confidential payloads indexed by intended recipient, excluding this party.
    pub private: BTreeMap<u8, PrivateContribution>,
}

/// Private state before accepting the committee's complete contributions.
///
/// A transition consumes this state, including on error. A restart requires a
/// fresh common session identity and fresh entropy; states are not Clone.
///
/// ```rust,compile_fail
/// use std::collections::BTreeMap;
/// use hermine::dkg::ContributionRound;
/// fn reuse(state: ContributionRound) {
///     let _ = state.accept(BTreeMap::new(), BTreeMap::new());
///     let _ = state.accept(BTreeMap::new(), BTreeMap::new());
/// }
/// ```
#[derive(Debug)]
pub struct ContributionRound {
    /// Agreed setup and expected layouts.
    session: DkgSession,
    /// Local party's authenticated identity.
    participant: u8,
    /// Locally retained payload, unavailable for replacement by the transport.
    own: PrivateContribution,
}

/// Second-round outgoing broadcast and the state awaiting verification shares.
#[derive(Debug)]
pub struct RoundTwo {
    /// Consumed only after collecting all second-round broadcasts.
    pub state: VerificationRound,
    /// Common-transcript acknowledgment and this party's public images.
    pub broadcast: VerificationMessage,
}

/// Untrusted second-round statement requiring consistent authenticated broadcast.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationMessage {
    /// Authenticated one-based sender identity.
    pub participant: u8,
    /// Digest of the context and every accepted contribution statement in order.
    pub agreement: Identifier,
    /// This sender's indexed public images, `2(A s_i + e_i)`.
    pub shares: BTreeMap<Index, Vector>,
}

/// Private state after local contribution acceptance, before public agreement.
///
/// ```rust,compile_fail
/// use std::collections::BTreeMap;
/// use hermine::dkg::VerificationRound;
/// fn reuse(state: VerificationRound) {
///     let _ = state.finish(BTreeMap::new());
///     let _ = state.finish(BTreeMap::new());
/// }
/// ```
#[derive(Debug)]
pub struct VerificationRound {
    /// Agreed setup and expected layouts.
    session: DkgSession,
    /// Original local second-round broadcast, pinned against substitution.
    own: VerificationMessage,
    /// Matrix derived after all accepted contribution statements are fixed.
    matrix: Matrix,
    /// Only this participant's sum of confidential input shares.
    private: BTreeMap<Index, Vec<Polynomial>>,
}

/// Common candidate DKG result; it is not a Hermine signing key package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOutput {
    /// Explicit parameters, including private acceptance limits.
    config: DkgConfig,
    /// Full contribution context identity.
    context: Identifier,
    /// Digest of all accepted contribution statements.
    agreement: Identifier,
    /// Deterministically derived public matrix A.
    matrix: Matrix,
    /// Checked public verification shares from all parties.
    verification_shares: Shares<Vector>,
    /// VandCheck's common reconstructed public key.
    full_key: Vector,
    /// Identity binding the complete result.
    id: Identifier,
}

/// One participant's completed research result, with zeroizing private storage.
///
/// This type is not Clone. `into_signing` consumes it under a distinct DKG
/// correctness profile; distribution, leakage, and cryptographic composition
/// remain open research obligations.
///
/// ```rust,compile_fail
/// use hermine::dkg::DkgOutput;
/// fn duplicate(output: DkgOutput) { let _ = output.clone(); }
/// ```
#[derive(Debug)]
pub struct DkgOutput {
    /// Common checked public result.
    public: Arc<PublicOutput>,
    /// Owner of these confidential shares.
    participant: u8,
    /// Locally aggregated secret/error components, erased by Polynomial on drop.
    private: BTreeMap<Index, Vec<Polynomial>>,
}

impl DkgSession {
    /// Validates dimensions, transform, sharing restrictions, and resource limits.
    ///
    /// The application supplies a fresh common session identity and authenticates
    /// all senders. This constructor does not establish a secure parameter set.
    pub fn new(config: DkgConfig, session: &Identifier) -> Result<Self, RoundError> {
        let components = config.sharing.projection.components();
        if !(1..=64).contains(&config.columns)
            || components <= config.columns
            || components - config.columns > 64
        {
            return Err(RoundError::Parameters);
        }
        let c = config.sharing;
        let count = c.committee.share_counts().iter().sum::<usize>() as u128;
        let n = u128::from(c.committee.parties());
        let m = c.projection.columns() as u128;
        if n * count * m * 256 > MAX_SESSION_TERMS
            || n * count * (m + 256) > MAX_SESSION_COEFFICIENTS
        {
            return Err(RoundError::Limit);
        }
        let ntt = Ntt::new(c.projection.ring(), config.root).map_err(RoundError::Ring)?;
        let mut binding = transcript(b"round-context-v1");
        binding
            .append(b"session", session)
            .append_u64(b"root", config.root)
            .append_u64(b"columns", config.columns as u64);
        let sharing =
            SharingSession::new(c, &binding.digest()).map_err(RoundError::Configuration)?;
        Ok(Self {
            config,
            sharing,
            ntt,
        })
    }

    /// Returns the explicit DKG configuration.
    pub fn config(&self) -> DkgConfig {
        self.config
    }

    /// Borrows the complete session/configuration identity.
    pub fn id(&self) -> &Identifier {
        self.sharing.id()
    }

    /// Generates one contribution, retaining only this party's private payload.
    pub fn start<R: TryCryptoRng>(
        &self,
        participant: u8,
        rng: &mut R,
    ) -> Result<RoundOne, RoundError>
    where
        R::Error: error::Error + Send + Sync + 'static,
    {
        if !self.participants().contains(&participant) {
            return Err(RoundError::Participants);
        }
        let set = self
            .sharing
            .contribute(participant, rng)
            .map_err(|error| RoundError::Contribution { participant, error })?;
        let mut private: BTreeMap<_, _> = set
            .recipients
            .into_iter()
            .map(|payload| (payload.recipient, payload))
            .collect();
        let own = private
            .remove(&participant)
            .ok_or(RoundError::Participants)?;
        Ok(RoundOne {
            state: ContributionRound {
                session: self.clone(),
                participant,
                own,
            },
            broadcast: set.public,
            private,
        })
    }

    /// Returns the exact ordered sender set for this committee.
    fn participants(&self) -> RangeInclusive<u8> {
        1..=self.config.sharing.committee.parties()
    }
}

impl ContributionRound {
    /// Consumes all first-round deliveries and emits the local public images.
    ///
    /// Map keys must come from authenticated transport identities. `public`
    /// contains all N consistent broadcasts, including this party's original;
    /// `private` contains exactly the N-1 other contributors' local payloads.
    pub fn accept(
        self,
        public: BTreeMap<u8, Contribution>,
        mut private: BTreeMap<u8, PrivateContribution>,
    ) -> Result<RoundTwo, RoundError> {
        let Self {
            session,
            participant,
            own,
        } = self;
        if !public.keys().copied().eq(session.participants())
            || !private
                .keys()
                .copied()
                .eq(session.participants().filter(|p| *p != participant))
        {
            return Err(RoundError::Participants);
        }
        let original = own.statement;
        private.insert(participant, own);
        let mut binding = transcript(b"round-contributions-v1");
        binding.append(b"context", session.id());
        let mut aggregate: BTreeMap<Index, Vec<Polynomial>> = BTreeMap::new();
        for (sender, public) in public {
            let checked = session
                .sharing
                .check_contribution(sender, public)
                .map_err(|error| RoundError::Contribution {
                    participant: sender,
                    error,
                })?;
            if sender == participant && checked.id() != &original {
                return Err(RoundError::OwnMessage);
            }
            let payload = private.remove(&sender).ok_or(RoundError::Participants)?;
            checked
                .check_recipient(participant, &payload)
                .map_err(|error| RoundError::Contribution {
                    participant: sender,
                    error,
                })?;
            binding
                .append_u64(b"participant", u64::from(sender))
                .append(b"statement", checked.id());
            for (index, share) in payload.shares {
                if let Some(sum) = aggregate.get_mut(&index) {
                    for (sum, value) in sum.iter_mut().zip(share.input) {
                        *sum = sum.add(&value).map_err(RoundError::Ring)?;
                    }
                } else {
                    aggregate.insert(index, share.input);
                }
            }
        }
        let agreement = binding.digest();
        let c = session.config;
        let rows = c.sharing.projection.components() - c.columns;
        let mut oracle = Transcript::new(Domain::Matrix);
        oracle
            .append(b"kind", b"dkg-matrix-v1")
            .append(b"agreement", &agreement);
        let matrix = oracle
            .matrix(c.sharing.projection.ring(), rows, c.columns)
            .map_err(RoundError::Transcript)?;
        let transformed = matrix
            .transform(session.ntt.clone())
            .map_err(RoundError::Linear)?;
        let shares = aggregate
            .iter()
            .map(|(index, input)| {
                let secret =
                    Vector::new(input[..c.columns].to_vec()).map_err(RoundError::Linear)?;
                let error = Vector::new(input[c.columns..].to_vec()).map_err(RoundError::Linear)?;
                let image = transformed
                    .multiply(&secret)
                    .and_then(|value| value.add(&error))
                    .map_err(RoundError::Linear)?
                    .scale(2);
                Ok((index.clone(), image))
            })
            .collect::<Result<_, RoundError>>()?;
        let broadcast = VerificationMessage {
            participant,
            agreement,
            shares,
        };
        Ok(RoundTwo {
            state: VerificationRound {
                session,
                own: broadcast.clone(),
                matrix,
                private: aggregate,
            },
            broadcast,
        })
    }
}

impl VerificationRound {
    /// Consumes all N consistent broadcasts and returns the local research result.
    ///
    /// No output is returned unless every acknowledgment agrees and every public
    /// reconstruction is consistent. A missing message requires session abort.
    pub fn finish(
        self,
        messages: BTreeMap<u8, VerificationMessage>,
    ) -> Result<DkgOutput, RoundError> {
        let Self {
            session,
            own,
            matrix,
            private,
        } = self;
        if !messages.keys().copied().eq(session.participants()) {
            return Err(RoundError::Participants);
        }
        let c = session.config.sharing;
        let layout = c.committee.layout();
        let rows = c.projection.components() - session.config.columns;
        let mut verification_shares = Vec::with_capacity(messages.len());
        for (sender, message) in messages {
            if sender != message.participant {
                return Err(RoundError::Participants);
            }
            if message.agreement != own.agreement {
                return Err(RoundError::Binding);
            }
            if sender == own.participant && message != own {
                return Err(RoundError::OwnMessage);
            }
            if !message
                .shares
                .keys()
                .eq(layout[usize::from(sender - 1)].keys())
                || message
                    .shares
                    .values()
                    .any(|value| value.ring() != c.projection.ring() || value.dimension() != rows)
            {
                return Err(RoundError::Shape);
            }
            verification_shares.push(message.shares);
        }
        // Every dimension and ring is checked above before the infallible callback.
        let full_key = c
            .committee
            .check(&verification_shares, |a, b| {
                a.add(b).expect("prevalidated DKG public vector shapes")
            })
            .map_err(RoundError::Sharing)?;
        let mut public = PublicOutput {
            config: session.config,
            context: *session.id(),
            agreement: own.agreement,
            matrix,
            verification_shares,
            full_key,
            id: [0; 64],
        };
        public.id = output_id(&public);
        Ok(DkgOutput {
            public: Arc::new(public),
            participant: own.participant,
            private,
        })
    }
}

impl PublicOutput {
    /// Returns the candidate DKG configuration.
    pub fn config(&self) -> DkgConfig {
        self.config
    }
    /// Borrows the full contribution context identity.
    pub fn context(&self) -> &Identifier {
        &self.context
    }
    /// Borrows the acknowledgment binding all accepted contributions.
    pub fn agreement(&self) -> &Identifier {
        &self.agreement
    }
    /// Borrows the public matrix derived from the accepted transcript.
    pub fn matrix(&self) -> &Matrix {
        &self.matrix
    }
    /// Borrows the complete checked public verification sharing.
    pub fn verification_shares(&self) -> &Shares<Vector> {
        &self.verification_shares
    }
    /// Borrows the unrounded public key reconstructed by VandCheck.
    pub fn full_key(&self) -> &Vector {
        &self.full_key
    }
    /// Borrows the identity of this complete public result.
    pub fn id(&self) -> &Identifier {
        &self.id
    }
}

impl DkgOutput {
    /// Borrows the agreed public research result.
    pub fn public(&self) -> &PublicOutput {
        &self.public
    }
    /// Returns this output's one-based owner identity.
    pub fn participant(&self) -> u8 {
        self.participant
    }
    /// Borrows this party's confidential joint secret/error shares.
    ///
    /// The first `config.columns` components are secrets; the remainder are
    /// errors. This research accessor does not permit unchecked key import.
    pub fn shares(&self) -> &BTreeMap<Index, Vec<Polynomial>> {
        &self.private
    }
}

/// Binds the complete public output, including every indexed verification share.
fn output_id(public: &PublicOutput) -> Identifier {
    let mut binding = transcript(b"round-output-v1");
    binding
        .append(b"context", &public.context)
        .append(b"agreement", &public.agreement)
        .append_u64(b"rows", public.matrix.row_count() as u64)
        .append_u64(b"columns", public.matrix.column_count() as u64);
    for row in public.matrix.rows() {
        for polynomial in row.entries() {
            append_polynomial(&mut binding, b"matrix", polynomial);
        }
    }
    for (i, party) in public.verification_shares.iter().enumerate() {
        binding
            .append_u64(b"participant", i as u64 + 1)
            .append_u64(b"shares", party.len() as u64);
        for (index, vector) in party {
            binding.append(b"path", index.to_string().as_bytes());
            for polynomial in vector.entries() {
                append_polynomial(&mut binding, b"verification", polynomial);
            }
        }
    }
    for polynomial in public.full_key.entries() {
        append_polynomial(&mut binding, b"full-key", polynomial);
    }
    binding.digest()
}
