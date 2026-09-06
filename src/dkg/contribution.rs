//! Candidate verifiable short sharing with salted recipient commitments.

use std::{collections::BTreeMap, error, fmt, sync::Arc};

use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use super::{
    Error as ProjectionError, Projection, ProjectionParameters,
    transcript::{append_polynomial, transcript},
};
use crate::{
    Identifier,
    ring::{self, Polynomial},
    sampling::{self, Gaussian},
    sharing::{self, Index, Shares, Vandermonde},
};

/// Maximum scalar multiply/add terms when projecting a whole contribution.
const MAX_PROJECTION_TERMS: usize = 1 << 28;
/// Maximum input-plus-mask scalar coefficients across all recipient payloads.
const MAX_PRIVATE_COEFFICIENTS: usize = 1 << 22;

/// An invalid candidate contribution or a failed sampling operation.
#[derive(Debug)]
pub enum ContributionError {
    /// Committee, distribution, or private coefficient limit is unsupported.
    Parameters,
    /// Projecting the configured sharing would exceed the work limit.
    Limit,
    /// Sender or recipient is outside the configured committee or mismatched.
    Participant,
    /// A message belongs to another sharing context or statement.
    Binding,
    /// Private payload dimensions, ring, or index layout is malformed.
    Shape,
    /// A committed private input exceeds the configured coefficient limit.
    PrivateBound,
    /// The reconstructed projected response exceeds its configured bound.
    ResponseBound,
    /// A recipient payload does not match its salted commitment.
    Commitment,
    /// A local projected share differs from the public statement.
    Equation,
    /// Underlying projection validation failed.
    Projection(ProjectionError),
    /// Underlying sharing validation failed.
    Sharing(sharing::Error),
    /// Underlying polynomial arithmetic failed.
    Ring(ring::Error),
    /// Sampling or the caller's entropy source failed.
    Sampling(Box<dyn error::Error + Send + Sync>),
}

impl fmt::Display for ContributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parameters => f.write_str("invalid contribution parameters"),
            Self::Limit => f.write_str("contribution exceeds projection work limit"),
            Self::Participant => f.write_str("contribution participant mismatch"),
            Self::Binding => f.write_str("contribution context or statement mismatch"),
            Self::Shape => f.write_str("malformed private contribution layout"),
            Self::PrivateBound => f.write_str("private contribution exceeds coefficient bound"),
            Self::ResponseBound => f.write_str("projected contribution exceeds response bound"),
            Self::Commitment => f.write_str("private contribution commitment mismatch"),
            Self::Equation => f.write_str("private contribution projection mismatch"),
            Self::Projection(error) => error.fmt(f),
            Self::Sharing(error) => error.fmt(f),
            Self::Ring(error) => error.fmt(f),
            Self::Sampling(error) => error.fmt(f),
        }
    }
}

impl error::Error for ContributionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Projection(error) => Some(error),
            Self::Sharing(error) => Some(error),
            Self::Ring(error) => Some(error),
            Self::Sampling(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// Explicit inputs for one candidate short-sharing distribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharingConfig {
    /// Input dimensions and response predicate for the projection.
    pub projection: ProjectionParameters,
    /// Threshold and number of recipients.
    pub committee: Vandermonde,
    /// Integer Gaussian width for the root input and every sharing split.
    pub input_sigma: u64,
    /// Distribution used independently for the root mask and every masking split.
    pub masking: Masking,
    /// Maximum accepted absolute centered coefficient in any private input share.
    pub private_limit: u64,
}

/// Explicit mask distribution for candidate verifiable sharing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Masking {
    /// Gaussian masking paired with a bounded projected response.
    Gaussian {
        /// Integer Gaussian width for every mask root and split sample.
        sigma: u64,
    },
    /// Uniform finite-ring masking paired with a consistency-only projection.
    Uniform,
}

/// A validated public sharing configuration bound to a caller-chosen session.
///
/// This is not a DKG round state. It contains no private entropy and can be
/// cloned. A failed contribution attempt must abort the enclosing session;
/// retry selection and fresh session identities are caller responsibilities.
#[derive(Clone, Debug)]
pub struct SharingSession {
    /// Pinned distributions, committee, and coefficient limits.
    config: SharingConfig,
    /// Identity of the session and all configuration fields.
    id: Identifier,
    /// Expected paths, allocated only after the work-budget check.
    layout: Arc<Shares<()>>,
}

/// An untrusted public contribution statement for consistent broadcast.
#[derive(Clone, Debug)]
pub struct Contribution {
    /// Identity of the complete sharing configuration and session.
    pub context: Identifier,
    /// One-based contributor identity authenticated by the application.
    pub contributor: u8,
    /// Salted recipient-payload commitments in ascending recipient order.
    pub commitments: Vec<Identifier>,
    /// Every projected share, with implicit committee/path ordering.
    pub projected: Shares<Polynomial>,
}

/// A recipient's confidential input and mask for one indexed share.
#[derive(Debug)]
pub struct PrivateShare {
    /// Input polynomials, including secret and error components.
    pub input: Vec<Polynomial>,
    /// Masking share stored in the degree-256 response ring.
    pub mask: Polynomial,
}

/// A confidential recipient payload; the salt and polynomial storage erase on drop.
///
/// This type is not Clone. Applications must authenticate the contributor and
/// deliver it confidentially to the named recipient. Its public fields permit
/// transport integration but do not bypass recipient verification.
pub struct PrivateContribution {
    /// Full sharing context identity.
    pub context: Identifier,
    /// Contributor authenticated by the application.
    pub contributor: u8,
    /// Intended one-based recipient.
    pub recipient: u8,
    /// Identity of the public statement, including projected shares.
    pub statement: Identifier,
    /// Independent secret salt hiding low-entropy recipient payloads.
    pub salt: Zeroizing<[u8; 32]>,
    /// Exact indexed payload for this recipient.
    pub shares: BTreeMap<Index, PrivateShare>,
}

impl fmt::Debug for PrivateContribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateContribution")
            .field("contributor", &self.contributor)
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

/// One contributor's broadcast statement and confidential recipient payloads.
#[derive(Debug)]
pub struct ContributionSet {
    /// Public statement requiring common broadcast agreement.
    pub public: Contribution,
    /// Confidential payloads in ascending recipient order.
    pub recipients: Vec<PrivateContribution>,
}

/// Public checks and cached projection for a candidate contribution.
///
/// This does not establish confidentiality or DKG security. Every recipient
/// must also validate its private payload against this same public statement.
#[derive(Clone, Debug)]
pub struct CheckedContribution {
    /// Configuration and expected layouts used for validation.
    session: SharingSession,
    /// Immutable statement whose public checks passed.
    public: Arc<Contribution>,
    /// Full statement identity.
    id: Identifier,
    /// Projection derived from all salted recipient commitments.
    projection: Arc<Projection>,
}

impl SharingSession {
    /// Validates parameters and binds a fresh session identifier to them.
    ///
    /// Requires `2 <= T < N <= 64` and `N >= 2T-1`. A contribution may use at
    /// most 2^28 scalar projection terms and 2^22 private scalar coefficients.
    /// These checks do not prove hiding,
    /// Gaussian completeness, or compatibility with signing parameters.
    pub fn new(config: SharingConfig, session: &Identifier) -> Result<Self, ContributionError> {
        let n = config.committee.parties();
        let t = config.committee.threshold();
        if t < 2
            || t >= n
            || u16::from(n) < 2 * u16::from(t) - 1
            || config.private_limit == 0
            || config.private_limit > config.projection.ring().modulus() / 2
        {
            return Err(ContributionError::Parameters);
        }
        Gaussian::new(config.input_sigma).map_err(sampling_error)?;
        match (config.masking, config.projection.response_limit()) {
            (Masking::Gaussian { sigma }, Some(_)) => {
                Gaussian::new(sigma).map_err(sampling_error)?;
            }
            (Masking::Uniform, None)
                if 2 * u128::from(t) * u128::from(config.private_limit)
                    < u128::from(config.projection.ring().modulus()) => {}
            _ => return Err(ContributionError::Parameters),
        }
        let count: usize = config.committee.share_counts().iter().sum();
        let terms = count as u128 * config.projection.columns() as u128 * 256;
        let coefficients = count as u128 * (config.projection.columns() + 256) as u128;
        if terms > MAX_PROJECTION_TERMS as u128 || coefficients > MAX_PRIVATE_COEFFICIENTS as u128 {
            return Err(ContributionError::Limit);
        }
        let p = config.projection;
        let kind: &[u8] = match config.masking {
            Masking::Gaussian { .. } => b"sharing-context-v1",
            Masking::Uniform => b"sharing-context-v2",
        };
        let mut transcript = transcript(kind);
        transcript
            .append(b"session", session)
            .append_u64(b"degree", p.ring().degree() as u64)
            .append_u64(b"modulus", p.ring().modulus())
            .append_u64(b"components", p.components() as u64);
        if let Some(limit) = p.response_limit() {
            transcript.append_u64(b"response-limit", limit);
        }
        transcript
            .append_u64(b"threshold", u64::from(t))
            .append_u64(b"parties", u64::from(n))
            .append_u64(b"input-sigma", config.input_sigma);
        match config.masking {
            Masking::Gaussian { sigma } => {
                transcript.append_u64(b"mask-sigma", sigma);
            }
            Masking::Uniform => {
                transcript.append(b"masking", b"uniform-v1");
            }
        }
        transcript.append_u64(b"private-limit", config.private_limit);
        Ok(Self {
            config,
            id: transcript.digest(),
            layout: Arc::new(config.committee.layout()),
        })
    }

    /// Returns the complete configuration used by this context.
    pub fn config(&self) -> SharingConfig {
        self.config
    }

    /// Borrows the configuration/session identity.
    pub fn id(&self) -> &Identifier {
        &self.id
    }

    /// Samples, commits, and projects one contribution without internal retries.
    ///
    /// All samples and salts are fixed before the projection is derived. Any
    /// sampling or norm failure returns an error and drops private material.
    pub fn contribute<R: TryCryptoRng>(
        &self,
        contributor: u8,
        rng: &mut R,
    ) -> Result<ContributionSet, ContributionError>
    where
        R::Error: error::Error + Send + Sync + 'static,
    {
        self.check_participant(contributor)?;
        let c = self.config;
        let input = c.committee.try_share(
            sample_input(c, rng)?,
            || sample_input(c, rng),
            |a, b| subtract_input(a, b),
        )?;
        let masks = c.committee.try_share(
            sample_mask(c, rng)?,
            || sample_mask(c, rng),
            |a, b| a.subtract(b).map_err(ContributionError::Ring),
        )?;
        let mut recipients = Vec::with_capacity(usize::from(c.committee.parties()));
        let mut commitments = Vec::with_capacity(recipients.capacity());
        for (i, (inputs, mut masks)) in input.into_iter().zip(masks).enumerate() {
            let mut shares = BTreeMap::new();
            for (index, input) in inputs {
                let mask = masks.remove(&index).ok_or(ContributionError::Shape)?;
                shares.insert(index, PrivateShare { input, mask });
            }
            let mut salt = Zeroizing::new([0; 32]);
            rng.try_fill_bytes(&mut *salt).map_err(sampling_error)?;
            let payload = PrivateContribution {
                context: self.id,
                contributor,
                recipient: i as u8 + 1,
                statement: [0; 64],
                salt,
                shares,
            };
            self.check_payload_shape(&payload)?;
            commitments.push(payload_commitment(&payload));
            recipients.push(payload);
        }
        let mut public = Contribution {
            context: self.id,
            contributor,
            commitments,
            projected: Vec::new(),
        };
        let projection = self.projection(&public)?;
        public.projected = recipients
            .iter()
            .map(|payload| {
                payload
                    .shares
                    .iter()
                    .map(|(index, share)| {
                        Ok((
                            index.clone(),
                            projection
                                .evaluate(&share.input, &share.mask)
                                .map_err(ContributionError::Projection)?,
                        ))
                    })
                    .collect()
            })
            .collect::<Result<_, ContributionError>>()?;
        self.check_projected(&public)?;
        let statement = statement_id(&public);
        for payload in &mut recipients {
            payload.statement = statement;
        }
        Ok(ContributionSet { public, recipients })
    }

    /// Validates an authenticated sender's public statement and caches its projection.
    pub fn check_contribution(
        &self,
        sender: u8,
        public: Contribution,
    ) -> Result<CheckedContribution, ContributionError> {
        self.check_participant(sender)?;
        if public.contributor != sender {
            return Err(ContributionError::Participant);
        }
        self.check_metadata(&public)?;
        self.check_projected(&public)?;
        let id = statement_id(&public);
        let projection = Arc::new(self.projection(&public)?);
        Ok(CheckedContribution {
            session: self.clone(),
            public: Arc::new(public),
            id,
            projection,
        })
    }

    /// Checks contributor, context, and the complete commitment list.
    fn check_metadata(&self, public: &Contribution) -> Result<(), ContributionError> {
        self.check_participant(public.contributor)?;
        if public.context != self.id {
            return Err(ContributionError::Binding);
        }
        if public.commitments.len() != usize::from(self.config.committee.parties()) {
            return Err(ContributionError::Shape);
        }
        Ok(())
    }

    /// Checks public layouts, all reconstructions, and the reconstructed norm.
    fn check_projected(&self, public: &Contribution) -> Result<(), ContributionError> {
        let c = self.config;
        let ring = c.projection.response_ring();
        if public.projected.len() != self.layout.len()
            || public
                .projected
                .iter()
                .zip(self.layout.iter())
                .any(|(actual, expected)| {
                    !actual.keys().eq(expected.keys()) || actual.values().any(|p| p.ring() != ring)
                })
        {
            return Err(ContributionError::Shape);
        }
        // Every ring and shape was checked above; addition cannot fail here.
        let root = c
            .committee
            .check(&public.projected, |a, b| {
                a.add(b).expect("prevalidated projection rings")
            })
            .map_err(ContributionError::Sharing)?;
        if !c
            .projection
            .accepts_response(&root)
            .map_err(ContributionError::Projection)?
        {
            return Err(ContributionError::ResponseBound);
        }
        Ok(())
    }

    /// Derives the challenge only from the fixed list of recipient commitments.
    fn projection(&self, public: &Contribution) -> Result<Projection, ContributionError> {
        self.check_metadata(public)?;
        let mut transcript = transcript(b"sharing-root-v1");
        transcript
            .append(b"context", &public.context)
            .append_u64(b"contributor", u64::from(public.contributor))
            .append_u64(b"recipients", public.commitments.len() as u64);
        for commitment in &public.commitments {
            transcript.append(b"leaf", commitment);
        }
        Projection::derive(
            self.config.projection,
            &self.id,
            public.contributor,
            &transcript.digest(),
        )
        .map_err(ContributionError::Projection)
    }

    /// Rejects identities outside the committee.
    fn check_participant(&self, participant: u8) -> Result<(), ContributionError> {
        if participant == 0 || participant > self.config.committee.parties() {
            return Err(ContributionError::Participant);
        }
        Ok(())
    }

    /// Validates one payload's entire index set, shapes, and direct input bounds.
    fn check_payload_shape(&self, payload: &PrivateContribution) -> Result<(), ContributionError> {
        self.check_participant(payload.recipient)?;
        let expected = &self.layout[usize::from(payload.recipient - 1)];
        if !payload.shares.keys().eq(expected.keys()) {
            return Err(ContributionError::Shape);
        }
        let c = self.config;
        for share in payload.shares.values() {
            if share.input.len() != c.projection.components()
                || share.input.iter().any(|p| p.ring() != c.projection.ring())
                || share.mask.ring() != c.projection.response_ring()
            {
                return Err(ContributionError::Shape);
            }
            if share
                .input
                .iter()
                .flat_map(Polynomial::centered)
                .any(|value| value.unsigned_abs() > c.private_limit)
            {
                return Err(ContributionError::PrivateBound);
            }
        }
        Ok(())
    }
}

impl CheckedContribution {
    /// Borrows the full public-statement identity.
    pub fn id(&self) -> &Identifier {
        &self.id
    }

    /// Borrows the public statement whose common checks passed.
    pub fn public(&self) -> &Contribution {
        &self.public
    }

    /// Validates an intended recipient's confidential payload without consuming it.
    ///
    /// Checks bindings, exact paths, direct private bounds, commitment opening,
    /// and each local projection equation. Agreement with other recipients and
    /// confidentiality are separate obligations; this does not produce a key.
    pub fn check_recipient(
        &self,
        recipient: u8,
        payload: &PrivateContribution,
    ) -> Result<(), ContributionError> {
        self.session.check_participant(recipient)?;
        if payload.recipient != recipient || payload.contributor != self.public.contributor {
            return Err(ContributionError::Participant);
        }
        if payload.context != self.session.id || payload.statement != self.id {
            return Err(ContributionError::Binding);
        }
        self.session.check_payload_shape(payload)?;
        if payload_commitment(payload) != self.public.commitments[usize::from(recipient - 1)] {
            return Err(ContributionError::Commitment);
        }
        let projected = &self.public.projected[usize::from(recipient - 1)];
        for (index, share) in &payload.shares {
            let value = self
                .projection
                .evaluate(&share.input, &share.mask)
                .map_err(ContributionError::Projection)?;
            if value != projected[index] {
                return Err(ContributionError::Equation);
            }
        }
        Ok(())
    }
}

/// Hashes a complete salted recipient payload without allocating secret bytes.
fn payload_commitment(payload: &PrivateContribution) -> Identifier {
    let mut transcript = transcript(b"sharing-leaf-v1");
    transcript
        .append(b"context", &payload.context)
        .append_u64(b"contributor", u64::from(payload.contributor))
        .append_u64(b"recipient", u64::from(payload.recipient))
        .append(b"salt", payload.salt.as_slice())
        .append_u64(b"shares", payload.shares.len() as u64);
    for (index, share) in &payload.shares {
        transcript
            .append(b"path", index.to_string().as_bytes())
            .append_u64(b"components", share.input.len() as u64);
        for polynomial in &share.input {
            append_polynomial(&mut transcript, b"input", polynomial);
        }
        append_polynomial(&mut transcript, b"mask", &share.mask);
    }
    transcript.digest()
}

/// Hashes all public fields, including the projected sharing, after validation.
fn statement_id(public: &Contribution) -> Identifier {
    let mut transcript = transcript(b"sharing-statement-v1");
    transcript
        .append(b"context", &public.context)
        .append_u64(b"contributor", u64::from(public.contributor))
        .append_u64(b"recipients", public.commitments.len() as u64);
    for commitment in &public.commitments {
        transcript.append(b"leaf", commitment);
    }
    for (i, party) in public.projected.iter().enumerate() {
        transcript
            .append_u64(b"recipient", i as u64 + 1)
            .append_u64(b"shares", party.len() as u64);
        for (index, polynomial) in party {
            transcript.append(b"path", index.to_string().as_bytes());
            append_polynomial(&mut transcript, b"projected", polynomial);
        }
    }
    transcript.digest()
}

/// Samples a root or split vector from the same explicit input distribution.
fn sample_input<R: TryCryptoRng>(
    c: SharingConfig,
    rng: &mut R,
) -> Result<Vec<Polynomial>, ContributionError>
where
    R::Error: error::Error + Send + Sync + 'static,
{
    let gaussian = Gaussian::new(c.input_sigma).map_err(sampling_error)?;
    (0..c.projection.components())
        .map(|_| {
            gaussian
                .polynomial(c.projection.ring(), rng)
                .map_err(sampling_error)
        })
        .collect()
}

/// Samples an independent mask root or split under the validated distribution.
fn sample_mask<R: TryCryptoRng>(
    c: SharingConfig,
    rng: &mut R,
) -> Result<Polynomial, ContributionError>
where
    R::Error: error::Error + Send + Sync + 'static,
{
    let ring = c.projection.response_ring();
    match c.masking {
        Masking::Gaussian { sigma } => Gaussian::new(sigma)
            .map_err(sampling_error)?
            .polynomial(ring, rng)
            .map_err(sampling_error),
        Masking::Uniform => sampling::uniform_polynomial(ring, rng).map_err(sampling_error),
    }
}

/// Subtracts two internally generated vectors during Figure 5 sharing.
fn subtract_input(
    a: &[Polynomial],
    b: &[Polynomial],
) -> Result<Vec<Polynomial>, ContributionError> {
    a.iter()
        .zip(b)
        .map(|(a, b)| a.subtract(b).map_err(ContributionError::Ring))
        .collect()
}

/// Preserves an entropy/sampling error as a standard error source.
fn sampling_error<E: error::Error + Send + Sync + 'static>(error: E) -> ContributionError {
    ContributionError::Sampling(Box::new(error))
}
