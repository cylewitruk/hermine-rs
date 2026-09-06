//! Explicit Hermine parameters and conservative integer correctness bounds.
//!
//! Validation checks algebra, dimensions, entropy, and representability. It does
//! not certify MLWE/MSIS hardness or define an author-approved security profile.

use std::{error, fmt};

use crate::{
    ring::{Ntt, Ring},
    sampling::Gaussian,
    sharing::Vandermonde,
};

#[cfg(any(feature = "experimental-dkg", feature = "experimental-mpc"))]
use crate::Identifier;

/// An invalid or unrepresentable protocol parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A signing configuration does not match the completed DKG's algebra.
    DkgMismatch,
    /// Matrix dimensions must lie in `1..=64`.
    Dimension,
    /// The supplied NTT root is invalid for the ring.
    Root,
    /// A bit-dropping exponent is invalid for the ring.
    Rounding,
    /// A Gaussian standard deviation is unsupported.
    Gaussian,
    /// Challenge or binding-factor entropy is insufficient or invalid.
    Entropy,
    /// The Gaussian tail multiplier does not satisfy the conservative bound.
    Tail,
    /// A signing or refresh limit is unsupported.
    Limit,
    /// A derived correctness bound cannot be represented exactly.
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DkgMismatch => "signing configuration does not match DKG output",
            Self::Dimension => "invalid matrix dimensions",
            Self::Root => "invalid NTT root",
            Self::Rounding => "invalid bit-dropping exponent",
            Self::Gaussian => "unsupported Gaussian standard deviation",
            Self::Entropy => "invalid or insufficient random-oracle output entropy",
            Self::Tail => "insufficient Gaussian tail multiplier",
            Self::Limit => "invalid protocol usage limit",
            Self::Overflow => "correctness bound exceeds integer limits",
        })
    }
}

impl error::Error for Error {}

/// All explicit inputs to a local parameter profile.
///
/// There are deliberately no default values or named security-level presets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The polynomial coefficient ring.
    pub ring: Ring,
    /// Primitive 2n-th root used by the NTT implementation.
    pub root: u64,
    /// Threshold and party count.
    pub committee: Vandermonde,
    /// Number of matrix rows, k.
    pub rows: usize,
    /// Number of matrix columns, ell.
    pub columns: usize,
    /// H_c/H_beta output entropy target; not a cryptanalytic security claim.
    pub entropy_bits: u16,
    /// Number of nonzero signed coefficients in the challenge, omega.
    pub challenge_weight: usize,
    /// Number of preprocessing columns, including the fixed beta_1=1 column.
    pub repetitions: usize,
    /// Dealer secret/sharing width; for DKG profiles, only the refresh width.
    pub secret_sigma: u64,
    /// Explicit integer standard deviation of preprocessing noise.
    pub nonce_sigma: u64,
    /// Public-key bit dropping, nu_t.
    pub public_key_bits: u32,
    /// Aggregated commitment bit dropping, nu_w.
    pub commitment_bits: u32,
    /// Per-party preprocessing bit dropping, nu_w_prime.
    pub preprocessing_bits: u32,
    /// Integer Gaussian tail multiplier alpha.
    pub tail_multiplier: u8,
    /// Global lifetime preprocessing allowance, conservatively divided among N parties.
    pub preprocessing_limit: u128,
    /// Maximum number of share refreshes over the key's lifetime, Q_rf.
    pub refresh_limit: u64,
}

/// Provenance bound into a key's parameter encoding and transcript identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyOrigin {
    /// The original paper's dealer profile and parameter encoding version 1.
    TrustedDealer,
    /// Experimental sigma=1 dealer-equivalent MPC, with a distinct transcript encoding.
    #[cfg(feature = "experimental-mpc")]
    ExperimentalMpc {
        /// Application-agreed fresh invocation identifier.
        session: Identifier,
    },
    /// Experimental DKG profile with explicit checked local contribution limits.
    #[cfg(feature = "experimental-dkg")]
    ExperimentalDkg {
        /// Identity of the complete candidate DKG public output.
        output: Identifier,
        /// Maximum centered coefficient in each accepted private contribution.
        contribution_limit: u64,
    },
}

/// Validated algebraic parameters with conservative integral norm bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parameters {
    /// Locally derived key-material pins, recoverable from the bound DKG output.
    #[cfg(feature = "experimental-dkg")]
    dkg_material: Option<dkg::DkgMaterial>,
    /// Key provenance and any DKG-specific bound inputs.
    origin: KeyOrigin,
    /// Explicit source configuration.
    config: Config,
    /// Validated reusable transform.
    ntt: Ntt,
    /// Partial signature Euclidean norm bound.
    partial_bound: u64,
    /// Final signature Euclidean norm bound.
    signature_bound: u64,
    /// Individual refresh Euclidean norm bound.
    refresh_bound: u64,
}

impl Parameters {
    /// Validates the configuration and derives Section 6.1 correctness bounds.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::build(config, KeyOrigin::TrustedDealer)
    }

    /// Validates common algebra and derives bounds for the selected key source.
    fn build(config: Config, origin: KeyOrigin) -> Result<Self, Error> {
        if !(1..=64).contains(&config.rows) || !(1..=64).contains(&config.columns) {
            return Err(Error::Dimension);
        }
        let ntt = Ntt::new(config.ring, config.root).map_err(|_| Error::Root)?;
        for bits in [
            config.public_key_bits,
            config.commitment_bits,
            config.preprocessing_bits,
        ] {
            config
                .ring
                .rounded_modulus(bits)
                .map_err(|_| Error::Rounding)?;
        }
        Gaussian::new(config.secret_sigma).map_err(|_| Error::Gaussian)?;
        Gaussian::new(config.nonce_sigma).map_err(|_| Error::Gaussian)?;
        let n = config.ring.degree();
        if !(1..=256).contains(&config.entropy_bits)
            || config.challenge_weight == 0
            || config.challenge_weight > n
            || !(2..=64).contains(&config.repetitions)
            || !challenge_entropy(n, config.challenge_weight, config.entropy_bits)
            || (config.repetitions - 1) * ((2 * n).ilog2() as usize)
                < usize::from(config.entropy_bits)
        {
            return Err(Error::Entropy);
        }
        let alpha = u128::from(config.tail_multiplier);
        if alpha < 2 || (alpha - 1).pow(2) * 3 * (n as u128) < u128::from(config.entropy_bits) {
            return Err(Error::Tail);
        }
        if config.preprocessing_limit < u128::from(config.committee.parties())
            || config.preprocessing_limit > (1_u128 << 64)
            || config.refresh_limit > (1 << 32)
        {
            return Err(Error::Limit);
        }
        let dimension = n as u128 * (config.rows + config.columns) as u128;
        let rows_dimension = n as u128 * config.rows as u128;
        let depth = u128::from(config.committee.parties().next_power_of_two().ilog2());
        let secret_scale = alpha * u128::from(config.secret_sigma);
        let refresh_bound = secret_scale * sqrt_ceil(dimension * depth);
        let dealer_secret_bound = secret_scale
            * sqrt_ceil(dimension)
            * (1 + (u128::from(config.refresh_limit) + 1) * sqrt_ceil(depth));
        let dealer_bounds = (
            dealer_secret_bound,
            alpha
                * u128::from(config.nonce_sigma)
                * sqrt_ceil(dimension * config.repetitions as u128),
        );
        let (secret_bound, nonce_bound) = match origin {
            KeyOrigin::TrustedDealer => dealer_bounds,
            #[cfg(feature = "experimental-mpc")]
            KeyOrigin::ExperimentalMpc { .. } => dealer_bounds,
            #[cfg(feature = "experimental-dkg")]
            KeyOrigin::ExperimentalDkg {
                contribution_limit, ..
            } => (
                u128::from(config.committee.parties())
                    * u128::from(contribution_limit)
                    * sqrt_ceil(dimension)
                    + u128::from(config.refresh_limit) * refresh_bound,
                config.repetitions as u128
                    * alpha
                    * u128::from(config.nonce_sigma)
                    * sqrt_ceil(dimension),
            ),
        };
        let partial_bound = 2 * config.challenge_weight as u128 * secret_bound
            + nonce_bound
            + config.repetitions as u128
                * (1_u128 << (config.preprocessing_bits - 1))
                * sqrt_ceil(rows_dimension);
        let scale = 1_u64 << config.commitment_bits;
        let q_rounded = config
            .ring
            .rounded_modulus(config.commitment_bits)
            .map_err(|_| Error::Rounding)?;
        let q_perp_positive = config.ring.modulus().saturating_sub(scale * q_rounded);
        // The larger of the bounds printed on pp. 26 and 30 covers both forms.
        let rounding_error = (3 * (u128::from(scale / 2) + u128::from(q_perp_positive))
            + config.challenge_weight as u128 * (1_u128 << (config.public_key_bits - 1)))
            * sqrt_ceil(rows_dimension);
        let signature_bound =
            u128::from(config.committee.threshold()) * partial_bound + rounding_error;
        Ok(Self {
            #[cfg(feature = "experimental-dkg")]
            dkg_material: None,
            origin,
            config,
            ntt,
            partial_bound: partial_bound.try_into().map_err(|_| Error::Overflow)?,
            signature_bound: signature_bound.try_into().map_err(|_| Error::Overflow)?,
            refresh_bound: refresh_bound.try_into().map_err(|_| Error::Overflow)?,
        })
    }

    /// Creates the restricted MPC prototype profile and binds its fresh session.
    ///
    /// This metadata constructor does not certify execution of MPC. The prototype
    /// supports sigma=1, 2-of-4 signing, and no refresh; MPC output owns the keys.
    #[cfg(feature = "experimental-mpc")]
    pub fn for_mpc(config: Config, session: Identifier) -> Result<Self, Error> {
        if config.committee.parties() != 4
            || config.committee.threshold() != 2
            || config.secret_sigma != 1
            || config.refresh_limit != 0
            || session == [0; 64]
        {
            return Err(Error::DkgMismatch);
        }
        Self::build(config, KeyOrigin::ExperimentalMpc { session })
    }

    /// Returns the key provenance bound into this profile's encoding.
    pub fn origin(&self) -> KeyOrigin {
        self.origin
    }

    /// Borrows the explicit configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Borrows the reusable transform.
    pub fn ntt(&self) -> &Ntt {
        &self.ntt
    }

    /// Returns the partial-signature norm bound.
    pub fn partial_bound(&self) -> u64 {
        self.partial_bound
    }

    /// Returns the final-signature norm bound.
    pub fn signature_bound(&self) -> u64 {
        self.signature_bound
    }

    /// Returns the individual refresh norm bound.
    pub fn refresh_bound(&self) -> u64 {
        self.refresh_bound
    }

    /// Returns the lifetime allowance for each party; refresh does not reset it.
    pub fn per_party_preprocessing_limit(&self) -> u128 {
        self.config.preprocessing_limit / u128::from(self.config.committee.parties())
    }

    /// Encodes all explicit inputs and derived bounds as versioned u64 LE fields.
    pub fn to_bytes(&self) -> Vec<u8> {
        let c = &self.config;
        let version = match self.origin {
            KeyOrigin::TrustedDealer => 1,
            #[cfg(feature = "experimental-mpc")]
            KeyOrigin::ExperimentalMpc { .. } => 3,
            #[cfg(feature = "experimental-dkg")]
            KeyOrigin::ExperimentalDkg { .. } => 2,
        };
        let values = [
            version,
            c.ring.degree() as u64,
            c.ring.modulus(),
            c.root,
            u64::from(c.committee.threshold()),
            u64::from(c.committee.parties()),
            c.rows as u64,
            c.columns as u64,
            u64::from(c.entropy_bits),
            c.challenge_weight as u64,
            c.repetitions as u64,
            c.secret_sigma,
            c.nonce_sigma,
            u64::from(c.public_key_bits),
            u64::from(c.commitment_bits),
            u64::from(c.preprocessing_bits),
            u64::from(c.tail_multiplier),
            c.preprocessing_limit as u64,
            (c.preprocessing_limit >> 64) as u64,
            c.refresh_limit,
            self.partial_bound,
            self.signature_bound,
            self.refresh_bound,
        ];
        let bytes = values.into_iter().flat_map(u64::to_le_bytes).collect();
        #[cfg(feature = "experimental-dkg")]
        let bytes = {
            let mut bytes: Vec<u8> = bytes;
            if let KeyOrigin::ExperimentalDkg {
                output,
                contribution_limit,
            } = self.origin
            {
                bytes.extend_from_slice(&contribution_limit.to_le_bytes());
                bytes.extend_from_slice(&output);
            }
            bytes
        };
        #[cfg(feature = "experimental-mpc")]
        let bytes = {
            let mut bytes: Vec<u8> = bytes;
            if let KeyOrigin::ExperimentalMpc { session } = self.origin {
                bytes.extend_from_slice(&session);
            }
            bytes
        };
        bytes
    }
}

#[cfg(feature = "experimental-dkg")]
mod dkg;

/// Returns ceil(sqrt(value)) using exact integer arithmetic.
fn sqrt_ceil(value: u128) -> u128 {
    let root = value.isqrt();
    root + u128::from(root * root != value)
}

/// Compares binomial(n, weight) * 2^weight with 2^bits without floating point.
fn challenge_entropy(n: usize, weight: usize, bits: u16) -> bool {
    if weight >= usize::from(bits) {
        return true;
    }
    let needed = usize::from(bits) - weight;
    let mut limbs = [0_u64; 5];
    limbs[0] = 1;
    for i in 1..=weight.min(n - weight) {
        let mut carry = 0_u128;
        for limb in &mut limbs {
            let value = u128::from(*limb) * (n - i + 1) as u128 + carry;
            *limb = value as u64;
            carry = value >> 64;
        }
        let mut remainder = 0_u128;
        for limb in limbs.iter_mut().rev() {
            let value = (remainder << 64) | u128::from(*limb);
            *limb = (value / i as u128) as u64;
            remainder = value % i as u128;
        }
        if limbs[needed / 64] >> (needed % 64) != 0
            || limbs[needed / 64 + 1..].iter().any(|&x| x != 0)
        {
            return true;
        }
    }
    false
}
