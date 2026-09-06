//! Versioned, length-framed SHAKE256 transcripts for Hermine's random oracles.
//!
//! This is a local wire convention, not an author-published Hermine encoding.
//! Each field binds its label, length, and bytes. Extraction binds ring and
//! sampling parameters as additional fields. Protocol callers must still include
//! every input specified for H_c and H_beta in the paper.

use std::{convert::Infallible, error, fmt};

use rand_core::{TryCryptoRng, TryRng};
use shake::{ExtendableOutput, Shake256, Shake256Reader, Update, XofReader};

use crate::{
    linear::{self, Matrix, Vector},
    ring::{self, Polynomial, Ring},
    sampling,
};

/// A distinct protocol purpose in transcript format version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Domain {
    /// H_c, deriving the sparse signature challenge.
    Challenge = 1,
    /// H_beta, deriving commitment binding coefficients.
    Binding = 2,
    /// Expansion of a public matrix seed.
    Matrix = 3,
    /// Identification of a public key and its parameters.
    Key = 4,
    /// Identification of a particular signing session.
    Session = 5,
    /// Identification of a share-refresh transcript.
    Refresh = 6,
    /// Experimental distributed key generation research, with labeled subprotocols.
    Dkg = 7,
}

/// An invalid transcript extraction parameter or sampling failure.
#[derive(Debug)]
pub enum Error {
    /// Matrix dimensions or component construction failed.
    Linear(linear::Error),
    /// Challenge weight must be in `1..=n`.
    Weight,
    /// Binding-factor count must be in `2..=64`.
    Repetitions,
    /// Extraction was requested for a different transcript purpose.
    Domain,
    /// Polynomial construction failed.
    Ring(ring::Error),
    /// Uniform extraction failed.
    Sampling(sampling::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linear(error) => error.fmt(f),
            Self::Weight => f.write_str("invalid challenge weight"),
            Self::Repetitions => f.write_str("invalid binding-factor count"),
            Self::Domain => f.write_str("incorrect transcript domain for extraction"),
            Self::Ring(error) => error.fmt(f),
            Self::Sampling(error) => error.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Linear(error) => Some(error),
            Self::Ring(error) => Some(error),
            Self::Sampling(error) => Some(error),
            _ => None,
        }
    }
}

/// A signed monomial used to combine preprocessing commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Monomial {
    /// Exponent of X; smaller than the ring degree used during extraction.
    exponent: usize,
    /// Whether the coefficient is -1 rather than +1.
    negative: bool,
}

impl Monomial {
    /// Returns the exponent of X.
    pub fn exponent(self) -> usize {
        self.exponent
    }

    /// Returns true for a coefficient of -1.
    pub fn is_negative(self) -> bool {
        self.negative
    }

    /// Multiplies a polynomial by this signed monomial.
    pub fn apply(self, polynomial: &Polynomial) -> Result<Polynomial, ring::Error> {
        polynomial.monomial(self.exponent, self.negative)
    }
}

/// A consuming transcript builder with domain-separated, labeled fields.
pub struct Transcript {
    /// SHAKE absorption state.
    state: Shake256,
    /// Purpose selected at construction.
    domain: Domain,
}

impl fmt::Debug for Transcript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transcript")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl Transcript {
    /// Starts a version-1 transcript with a fixed protocol purpose.
    pub fn new(domain: Domain) -> Self {
        let mut state = Shake256::default();
        state.update(b"hermine-rs/transcript/v1\0");
        state.update(&[domain as u8]);
        Self { state, domain }
    }

    /// Appends `len(label) || label || len(value) || value`, with u64 LE lengths.
    pub fn append(&mut self, label: &[u8], value: &[u8]) -> &mut Self {
        self.state.update(&(label.len() as u64).to_le_bytes());
        self.state.update(label);
        self.state.update(&(value.len() as u64).to_le_bytes());
        self.state.update(value);
        self
    }

    /// Appends a labeled fixed-width little-endian integer.
    pub fn append_u64(&mut self, label: &[u8], value: u64) -> &mut Self {
        self.append(label, &value.to_le_bytes())
    }

    /// Consumes the transcript and extracts a fixed number of SHAKE256 bytes.
    pub fn digest<const N: usize>(self) -> [u8; N] {
        let mut output = [0; N];
        self.fill(&mut output);
        output
    }

    /// Consumes the transcript and fills a caller-sized SHAKE256 output buffer.
    ///
    /// The caller controls and bounds the allocation. Domain-specific protocols
    /// must specify how these bytes are interpreted and bind every required input.
    pub fn fill(self, output: &mut [u8]) {
        self.state.finalize_xof().read(output);
    }

    /// Extracts a uniform matrix in row/component/coefficient order.
    ///
    /// Requires the Matrix domain and dimensions in `1..=64`. The caller must
    /// bind the complete agreed input transcript before requesting extraction.
    pub fn matrix(mut self, ring: Ring, rows: usize, columns: usize) -> Result<Matrix, Error> {
        if self.domain != Domain::Matrix {
            return Err(Error::Domain);
        }
        if !(1..=64).contains(&rows) || !(1..=64).contains(&columns) {
            return Err(Error::Linear(linear::Error::Dimension));
        }
        self.bind_ring(ring);
        self.append_u64(b"matrix-rows", rows as u64)
            .append_u64(b"matrix-columns", columns as u64);
        let mut source = OracleSource(self.state.finalize_xof());
        let entries = (0..rows)
            .map(|_| {
                let entries = (0..columns)
                    .map(|_| {
                        sampling::uniform_polynomial(ring, &mut source).map_err(Error::Sampling)
                    })
                    .collect::<Result<_, _>>()?;
                Vector::new(entries).map_err(Error::Linear)
            })
            .collect::<Result<_, _>>()?;
        Matrix::new(entries).map_err(Error::Linear)
    }

    /// Derives a uniformly selected signed weight-omega challenge polynomial.
    ///
    /// Uses partial Fisher–Yates selection so support indices never repeat.
    /// This operation is only available for the Challenge domain.
    pub fn challenge(mut self, ring: Ring, weight: usize) -> Result<Polynomial, Error> {
        if self.domain != Domain::Challenge {
            return Err(Error::Domain);
        }
        if weight == 0 || weight > ring.degree() {
            return Err(Error::Weight);
        }
        self.bind_ring(ring);
        self.append_u64(b"challenge-weight", weight as u64);
        let mut source = OracleSource(self.state.finalize_xof());
        let mut coefficients = vec![0_i64; ring.degree()];
        for i in ring.degree() - weight..ring.degree() {
            let index = source.uniform((i + 1) as u128)? as usize;
            coefficients[i] = coefficients[index];
            coefficients[index] = if source.uniform(2)? == 0 { 1 } else { -1 };
        }
        ring.from_signed(&coefficients).map_err(Error::Ring)
    }

    /// Derives beta_1=1 followed by independent uniformly signed monomials.
    ///
    /// The caller's parameter profile must additionally enforce the paper's
    /// entropy requirement `(2n)^(repetitions-1) >= 2^kappa`.
    pub fn binding_factors(
        mut self,
        ring: Ring,
        repetitions: usize,
    ) -> Result<Vec<Monomial>, Error> {
        if self.domain != Domain::Binding {
            return Err(Error::Domain);
        }
        if !(2..=64).contains(&repetitions) {
            return Err(Error::Repetitions);
        }
        self.bind_ring(ring);
        self.append_u64(b"binding-repetitions", repetitions as u64);
        let mut source = OracleSource(self.state.finalize_xof());
        let mut factors = Vec::with_capacity(repetitions);
        factors.push(Monomial {
            exponent: 0,
            negative: false,
        });
        for _ in 1..repetitions {
            let sample = source.uniform(2 * ring.degree() as u128)? as usize;
            factors.push(Monomial {
                exponent: sample % ring.degree(),
                negative: sample >= ring.degree(),
            });
        }
        Ok(factors)
    }

    /// Appends ring parameters before domain-specific extraction.
    fn bind_ring(&mut self, ring: Ring) {
        self.append_u64(b"ring-degree", ring.degree() as u64);
        self.append_u64(b"ring-modulus", ring.modulus());
    }
}

/// Public oracle output used for unbiased extraction, not secret RNG seeding.
struct OracleSource(Shake256Reader);

// SHAKE provides a cryptographic stream. Matrix extraction intentionally uses
// public input; this private adapter is never used to sample secret material.
impl TryCryptoRng for OracleSource {}

impl OracleSource {
    /// Samples uniformly from a nonempty range of oracle output integers.
    fn uniform(&mut self, bound: u128) -> Result<u128, Error> {
        sampling::uniform_below(bound, self).map_err(Error::Sampling)
    }
}

impl TryRng for OracleSource {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.0.read(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.0.read(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(destination);
        Ok(())
    }
}
