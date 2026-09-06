//! Ternary projections and conservative coefficient-bound research predicates.

use std::{error, fmt};

use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zeroize::Zeroizing;

use crate::{
    Identifier,
    ring::{self, Polynomial, Ring},
    transcript::{Domain, Transcript},
};

/// Number of independent scalar projection rows in the research construction.
const ROWS: usize = 256;
/// Allocation and work limit for one flattened input vector.
const MAX_COLUMNS: usize = 16384;

/// An invalid projection configuration or arithmetic input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Component count or flattened dimension exceeds the supported limits.
    Dimension,
    /// The response bound is zero or leaves no detectable large coefficients.
    Bound,
    /// A contributor identifier is outside 1 through 64.
    Participant,
    /// Polynomial shapes or rings differ from the pinned configuration.
    Shape,
    /// Underlying polynomial construction failed.
    Ring(ring::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dimension => f.write_str("invalid projection dimension"),
            Self::Bound => f.write_str("invalid projection response bound"),
            Self::Participant => f.write_str("invalid projection contributor"),
            Self::Shape => f.write_str("projection input shape or ring mismatch"),
            Self::Ring(error) => error.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Ring(error) => Some(error),
            _ => None,
        }
    }
}

/// Explicit dimensions and an optional infinity-norm response limit.
///
/// Construction checks arithmetic conditions, not completeness, privacy, or DKG
/// security. The fixed-input argument in `docs/DKG-SUBMERSION.md` bounds each
/// secret coefficient by twice a configured response limit. Consistency-only
/// projections do not provide that shortness predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionParameters {
    /// Ring of the input polynomials.
    ring: Ring,
    /// Number of input polynomials, including both secret and error components.
    components: usize,
    /// Ring used solely to store 256 scalar mask/response coordinates.
    response_ring: Ring,
    /// Maximum accepted absolute centered response coefficient.
    response_limit: Option<u64>,
}

impl ProjectionParameters {
    /// Pins dimensions and checks `0 < 4*response_limit < q-1`.
    ///
    /// Supports 1 through 128 input polynomials and at most 16384 flattened
    /// coefficients. Polynomial multiplication is not used by this primitive.
    pub fn new(ring: Ring, components: usize, response_limit: u64) -> Result<Self, Error> {
        Self::build(ring, components, Some(response_limit))
    }

    /// Pins dimensions for consistency projection with no masked-response norm check.
    ///
    /// Intended for the uniform-mask research variant, which derives its root
    /// norm bound from checked private shares instead of the projected response.
    pub fn for_consistency(ring: Ring, components: usize) -> Result<Self, Error> {
        Self::build(ring, components, None)
    }

    /// Checks common dimensions and any configured response predicate.
    fn build(ring: Ring, components: usize, response_limit: Option<u64>) -> Result<Self, Error> {
        if !(1..=128).contains(&components) || components * ring.degree() > MAX_COLUMNS {
            return Err(Error::Dimension);
        }
        if response_limit.is_some_and(|limit| {
            limit == 0 || 4 * u128::from(limit) >= u128::from(ring.modulus() - 1)
        }) {
            return Err(Error::Bound);
        }
        Ok(Self {
            ring,
            components,
            response_ring: Ring::new(ROWS, ring.modulus()).map_err(Error::Ring)?,
            response_limit,
        })
    }

    /// Returns the input polynomial ring.
    pub fn ring(self) -> Ring {
        self.ring
    }

    /// Returns the number of input polynomials.
    pub fn components(self) -> usize {
        self.components
    }

    /// Returns the number of scalar input coefficients.
    pub fn columns(self) -> usize {
        self.components * self.ring.degree()
    }

    /// Returns the degree-256 ring storing scalar masks and responses.
    pub fn response_ring(self) -> Ring {
        self.response_ring
    }

    /// Returns the response coefficient limit, or None for consistency-only mode.
    pub fn response_limit(self) -> Option<u64> {
        self.response_limit
    }

    /// Returns twice the response limit, the candidate secret coefficient bound.
    pub fn secret_coefficient_bound(self) -> Option<u64> {
        self.response_limit.map(|limit| 2 * limit)
    }

    /// Returns the squared Euclidean bound implied by the coefficient bound.
    pub fn secret_norm_squared_bound(self) -> Option<u128> {
        self.secret_coefficient_bound()
            .map(|limit| self.columns() as u128 * u128::from(limit).pow(2))
    }

    /// Checks shape and any configured infinity-norm bound on a masked response.
    ///
    /// Success does not validate commitments, the projection equation, share
    /// consistency, or the independence required by the probability argument.
    pub fn accepts_response(self, response: &Polynomial) -> Result<bool, Error> {
        if response.ring() != self.response_ring {
            return Err(Error::Shape);
        }
        Ok(self.response_limit.is_none_or(|limit| {
            response
                .centered()
                .all(|coefficient| coefficient.unsigned_abs() <= limit)
        }))
    }
}

/// A public 256-row ternary matrix derived from a bound contribution commitment.
///
/// Entries have the intended probabilities 1/2 for zero and 1/4 for each sign
/// when the expansion is modeled as uniform. Callers must commit to both the
/// input and mask before deriving this matrix; the type cannot enforce that.
#[derive(Clone)]
pub struct Projection {
    /// Pinned input dimensions and response predicate.
    parameters: ProjectionParameters,
    /// Public matrix coefficients in row-major order.
    coefficients: Box<[i8]>,
}

impl fmt::Debug for Projection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Projection")
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
}

impl Projection {
    /// Derives a matrix bound to context, contributor, commitment, and parameters.
    ///
    /// The context must identify the complete common DKG configuration and a
    /// fresh session. It is an opaque identifier at this primitive layer.
    pub fn derive(
        parameters: ProjectionParameters,
        context: &Identifier,
        contributor: u8,
        commitment: &Identifier,
    ) -> Result<Self, Error> {
        if !(1..=64).contains(&contributor) {
            return Err(Error::Participant);
        }
        let mut transcript = Transcript::new(Domain::Dkg);
        let kind: &[u8] = if parameters.response_limit.is_some() {
            b"ternary-submersion-v1"
        } else {
            b"ternary-consistency-v1"
        };
        transcript
            .append(b"kind", kind)
            .append(b"context", context)
            .append_u64(b"contributor", u64::from(contributor))
            .append(b"commitment", commitment)
            .append_u64(b"degree", parameters.ring.degree() as u64)
            .append_u64(b"modulus", parameters.ring.modulus())
            .append_u64(b"components", parameters.components as u64)
            .append_u64(b"rows", ROWS as u64);
        if let Some(limit) = parameters.response_limit {
            transcript.append_u64(b"response-limit", limit);
        }
        let mut packed = vec![0; ROWS * parameters.columns() / 4];
        if parameters.response_limit.is_some() {
            let mut state = Shake256::default();
            state.update(b"hermine-rs/dkg/projection-expand/v1\0");
            state.update(&transcript.digest::<64>());
            state.finalize_xof().read(&mut packed);
        } else {
            // The uniform variant has one direct challenge XOF, avoiding a
            // separate seeded expansion in its random-oracle specification.
            transcript.fill(&mut packed);
        }
        let coefficients = packed
            .into_iter()
            .flat_map(|byte| {
                [0, 2, 4, 6].map(|shift| match (byte >> shift) & 3 {
                    1 => 1,
                    2 => -1,
                    _ => 0,
                })
            })
            .collect();
        Ok(Self {
            parameters,
            coefficients,
        })
    }

    /// Returns the configuration bound by this projection.
    pub fn parameters(&self) -> ProjectionParameters {
        self.parameters
    }

    /// Borrows public matrix coefficients in row-major order.
    pub fn coefficients(&self) -> &[i8] {
        &self.coefficients
    }

    /// Computes `R*x + mask mod q`, flattening polynomials in component order.
    ///
    /// Within each component, coefficients are ordered by increasing degree.
    /// The mask must use the configured response ring. Arithmetic is variable-time.
    pub fn evaluate(&self, input: &[Polynomial], mask: &Polynomial) -> Result<Polynomial, Error> {
        let p = self.parameters;
        if input.len() != p.components
            || input.iter().any(|polynomial| polynomial.ring() != p.ring)
            || mask.ring() != p.response_ring
        {
            return Err(Error::Shape);
        }
        let mut output = Zeroizing::new(Vec::with_capacity(ROWS));
        for (row, &mask) in self
            .coefficients
            .chunks_exact(p.columns())
            .zip(mask.coefficients())
        {
            let mut sum = Zeroizing::new(i128::from(mask));
            for (&coefficient, &value) in row
                .iter()
                .zip(input.iter().flat_map(Polynomial::coefficients))
            {
                *sum += i128::from(coefficient) * i128::from(value);
            }
            output.push(sum.rem_euclid(i128::from(p.ring.modulus())) as u64);
        }
        p.response_ring.polynomial(&output).map_err(Error::Ring)
    }
}
