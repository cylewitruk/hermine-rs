//! Uniform residues and centered discrete Gaussians using exact integer arithmetic.
//!
//! Gaussian sampling uses the Canonne–Kamath–Steinke rejection construction,
//! specialized to integer standard deviations and Laplace scale t = sigma.
//! See `docs/SAMPLING.md` for the derivation, sources, and finite-integer limits.
//! Rejection paths are variable-time; this is not a side-channel hardened sampler.

use std::{convert::Infallible, error, fmt};

use rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroizing;

use crate::ring::{self, Polynomial, Ring};

/// An invalid sampling parameter, entropy-source failure, or arithmetic failure.
#[derive(Debug)]
pub enum Error<E = Infallible> {
    /// The requested standard deviation is outside `1..=2^36`.
    StandardDeviation,
    /// A uniform sampling range is empty.
    EmptyRange,
    /// The caller's entropy source returned an error.
    Random(E),
    /// A sample or rejection counter exceeded the finite integer representation.
    Overflow,
    /// Polynomial construction failed.
    Ring(ring::Error),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StandardDeviation => f.write_str("standard deviation must be in 1..=2^36"),
            Self::EmptyRange => f.write_str("uniform sampling range is empty"),
            Self::Random(error) => write!(f, "entropy source failed: {error}"),
            Self::Overflow => f.write_str("sampling exceeded integer representation limits"),
            Self::Ring(error) => error.fmt(f),
        }
    }
}

impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Random(error) => Some(error),
            Self::Ring(error) => Some(error),
            _ => None,
        }
    }
}

/// A centered discrete Gaussian with an explicit integer standard deviation.
///
/// The target mass at x is proportional to `exp(-x² / (2 sigma²))`, as in Hermine
/// Definition 2.2. No floating-point calculations or Gaussian tail clamping occur.
///
/// A caller must provide cryptographically suitable randomness:
///
/// ```rust,compile_fail
/// use hermine::sampling::Gaussian;
/// use rand_core::TryRng;
///
/// fn sample_with_unrestricted_rng<R: TryRng>(rng: &mut R) {
///     let gaussian = Gaussian::new(128).unwrap();
///     let _ = gaussian.sample(rng); // R lacks the required TryCryptoRng bound.
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gaussian {
    /// Integer standard deviation, not variance or a bit-width.
    sigma: u64,
}

impl Gaussian {
    /// Validates an explicit standard deviation in `1..=2^36`.
    pub fn new(sigma: u64) -> Result<Self, Error> {
        if !(1..=(1 << 36)).contains(&sigma) {
            return Err(Error::StandardDeviation);
        }
        Ok(Self { sigma })
    }

    /// Returns the configured standard deviation.
    pub fn sigma(self) -> u64 {
        self.sigma
    }

    /// Samples an integer with exact rational acceptance probabilities.
    ///
    /// Entropy failures and unrepresentable proposals/counters abort sampling;
    /// they are never converted to zeros, clamped tails, or silent retries.
    /// With a correctly implemented random source, loops terminate almost surely.
    pub fn sample<R: TryCryptoRng + ?Sized>(self, rng: &mut R) -> Result<i64, Error<R::Error>> {
        let denominator = 2 * u128::from(self.sigma).pow(2);
        loop {
            let (magnitude, negative) = laplace(self.sigma, rng)?;
            let difference = magnitude.abs_diff(self.sigma);
            let numerator = u128::from(difference).pow(2);
            if bernoulli_exp(numerator, denominator, rng)? {
                let magnitude = i64::try_from(magnitude).map_err(|_| Error::Overflow)?;
                return Ok(if negative { -magnitude } else { magnitude });
            }
        }
    }

    /// Samples independent Gaussian coefficients and reduces them modulo q.
    pub fn polynomial<R: TryCryptoRng + ?Sized>(
        self,
        ring: Ring,
        rng: &mut R,
    ) -> Result<Polynomial, Error<R::Error>> {
        let mut coefficients = Zeroizing::new(Vec::with_capacity(ring.degree()));
        for _ in 0..ring.degree() {
            coefficients.push(self.sample(rng)?);
        }
        ring.from_signed(&coefficients).map_err(Error::Ring)
    }
}

/// Samples uniformly from `[0, bound)` without modulo bias.
///
/// Each proposal reads 16 bytes and interprets their low bits as a little-endian
/// integer. A singleton range consumes no entropy; a zero bound is rejected.
pub fn uniform_below<R: TryRng + ?Sized>(
    bound: u128,
    rng: &mut R,
) -> Result<u128, Error<R::Error>> {
    if bound == 0 {
        return Err(Error::EmptyRange);
    }
    if bound == 1 {
        return Ok(0);
    }
    let bits = 128 - (bound - 1).leading_zeros();
    let mask = u128::MAX >> (128 - bits);
    let mut bytes = Zeroizing::new([0_u8; 16]);
    loop {
        rng.try_fill_bytes(bytes.as_mut()).map_err(Error::Random)?;
        let value = u128::from_le_bytes(*bytes) & mask;
        if value < bound {
            return Ok(value);
        }
    }
}

/// Samples a polynomial uniformly from the given coefficient ring.
pub fn uniform_polynomial<R: TryCryptoRng + ?Sized>(
    ring: Ring,
    rng: &mut R,
) -> Result<Polynomial, Error<R::Error>> {
    let mut coefficients = Zeroizing::new(Vec::with_capacity(ring.degree()));
    for _ in 0..ring.degree() {
        coefficients.push(uniform_below(u128::from(ring.modulus()), rng)? as u64);
    }
    ring.polynomial(&coefficients).map_err(Error::Ring)
}

/// Samples a signed discrete Laplace proposal with positive integer scale.
fn laplace<R: TryCryptoRng + ?Sized>(
    scale: u64,
    rng: &mut R,
) -> Result<(u64, bool), Error<R::Error>> {
    loop {
        let u = loop {
            let u = uniform_below(u128::from(scale), rng)?;
            if bernoulli_exp(u, u128::from(scale), rng)? {
                break u as u64;
            }
        };
        let mut v = 0_u64;
        while bernoulli_exp_unit(1, 1, rng)? {
            v = v.checked_add(1).ok_or(Error::Overflow)?;
        }
        let magnitude = v
            .checked_mul(scale)
            .and_then(|value| value.checked_add(u))
            .ok_or(Error::Overflow)?;
        let negative = uniform_below(2, rng)? == 1;
        if magnitude == 0 && negative {
            continue;
        }
        return Ok((magnitude, negative));
    }
}

/// Samples Bernoulli(exp(-numerator/denominator)) for a nonnegative ratio.
fn bernoulli_exp<R: TryCryptoRng + ?Sized>(
    mut numerator: u128,
    denominator: u128,
    rng: &mut R,
) -> Result<bool, Error<R::Error>> {
    while numerator > denominator {
        if !bernoulli_exp_unit(1, 1, rng)? {
            return Ok(false);
        }
        numerator -= denominator;
    }
    bernoulli_exp_unit(numerator, denominator, rng)
}

/// Samples the exponential Bernoulli distribution for a ratio in `[0, 1]`.
fn bernoulli_exp_unit<R: TryCryptoRng + ?Sized>(
    numerator: u128,
    denominator: u128,
    rng: &mut R,
) -> Result<bool, Error<R::Error>> {
    if numerator == 0 {
        return Ok(true);
    }
    let mut counter = 1_u128;
    loop {
        let divisor = denominator.checked_mul(counter).ok_or(Error::Overflow)?;
        let factor = gcd(numerator, divisor);
        let draw = uniform_below(divisor / factor, rng)?;
        if draw >= numerator / factor {
            return Ok(counter % 2 == 1);
        }
        counter = counter.checked_add(1).ok_or(Error::Overflow)?;
    }
}

/// Reduces rational probabilities before unbiased integer sampling.
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
