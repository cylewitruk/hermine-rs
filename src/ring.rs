//! Reference arithmetic in `Z_q[X]/(X^n + 1)`.
//!
//! Coefficients are canonical residues. Norms use centered representatives, while
//! rounding uses nonnegative representatives (paper Sections 2.1 and 2.2).
//! This implementation is variable-time and is not a side-channel hardened backend.
//!
//! ```
//! use hermine::ring::{Ntt, Ring};
//!
//! let ring = Ring::new(4, 17)?;
//! let x = ring.from_signed(&[0, 1, 0, 0])?;
//! let x_cubed = ring.from_signed(&[0, 0, 0, 1])?;
//! let minus_one = ring.from_signed(&[-1, 0, 0, 0])?;
//! assert_eq!(x.multiply(&x_cubed)?, minus_one);
//! assert_eq!(Ntt::new(ring, 2)?.multiply(&x, &x_cubed)?, minus_one);
//! # Ok::<(), hermine::ring::Error>(())
//! ```

use std::{error, fmt};

use zeroize::{Zeroize, Zeroizing};

mod ntt;

pub use ntt::{Ntt, NttPolynomial};

/// An invalid ring description, coefficient, or arithmetic operand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The degree must be a power of two between 2 and 4096.
    Degree,
    /// The modulus must be odd, at least 3, and smaller than 2^48.
    Modulus,
    /// The coefficient count differs from the ring degree.
    Length,
    /// A coefficient is outside the canonical range `[0, q)`.
    NonCanonical,
    /// The operands belong to different rings.
    RingMismatch,
    /// The rounding exponent must satisfy `0 < 2^bits < q`.
    Rounding,
    /// The monomial degree is not smaller than the ring degree.
    Monomial,
    /// The supplied value is not a canonical primitive 2n-th root of unity.
    Root,
    /// Transformed operands use a different root of unity or ring.
    TransformMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Degree => "invalid ring degree",
            Self::Modulus => "invalid ring modulus",
            Self::Length => "incorrect coefficient count",
            Self::NonCanonical => "noncanonical coefficient",
            Self::RingMismatch => "operands belong to different rings",
            Self::Rounding => "invalid rounding exponent",
            Self::Monomial => "invalid monomial degree",
            Self::Root => "invalid root of unity",
            Self::TransformMismatch => "incompatible number theoretic transforms",
        })
    }
}

impl error::Error for Error {}

/// A bounded ring description; primality is not implied by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ring {
    /// Degree of the power-of-two cyclotomic polynomial.
    degree: usize,
    /// Odd coefficient modulus.
    modulus: u64,
}

impl Ring {
    /// Validates arithmetic bounds for a power-of-two cyclotomic ring.
    pub fn new(degree: usize, modulus: u64) -> Result<Self, Error> {
        if !(2..=4096).contains(&degree) || !degree.is_power_of_two() {
            return Err(Error::Degree);
        }
        if !(3..(1 << 48)).contains(&modulus) || modulus.is_multiple_of(2) {
            return Err(Error::Modulus);
        }
        Ok(Self { degree, modulus })
    }

    /// Returns the number of coefficients in each polynomial.
    pub fn degree(self) -> usize {
        self.degree
    }

    /// Returns the coefficient modulus.
    pub fn modulus(self) -> u64 {
        self.modulus
    }

    /// Constructs the zero polynomial.
    pub fn zero(self) -> Polynomial {
        Polynomial {
            ring: self,
            coefficients: vec![0; self.degree].into_boxed_slice(),
        }
    }

    /// Constructs a polynomial, rejecting noncanonical coefficients and lengths.
    pub fn polynomial(self, coefficients: &[u64]) -> Result<Polynomial, Error> {
        if coefficients.len() != self.degree {
            return Err(Error::Length);
        }
        if coefficients
            .iter()
            .any(|&coefficient| coefficient >= self.modulus)
        {
            return Err(Error::NonCanonical);
        }
        Ok(Polynomial {
            ring: self,
            coefficients: coefficients.into(),
        })
    }

    /// Reduces signed integer coefficients modulo q.
    pub fn from_signed(self, coefficients: &[i64]) -> Result<Polynomial, Error> {
        if coefficients.len() != self.degree {
            return Err(Error::Length);
        }
        Ok(Polynomial {
            ring: self,
            coefficients: coefficients
                .iter()
                .map(|&x| x.rem_euclid(self.modulus as i64) as u64)
                .collect(),
        })
    }

    /// Returns the nearest-integer modulus q_nu from Table 2.
    pub fn rounded_modulus(self, bits: u32) -> Result<u64, Error> {
        let scale = self.rounding_scale(bits)?;
        Ok((self.modulus + scale / 2) / scale)
    }

    /// Validates a rounding exponent and returns its scale.
    fn rounding_scale(self, bits: u32) -> Result<u64, Error> {
        let scale = 1_u64.checked_shl(bits).ok_or(Error::Rounding)?;
        if bits == 0 || scale >= self.modulus {
            return Err(Error::Rounding);
        }
        Ok(scale)
    }
}

/// A polynomial with canonical coefficients and an explicit ring identity.
///
/// Storage is zeroized on drop and Debug omits coefficients. This low-level
/// arithmetic value remains cloneable; protocol secret types must enforce their
/// own ownership and nonce-use rules.
#[derive(Clone, Eq, PartialEq)]
pub struct Polynomial {
    /// Ring containing the polynomial.
    ring: Ring,
    /// Canonical coefficients in increasing degree order.
    coefficients: Box<[u64]>,
}

impl fmt::Debug for Polynomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Polynomial")
            .field("ring", &self.ring)
            .finish_non_exhaustive()
    }
}

impl Drop for Polynomial {
    fn drop(&mut self) {
        self.coefficients.zeroize();
    }
}

impl Polynomial {
    /// Returns this polynomial's ring.
    pub fn ring(&self) -> Ring {
        self.ring
    }

    /// Borrows canonical coefficients in increasing degree order.
    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }

    /// Iterates over representatives in `(-q/2, q/2]`.
    pub fn centered(&self) -> impl Iterator<Item = i64> + '_ {
        self.coefficients.iter().map(|&x| {
            if x > self.ring.modulus / 2 {
                x as i64 - self.ring.modulus as i64
            } else {
                x as i64
            }
        })
    }

    /// Returns the exact squared Euclidean norm of centered coefficients.
    pub fn norm_squared(&self) -> u128 {
        self.centered()
            .map(|x| u128::from(x.unsigned_abs()).pow(2))
            .sum()
    }

    /// Adds polynomials, rejecting a ring mismatch.
    pub fn add(&self, rhs: &Self) -> Result<Self, Error> {
        self.combine(rhs, |a, b, q| (a + b) % q)
    }

    /// Subtracts polynomials, rejecting a ring mismatch.
    pub fn subtract(&self, rhs: &Self) -> Result<Self, Error> {
        self.combine(rhs, |a, b, q| (a + q - b) % q)
    }

    /// Multiplies by a signed scalar modulo q.
    pub fn scale(&self, scalar: i64) -> Self {
        let scalar = scalar.rem_euclid(self.ring.modulus as i64) as u128;
        Self {
            ring: self.ring,
            coefficients: self
                .coefficients
                .iter()
                .map(|&x| (u128::from(x) * scalar % u128::from(self.ring.modulus)) as u64)
                .collect(),
        }
    }

    /// Multiplies using schoolbook negacyclic convolution in O(n²) time.
    ///
    /// Ring bounds keep every signed accumulator strictly inside i128. This is
    /// also the independent correctness oracle for an optimized backend.
    pub fn multiply(&self, rhs: &Self) -> Result<Self, Error> {
        self.ensure_same_ring(rhs)?;
        let n = self.ring.degree;
        let mut product = Zeroizing::new(vec![0_i128; n]);
        for (i, &a) in self.coefficients.iter().enumerate() {
            for (j, &b) in rhs.coefficients.iter().enumerate() {
                let term = i128::from(a) * i128::from(b);
                if i + j < n {
                    product[i + j] += term;
                } else {
                    product[i + j - n] -= term;
                }
            }
        }
        Ok(Self {
            ring: self.ring,
            coefficients: product
                .iter()
                .map(|&x| x.rem_euclid(i128::from(self.ring.modulus)) as u64)
                .collect(),
        })
    }

    /// Multiplies by a signed monomial `(-1)^negative * X^degree`.
    pub fn monomial(&self, degree: usize, negative: bool) -> Result<Self, Error> {
        if degree >= self.ring.degree {
            return Err(Error::Monomial);
        }
        let mut result = self.ring.zero();
        for (i, &x) in self.coefficients.iter().enumerate() {
            let position = i + degree;
            let negate = negative ^ (position >= self.ring.degree);
            result.coefficients[position % self.ring.degree] = if negate && x != 0 {
                self.ring.modulus - x
            } else {
                x
            };
        }
        Ok(result)
    }

    /// Rounds nonnegative representatives with half-up ties, without reduction.
    ///
    /// The output is an integer vector, not a polynomial modulo q_nu.
    pub fn round(&self, bits: u32) -> Result<Vec<u64>, Error> {
        let scale = self.ring.rounding_scale(bits)?;
        Ok(self
            .coefficients
            .iter()
            .map(|&x| (x + scale / 2) / scale)
            .collect())
    }

    /// Rejects operands from a different ring.
    fn ensure_same_ring(&self, rhs: &Self) -> Result<(), Error> {
        if self.ring != rhs.ring {
            Err(Error::RingMismatch)
        } else {
            Ok(())
        }
    }

    /// Applies a coefficient-wise binary operation to compatible operands.
    fn combine(&self, rhs: &Self, operation: impl Fn(u64, u64, u64) -> u64) -> Result<Self, Error> {
        self.ensure_same_ring(rhs)?;
        Ok(Self {
            ring: self.ring,
            coefficients: self
                .coefficients
                .iter()
                .zip(rhs.coefficients.iter())
                .map(|(&a, &b)| operation(a, b, self.ring.modulus))
                .collect(),
        })
    }
}
