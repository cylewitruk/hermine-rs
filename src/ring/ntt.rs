//! Twisted radix-two transforms for negacyclic multiplication.

use std::fmt;

use zeroize::Zeroize;

use super::{Error, Polynomial, Ring};

/// A reusable negacyclic number theoretic transform.
///
/// The caller supplies a primitive 2n-th root of unity. The power-of-two degree
/// and odd modulus make `root^n = -1` sufficient for this transform. Construction
/// does not certify primality or the cryptographic suitability of the modulus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ntt {
    /// Coefficient ring.
    ring: Ring,
    /// Primitive 2n-th root of unity.
    root: u64,
    /// Powers of the root for twisting polynomial coefficients.
    twist: Vec<u64>,
    /// Powers of the inverse root for untwisting coefficients.
    inverse_twist: Vec<u64>,
    /// Inverse of n modulo q.
    inverse_degree: u64,
}

impl Ntt {
    /// Validates the root and precomputes forward and inverse twists.
    pub fn new(ring: Ring, root: u64) -> Result<Self, Error> {
        if root >= ring.modulus || power(root, ring.degree as u64, ring.modulus) != ring.modulus - 1
        {
            return Err(Error::Root);
        }
        let inverse_root = power(root, 2 * ring.degree as u64 - 1, ring.modulus);
        let powers = |base| {
            let mut value = 1;
            (0..ring.degree)
                .map(|_| {
                    let current = value;
                    value = product(value, base, ring.modulus);
                    current
                })
                .collect()
        };
        Ok(Self {
            ring,
            root,
            twist: powers(root),
            inverse_twist: powers(inverse_root),
            inverse_degree: power(
                ring.modulus.div_ceil(2),
                u64::from(ring.degree.ilog2()),
                ring.modulus,
            ),
        })
    }

    /// Returns the coefficient ring.
    pub fn ring(&self) -> Ring {
        self.ring
    }

    /// Returns the chosen primitive root.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Transforms a polynomial, rejecting incompatible rings.
    pub fn forward(&self, polynomial: &Polynomial) -> Result<NttPolynomial, Error> {
        if polynomial.ring != self.ring {
            return Err(Error::RingMismatch);
        }
        let mut result = NttPolynomial {
            ring: self.ring,
            root: self.root,
            coefficients: polynomial
                .coefficients
                .iter()
                .zip(&self.twist)
                .map(|(&a, &b)| product(a, b, self.ring.modulus))
                .collect(),
        };
        self.transform(
            &mut result.coefficients,
            product(self.root, self.root, self.ring.modulus),
        );
        Ok(result)
    }

    /// Inverts a transform, rejecting a different ring or root.
    pub fn inverse(&self, polynomial: &NttPolynomial) -> Result<Polynomial, Error> {
        if polynomial.ring != self.ring || polynomial.root != self.root {
            return Err(Error::TransformMismatch);
        }
        let mut result = Polynomial {
            ring: self.ring,
            coefficients: polynomial.coefficients.clone(),
        };
        let inverse_root = self.inverse_twist[1];
        self.transform(
            &mut result.coefficients,
            product(inverse_root, inverse_root, self.ring.modulus),
        );
        for (coefficient, &twist) in result.coefficients.iter_mut().zip(&self.inverse_twist) {
            *coefficient = product(
                product(*coefficient, twist, self.ring.modulus),
                self.inverse_degree,
                self.ring.modulus,
            );
        }
        Ok(result)
    }

    /// Multiplies two coefficient polynomials in O(n log n) time.
    pub fn multiply(&self, lhs: &Polynomial, rhs: &Polynomial) -> Result<Polynomial, Error> {
        self.inverse(&self.forward(lhs)?.multiply(&self.forward(rhs)?)?)
    }

    /// Computes an in-place radix-two cyclic transform in natural output order.
    fn transform(&self, coefficients: &mut [u64], root: u64) {
        let n = self.ring.degree;
        let q = self.ring.modulus;
        for i in 0..n {
            let reversed = i.reverse_bits() >> (usize::BITS - n.ilog2());
            if i < reversed {
                coefficients.swap(i, reversed);
            }
        }
        let mut width = 2;
        while width <= n {
            let step = power(root, (n / width) as u64, q);
            for block in coefficients.chunks_exact_mut(width) {
                let (left, right) = block.split_at_mut(width / 2);
                let mut twiddle = 1;
                for (a, b) in left.iter_mut().zip(right) {
                    let u = *a;
                    let v = product(*b, twiddle, q);
                    *a = (u + v) % q;
                    *b = (u + q - v) % q;
                    twiddle = product(twiddle, step, q);
                }
            }
            width *= 2;
        }
    }
}

/// A polynomial in the transform domain with an explicit ring and root identity.
///
/// Storage is zeroized on drop and Debug omits transformed coefficients.
#[derive(Clone, Eq, PartialEq)]
pub struct NttPolynomial {
    /// Coefficient ring of the source polynomial.
    ring: Ring,
    /// Primitive root used by the transform.
    root: u64,
    /// Transformed coefficients in natural evaluation order.
    coefficients: Box<[u64]>,
}

impl fmt::Debug for NttPolynomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NttPolynomial")
            .field("ring", &self.ring)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl Drop for NttPolynomial {
    fn drop(&mut self) {
        self.coefficients.zeroize();
    }
}

impl NttPolynomial {
    /// Adds compatible transformed polynomials coefficient-wise.
    pub fn add(&self, rhs: &Self) -> Result<Self, Error> {
        if self.ring != rhs.ring || self.root != rhs.root {
            return Err(Error::TransformMismatch);
        }
        Ok(Self {
            ring: self.ring,
            root: self.root,
            coefficients: self
                .coefficients
                .iter()
                .zip(rhs.coefficients.iter())
                .map(|(&a, &b)| (a + b) % self.ring.modulus)
                .collect(),
        })
    }

    /// Multiplies compatible transformed polynomials coefficient-wise.
    pub fn multiply(&self, rhs: &Self) -> Result<Self, Error> {
        if self.ring != rhs.ring || self.root != rhs.root {
            return Err(Error::TransformMismatch);
        }
        Ok(Self {
            ring: self.ring,
            root: self.root,
            coefficients: self
                .coefficients
                .iter()
                .zip(rhs.coefficients.iter())
                .map(|(&a, &b)| product(a, b, self.ring.modulus))
                .collect(),
        })
    }
}

/// Computes a modular product without losing high bits.
fn product(a: u64, b: u64, modulus: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(modulus)) as u64
}

/// Computes a modular power with public exponents.
fn power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = product(result, base, modulus);
        }
        base = product(base, base, modulus);
        exponent >>= 1;
    }
    result
}
