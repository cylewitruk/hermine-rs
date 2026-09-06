//! Bounded polynomial vectors and matrices for the Hermine linear relations.
//!
//! Every dimension is in `1..=64`. Constructors reject mixed rings and ragged
//! matrices. Arithmetic shares the ring backend's variable-time behavior.

use std::{error, fmt};

use crate::ring::{self, Ntt, NttPolynomial, Polynomial, Ring};

/// An invalid dimension, operand shape, or coefficient ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A dimension is outside `1..=64` or operand dimensions differ.
    Dimension,
    /// A matrix row has a different length than the first row.
    Ragged,
    /// Polynomial arithmetic rejected the operand or parameters.
    Ring(ring::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dimension => f.write_str("invalid or incompatible vector dimension"),
            Self::Ragged => f.write_str("matrix rows have inconsistent lengths"),
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

impl From<ring::Error> for Error {
    fn from(error: ring::Error) -> Self {
        Self::Ring(error)
    }
}

/// A nonempty polynomial column vector with a uniform coefficient ring.
#[derive(Clone, Eq, PartialEq)]
pub struct Vector {
    /// Ring shared by every component.
    ring: Ring,
    /// Components, whose storage is zeroized by Polynomial on drop.
    entries: Box<[Polynomial]>,
}

impl fmt::Debug for Vector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vector")
            .field("ring", &self.ring)
            .field("dimension", &self.dimension())
            .finish_non_exhaustive()
    }
}

impl Vector {
    /// Constructs a vector, validating its dimension and every component ring.
    pub fn new(entries: Vec<Polynomial>) -> Result<Self, Error> {
        check_dimension(entries.len())?;
        let ring = entries[0].ring();
        if entries.iter().any(|entry| entry.ring() != ring) {
            return Err(ring::Error::RingMismatch.into());
        }
        Ok(Self {
            ring,
            entries: entries.into_boxed_slice(),
        })
    }

    /// Constructs a zero vector of a validated dimension.
    pub fn zero(ring: Ring, dimension: usize) -> Result<Self, Error> {
        check_dimension(dimension)?;
        Ok(Self {
            ring,
            entries: (0..dimension).map(|_| ring.zero()).collect(),
        })
    }

    /// Returns the common coefficient ring.
    pub fn ring(&self) -> Ring {
        self.ring
    }

    /// Returns the number of polynomial components.
    pub fn dimension(&self) -> usize {
        self.entries.len()
    }

    /// Borrows the polynomial components.
    pub fn entries(&self) -> &[Polynomial] {
        &self.entries
    }

    /// Returns the exact squared centered Euclidean norm.
    pub fn norm_squared(&self) -> u128 {
        self.entries.iter().map(Polynomial::norm_squared).sum()
    }

    /// Adds compatible vectors component-wise.
    pub fn add(&self, rhs: &Self) -> Result<Self, Error> {
        self.combine(rhs, Polynomial::add)
    }

    /// Subtracts compatible vectors component-wise.
    pub fn subtract(&self, rhs: &Self) -> Result<Self, Error> {
        self.combine(rhs, Polynomial::subtract)
    }

    /// Multiplies each component by a signed integer scalar.
    pub fn scale(&self, scalar: i64) -> Self {
        Self {
            ring: self.ring,
            entries: self
                .entries
                .iter()
                .map(|entry| entry.scale(scalar))
                .collect(),
        }
    }

    /// Multiplies every component by a polynomial in the same ring.
    pub fn multiply_polynomial(&self, scalar: &Polynomial) -> Result<Self, Error> {
        Self::new(
            self.entries
                .iter()
                .map(|entry| entry.multiply(scalar))
                .collect::<Result<_, _>>()?,
        )
    }

    /// Multiplies each component by the same signed monomial.
    pub fn monomial(&self, degree: usize, negative: bool) -> Result<Self, Error> {
        Self::new(
            self.entries
                .iter()
                .map(|entry| entry.monomial(degree, negative))
                .collect::<Result<_, _>>()?,
        )
    }

    /// Computes the additive inner product of compatible vectors.
    pub fn dot(&self, rhs: &Self) -> Result<Polynomial, Error> {
        self.ensure_compatible(rhs)?;
        let mut sum = self.ring.zero();
        for (a, b) in self.entries.iter().zip(&rhs.entries) {
            sum = sum.add(&a.multiply(b)?)?;
        }
        Ok(sum)
    }

    /// Rejects operands with different dimensions or coefficient rings.
    fn ensure_compatible(&self, rhs: &Self) -> Result<(), Error> {
        if self.dimension() != rhs.dimension() {
            return Err(Error::Dimension);
        }
        if self.ring != rhs.ring {
            return Err(ring::Error::RingMismatch.into());
        }
        Ok(())
    }

    /// Applies a checked coefficient operation to corresponding components.
    fn combine(
        &self,
        rhs: &Self,
        operation: impl Fn(&Polynomial, &Polynomial) -> Result<Polynomial, ring::Error>,
    ) -> Result<Self, Error> {
        self.ensure_compatible(rhs)?;
        Ok(Self {
            ring: self.ring,
            entries: self
                .entries
                .iter()
                .zip(&rhs.entries)
                .map(|(a, b)| operation(a, b))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// A nonempty rectangular polynomial matrix in row-major order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Matrix {
    /// Nonempty rows with identical dimensions and rings.
    rows: Box<[Vector]>,
}

impl Matrix {
    /// Validates row counts, column counts, and coefficient rings.
    pub fn new(rows: Vec<Vector>) -> Result<Self, Error> {
        check_dimension(rows.len())?;
        let first = &rows[0];
        for row in &rows {
            if row.dimension() != first.dimension() {
                return Err(Error::Ragged);
            }
            if row.ring() != first.ring() {
                return Err(ring::Error::RingMismatch.into());
            }
        }
        Ok(Self {
            rows: rows.into_boxed_slice(),
        })
    }

    /// Returns the common coefficient ring.
    pub fn ring(&self) -> Ring {
        self.rows[0].ring()
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns the number of columns.
    pub fn column_count(&self) -> usize {
        self.rows[0].dimension()
    }

    /// Borrows the matrix rows in order.
    pub fn rows(&self) -> &[Vector] {
        &self.rows
    }

    /// Multiplies by a column vector using schoolbook ring arithmetic.
    pub fn multiply(&self, vector: &Vector) -> Result<Vector, Error> {
        Vector::new(
            self.rows
                .iter()
                .map(|row| row.dot(vector))
                .collect::<Result<_, _>>()?,
        )
    }

    /// Precomputes this matrix's transform for repeated fast multiplication.
    pub fn transform(&self, ntt: Ntt) -> Result<NttMatrix, Error> {
        if ntt.ring() != self.ring() {
            return Err(ring::Error::RingMismatch.into());
        }
        let rows = self
            .rows
            .iter()
            .map(|row| {
                row.entries
                    .iter()
                    .map(|entry| ntt.forward(entry))
                    .collect::<Result<Box<[_]>, _>>()
            })
            .collect::<Result<_, _>>()?;
        Ok(NttMatrix { ntt, rows })
    }
}

/// A precomputed matrix used for repeated NTT matrix-vector products.
#[derive(Clone)]
pub struct NttMatrix {
    /// Transform parameters shared by all entries.
    ntt: Ntt,
    /// Rectangular matrix of transformed polynomials.
    rows: Box<[Box<[NttPolynomial]>]>,
}

impl fmt::Debug for NttMatrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NttMatrix")
            .field("ring", &self.ntt.ring())
            .field("rows", &self.rows.len())
            .field("columns", &self.rows[0].len())
            .finish_non_exhaustive()
    }
}

impl NttMatrix {
    /// Multiplies by a coefficient-domain vector, returning coefficient form.
    pub fn multiply(&self, vector: &Vector) -> Result<Vector, Error> {
        if vector.dimension() != self.rows[0].len() {
            return Err(Error::Dimension);
        }
        if vector.ring != self.ntt.ring() {
            return Err(ring::Error::RingMismatch.into());
        }
        let transformed = vector
            .entries
            .iter()
            .map(|entry| self.ntt.forward(entry))
            .collect::<Result<Vec<_>, _>>()?;
        let mut output = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let mut sum = row[0].multiply(&transformed[0])?;
            for (a, b) in row[1..].iter().zip(&transformed[1..]) {
                sum = sum.add(&a.multiply(b)?)?;
            }
            output.push(self.ntt.inverse(&sum)?);
        }
        Vector::new(output)
    }
}

/// Checks bounds before allocation or first-element indexing.
fn check_dimension(dimension: usize) -> Result<(), Error> {
    if !(1..=64).contains(&dimension) {
        Err(Error::Dimension)
    } else {
        Ok(())
    }
}
