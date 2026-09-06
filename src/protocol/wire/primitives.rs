//! Fixed-width framing and checked coefficient IO.

use std::mem;

use super::super::support;
use super::{Codec, Error, ProtocolError};
use crate::{encoding, linear::Vector, ring::Ring};

/// Version-1 packet types; values are permanent within this local format.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Kind {
    /// Long-term verification key.
    PublicKey = 1,
    /// Full per-epoch public package.
    PublicPackage = 2,
    /// A participant's public preprocessing token.
    Commitment = 3,
    /// Common message and selected preprocessing tokens.
    SigningPackage = 4,
    /// A participant's response.
    PartialSignature = 5,
    /// An aggregate signature.
    Signature = 6,
    /// Proposed public verification shares for the next epoch.
    RefreshProposal = 7,
    /// Confidential indexed refresh increments.
    RefreshToken = 8,
}

/// Protocol writer backed by the shared bounded byte buffer.
pub type Writer = encoding::Writer<Error>;
/// Protocol reader backed by the shared checked input cursor.
pub type Reader<'a> = encoding::Reader<'a, Error>;

impl Writer {
    /// Writes the format marker, type, and complete pinned parameter encoding.
    pub fn new(codec: &Codec, kind: Kind) -> Result<Self, Error> {
        let mut writer = Self::with_limit(codec.limits.packet_bytes);
        writer.bytes(&[b'H', b'R', b'M', b'N', 1, kind as u8])?;
        writer.bytes(&codec.parameters.to_bytes())?;
        Ok(writer)
    }

    /// Appends a canonical rectangular matrix with implicit, validated dimensions.
    pub fn coefficients(
        &mut self,
        values: &[Vec<u64>],
        ring: Ring,
        rows: usize,
        bound: u64,
    ) -> Result<(), Error> {
        if values.len() != rows || values.iter().any(|row| row.len() != ring.degree()) {
            return Err(ProtocolError::Malformed.into());
        }
        for row in values {
            self.row(row, bound)?;
        }
        Ok(())
    }

    /// Appends a fixed-dimension ring vector without temporary coefficient copies.
    pub fn vector(&mut self, vector: &Vector, ring: Ring, dimension: usize) -> Result<(), Error> {
        support::validate_vector(vector, ring, dimension)?;
        for polynomial in vector.entries() {
            self.row(polynomial.coefficients(), ring.modulus())?;
        }
        Ok(())
    }
}

impl<'a> Reader<'a> {
    /// Validates framing, limits, and pinned parameters before reading any body.
    pub fn new(codec: &Codec, kind: Kind, bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > codec.limits.packet_bytes {
            return Err(Error::Limit);
        }
        let mut reader = Self::from_bytes(bytes);
        if reader.bytes(6)? != [b'H', b'R', b'M', b'N', 1, kind as u8] {
            return Err(Error::Header);
        }
        let expected = codec.parameters.to_bytes();
        if reader.bytes(expected.len())? != expected {
            return Err(Error::Parameters);
        }
        Ok(reader)
    }

    /// Reads a checked coefficient matrix with dimensions supplied by the profile.
    pub fn coefficients(
        &mut self,
        ring: Ring,
        rows: usize,
        bound: u64,
    ) -> Result<Vec<Vec<u64>>, Error> {
        self.require(byte_count(rows, ring.degree())?)?;
        (0..rows)
            .map(|_| Ok(mem::take(&mut *self.row(ring.degree(), bound)?)))
            .collect()
    }

    /// Reads a ring vector, erasing temporary coefficient buffers even on failure.
    pub fn vector(&mut self, ring: Ring, dimension: usize) -> Result<Vector, Error> {
        self.require(byte_count(dimension, ring.degree())?)?;
        let entries = (0..dimension)
            .map(|_| self.polynomial(ring))
            .collect::<Result<_, _>>()?;
        Vector::new(entries).map_err(|e| ProtocolError::from(e).into())
    }
}

/// Computes a coefficient section's size without overflowing host integers.
pub fn byte_count(rows: usize, degree: usize) -> Result<usize, Error> {
    rows.checked_mul(degree)
        .and_then(|n| n.checked_mul(8))
        .ok_or(Error::Limit)
}
