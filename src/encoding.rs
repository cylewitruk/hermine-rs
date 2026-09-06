//! Shared bounded byte I/O for separately framed protocol codecs.

use std::{fmt, marker::PhantomData, mem};

use zeroize::Zeroizing;

use crate::ring::{Polynomial, Ring};

/// Primitive encoding failures translated into each protocol's public error.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Output exceeds its configured bound or a byte count overflows.
    Limit,
    /// Input does not contain the requested bytes.
    Truncated,
    /// Input contains bytes beyond the canonical object.
    Trailing,
    /// A coefficient is not a canonical residue.
    Coefficient,
}

/// Confidential transport bytes whose owned allocation zeroizes on drop.
///
/// Neither Clone nor exposed through Debug. Applications must protect and erase
/// any copies they make, including decrypted input buffers supplied to decoders.
///
/// ```rust,compile_fail
/// use hermine::wire::SecretPacket;
/// fn duplicate(packet: SecretPacket) { let _ = packet.clone(); }
/// ```
pub struct SecretPacket {
    /// Owned confidential payload.
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretPacket {
    /// Borrows the payload for a confidential authenticated transport.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SecretPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPacket")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Bounded output with error translation and erasure on incomplete encoding.
pub struct Writer<E> {
    /// Bytes accumulated so far.
    bytes: Zeroizing<Vec<u8>>,
    /// Absolute packet size limit.
    limit: usize,
    /// Error type supplied by the enclosing protocol codec.
    error: PhantomData<E>,
}

impl<E: From<Error>> Writer<E> {
    /// Creates an empty buffer with a caller-selected absolute byte limit.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            limit,
            error: PhantomData,
        }
    }

    /// Reserves the entire confidential section before writing its secret bytes.
    pub fn reserve_body(&mut self, length: usize) -> Result<(), E> {
        if length > self.limit.saturating_sub(self.bytes.len()) {
            return Err(Error::Limit.into());
        }
        self.bytes.reserve_exact(length);
        Ok(())
    }

    /// Appends bytes after checking the resulting packet size.
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), E> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(Error::Limit.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends a little-endian unsigned 64-bit value.
    pub fn u64(&mut self, value: u64) -> Result<(), E> {
        self.bytes(&value.to_le_bytes())
    }

    /// Appends coefficients after checking their canonical representatives.
    pub fn row(&mut self, row: &[u64], bound: u64) -> Result<(), E> {
        for &value in row {
            if value >= bound {
                return Err(Error::Coefficient.into());
            }
            self.u64(value)?;
        }
        Ok(())
    }

    /// Releases a completed public packet.
    pub fn finish(mut self) -> Vec<u8> {
        mem::take(&mut *self.bytes)
    }

    /// Releases a completed confidential packet, preserving erasure ownership.
    pub fn finish_secret(self) -> SecretPacket {
        SecretPacket { bytes: self.bytes }
    }
}

/// Borrowed input cursor with checks before reads and coefficient allocations.
pub struct Reader<'a, E> {
    /// Unconsumed input bytes.
    remaining: &'a [u8],
    /// Error type supplied by the enclosing protocol codec.
    error: PhantomData<E>,
}

impl<'a, E: From<Error>> Reader<'a, E> {
    /// Creates a cursor; the enclosing codec must first enforce packet limits.
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            error: PhantomData,
        }
    }

    /// Checks that an entire fixed section exists before allocating its objects.
    pub fn require(&self, length: usize) -> Result<(), E> {
        if length > self.remaining.len() {
            return Err(Error::Truncated.into());
        }
        Ok(())
    }

    /// Borrows and consumes a checked number of input bytes.
    pub fn bytes(&mut self, length: usize) -> Result<&'a [u8], E> {
        self.require(length)?;
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    /// Reads a fixed-size byte array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], E> {
        let mut value = [0; N];
        value.copy_from_slice(self.bytes(N)?);
        Ok(value)
    }

    /// Reads a little-endian unsigned 64-bit value.
    pub fn u64(&mut self) -> Result<u64, E> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Reads canonical coefficients into an allocation erased on drop.
    pub fn row(&mut self, degree: usize, bound: u64) -> Result<Zeroizing<Vec<u64>>, E> {
        self.require(degree.checked_mul(8).ok_or(Error::Limit)?)?;
        let mut row = Zeroizing::new(Vec::with_capacity(degree));
        for _ in 0..degree {
            let value = self.u64()?;
            if value >= bound {
                return Err(Error::Coefficient.into());
            }
            row.push(value);
        }
        Ok(row)
    }

    /// Reads a polynomial with canonical residues and zeroizing temporaries.
    pub fn polynomial(&mut self, ring: Ring) -> Result<Polynomial, E> {
        let row = self.row(ring.degree(), ring.modulus())?;
        ring.polynomial(&row).map_err(|_| Error::Coefficient.into())
    }

    /// Rejects suffixes after the complete object.
    pub fn finish(self) -> Result<(), E> {
        if !self.remaining.is_empty() {
            return Err(Error::Trailing.into());
        }
        Ok(())
    }
}
