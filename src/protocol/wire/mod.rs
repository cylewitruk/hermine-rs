//! Bounded, canonical version-1 transport encoding with pinned parameters.
//!
//! This is a local format, not an official Hermine wire standard. Public packets
//! do not provide transport authentication. Confidential refresh packets must be
//! encrypted and delivered to their intended owner. Secret shares and nonces have
//! no serialization API because their persistence requires durable replay control.

use std::{error, fmt};

use super::Error as ProtocolError;
use crate::{encoding, parameters::Parameters};

mod messages;
mod primitives;

/// A framing, canonicality, resource-limit, or protocol validation failure.
#[derive(Debug)]
pub enum Error {
    /// Packet, message, or indexed-share count exceeds the configured limit.
    Limit,
    /// Input ends before the required fields are complete.
    Truncated,
    /// Bytes follow the canonical end of the packet.
    Trailing,
    /// Magic, version, or message type is incorrect.
    Header,
    /// The packet does not use the caller's pinned parameter configuration.
    Parameters,
    /// A coefficient is outside the required canonical range.
    Coefficient,
    /// Structural, context, or mathematical protocol validation failed.
    Protocol(ProtocolError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit => f.write_str("wire resource limit exceeded"),
            Self::Truncated => f.write_str("truncated wire packet"),
            Self::Trailing => f.write_str("trailing wire bytes"),
            Self::Header => f.write_str("invalid wire header"),
            Self::Parameters => f.write_str("wire parameters do not match pinned configuration"),
            Self::Coefficient => f.write_str("noncanonical wire coefficient"),
            Self::Protocol(e) => e.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Caller-selected limits enforced before variable-size allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum encoded packet size, including the header and parameters.
    pub packet_bytes: usize,
    /// Maximum message bytes embedded in a signing request.
    pub message_bytes: usize,
    /// Maximum total indexed shares when processing a public share collection.
    pub indexed_shares: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            packet_bytes: 16 * 1024 * 1024,
            message_bytes: 1024 * 1024,
            indexed_shares: 65_536,
        }
    }
}

/// A codec pinned to an explicit parameter profile and local resource limits.
#[derive(Clone, Debug)]
pub struct Codec {
    /// Expected parameters, never negotiated from untrusted packet input.
    parameters: Parameters,
    /// Packet and allocation policy chosen by the application.
    limits: Limits,
    /// Fixed number of expected indices for each participant.
    counts: Vec<usize>,
}

impl Codec {
    /// Creates a codec; large profiles may require explicit limit increases.
    pub fn new(parameters: Parameters, limits: Limits) -> Self {
        let counts = parameters.config().committee.share_counts();
        Self {
            parameters,
            limits,
            counts,
        }
    }

    /// Borrows the pinned parameter profile.
    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    /// Returns the configured resource limits.
    pub fn limits(&self) -> Limits {
        self.limits
    }
}

/// Confidential encoded transport material, erased on drop.
pub use crate::encoding::SecretPacket;

impl From<encoding::Error> for Error {
    fn from(error: encoding::Error) -> Self {
        match error {
            encoding::Error::Limit => Self::Limit,
            encoding::Error::Truncated => Self::Truncated,
            encoding::Error::Trailing => Self::Trailing,
            encoding::Error::Coefficient => Self::Coefficient,
        }
    }
}
