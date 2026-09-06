//! Canonical bounded DKG message transport, pinned to an existing session.
//!
//! Decoding validates framing, identities, shapes, and private coefficient limits.
//! Messages remain untrusted: consumed rounds must check commitments, equations,
//! consistency, and agreement. Senders come from authenticated transport metadata;
//! private packets require confidential delivery and caller-owned input erasure.

use std::{error, fmt, sync::Arc};

use super::{DkgConfig, DkgSession};
use crate::{Identifier, encoding, sharing::Shares};

mod messages;

/// Confidential encoded material whose owned allocation erases on drop.
pub use crate::encoding::SecretPacket;

/// DKG transport framing, allocation, or structural validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Packet size or indexed-path allocation exceeds the caller's limits.
    Limit,
    /// The input does not contain the entire canonical packet.
    Truncated,
    /// Bytes follow the canonical packet.
    Trailing,
    /// Magic, version, or message kind differs from the requested type.
    Header,
    /// The packet or object belongs to a different pinned DKG session.
    Binding,
    /// A sender or recipient is invalid or differs from transport metadata.
    Participant,
    /// The object has incorrect paths, dimensions, or polynomial rings.
    Shape,
    /// A coefficient is not a canonical residue modulo q.
    Coefficient,
    /// A confidential input share exceeds the session's coefficient limit.
    PrivateBound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit => "DKG wire resource limit exceeded",
            Self::Truncated => "truncated DKG wire packet",
            Self::Trailing => "trailing DKG wire bytes",
            Self::Header => "invalid DKG wire header",
            Self::Binding => "DKG wire session mismatch",
            Self::Participant => "DKG wire transport identity mismatch",
            Self::Shape => "malformed DKG wire object",
            Self::Coefficient => "noncanonical DKG wire coefficient",
            Self::PrivateBound => "DKG wire input exceeds private coefficient limit",
        })
    }
}

impl error::Error for Error {}

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

/// Explicit local packet and path-allocation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum bytes in one packet, including all framing.
    pub packet_bytes: usize,
    /// Maximum total indexed paths in the pinned committee layout.
    pub indexed_shares: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            packet_bytes: 16 * 1024 * 1024,
            indexed_shares: 65_536,
        }
    }
}

/// Codec bound to validated local configuration; packets cannot negotiate it.
#[derive(Clone, Debug)]
pub struct Codec {
    /// Configuration established before transport processing.
    config: DkgConfig,
    /// Context binding every parameter, mask variant, and common session.
    context: Identifier,
    /// Caller-selected transport limits.
    limits: Limits,
    /// Expected canonical path order, bounded before allocation.
    layout: Arc<Shares<()>>,
    /// Total number of indexed paths across all recipients.
    count: usize,
}

impl Codec {
    /// Pins a validated session and checks path limits before allocating a layout.
    pub fn new(session: &DkgSession, limits: Limits) -> Result<Self, Error> {
        let config = session.config();
        let count = config
            .sharing
            .committee
            .share_counts()
            .iter()
            .try_fold(0_usize, |sum, count| sum.checked_add(*count))
            .ok_or(Error::Limit)?;
        if count > limits.indexed_shares {
            return Err(Error::Limit);
        }
        Ok(Self {
            config,
            context: *session.id(),
            limits,
            count,
            layout: Arc::new(config.sharing.committee.layout()),
        })
    }

    /// Returns the pinned configuration.
    pub fn config(&self) -> DkgConfig {
        self.config
    }

    /// Borrows the session identity required in every packet.
    pub fn session_id(&self) -> &Identifier {
        &self.context
    }

    /// Returns the local resource limits.
    pub fn limits(&self) -> Limits {
        self.limits
    }
}
