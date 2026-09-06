//! Fixed-layout message encodings and structural checks shared by both variants.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::{Codec, Error, SecretPacket};
use crate::{
    Identifier,
    dkg::{Contribution, PrivateContribution, PrivateShare, VerificationMessage},
    encoding,
    linear::Vector,
    ring::Polynomial,
    sharing::Index,
};

/// Six-byte marker/version/kind followed by the 64-byte pinned context.
const HEADER: usize = 70;
/// First-round public projected sharing.
const CONTRIBUTION: u8 = 1;
/// First-round confidential recipient opening.
const PRIVATE: u8 = 2;
/// Second-round public verification shares and agreement digest.
const VERIFICATION: u8 = 3;

/// Shared byte writer using DKG transport errors.
type Writer = encoding::Writer<Error>;
/// Shared byte reader using DKG transport errors.
type Reader<'a> = encoding::Reader<'a, Error>;

impl Codec {
    /// Encodes a structurally valid first broadcast; round verification is separate.
    pub fn encode_contribution(&self, message: &Contribution) -> Result<Vec<u8>, Error> {
        let size = self.contribution_size()?;
        self.check_context(&message.context)?;
        self.party(message.contributor)?;
        let n = self.layout.len();
        if message.commitments.len() != n || message.projected.len() != n {
            return Err(Error::Shape);
        }
        let ring = self.config.sharing.projection.response_ring();
        for (expected, actual) in self.layout.iter().zip(&message.projected) {
            if !actual.keys().eq(expected.keys()) || actual.values().any(|p| p.ring() != ring) {
                return Err(Error::Shape);
            }
        }
        let mut writer = self.writer(CONTRIBUTION, size)?;
        writer.bytes(&[message.contributor])?;
        for commitment in &message.commitments {
            writer.bytes(commitment)?;
        }
        for polynomial in message.projected.iter().flat_map(|p| p.values()) {
            writer.row(polynomial.coefficients(), ring.modulus())?;
        }
        Ok(writer.finish())
    }

    /// Decodes a first broadcast bound to its authenticated sender and this session.
    ///
    /// Does not run VandCheck or prove any commitment opening or norm statement.
    pub fn decode_contribution(&self, sender: u8, bytes: &[u8]) -> Result<Contribution, Error> {
        self.party(sender)?;
        let size = self.contribution_size()?;
        let mut reader = self.reader(CONTRIBUTION, size, bytes)?;
        if reader.array::<1>()?[0] != sender {
            return Err(Error::Participant);
        }
        let commitments = (0..self.layout.len())
            .map(|_| reader.array())
            .collect::<Result<_, _>>()?;
        let ring = self.config.sharing.projection.response_ring();
        let projected = self
            .layout
            .iter()
            .map(|paths| {
                paths
                    .keys()
                    .map(|index| Ok((index.clone(), reader.polynomial(ring)?)))
                    .collect()
            })
            .collect::<Result<_, Error>>()?;
        reader.finish()?;
        Ok(Contribution {
            context: self.context,
            contributor: sender,
            commitments,
            projected,
        })
    }

    /// Encodes a confidential payload after checking its context, layout, and bound.
    ///
    /// This does not check the public statement or opening equation. The entire
    /// output allocation is reserved before any secret bytes are written.
    pub fn encode_private_contribution(
        &self,
        message: &PrivateContribution,
    ) -> Result<SecretPacket, Error> {
        self.check_context(&message.context)?;
        self.party(message.contributor)?;
        let size = self.private_size(message.recipient)?;
        let paths = &self.layout[self.party(message.recipient)?];
        if !message.shares.keys().eq(paths.keys()) {
            return Err(Error::Shape);
        }
        for share in message.shares.values() {
            self.check_private_share(share)?;
        }
        let mut writer = self.writer(PRIVATE, size)?;
        writer.bytes(&[message.contributor, message.recipient])?;
        writer.bytes(&message.statement)?;
        writer.bytes(message.salt.as_slice())?;
        let q = self.config.sharing.projection.ring().modulus();
        for share in message.shares.values() {
            for input in &share.input {
                writer.row(input.coefficients(), q)?;
            }
            writer.row(share.mask.coefficients(), q)?;
        }
        Ok(writer.finish_secret())
    }

    /// Decodes a confidential payload for a fixed authenticated sender and recipient.
    ///
    /// The caller must erase its input buffer. Acceptance still requires the
    /// consuming round's statement, commitment-opening, and equation checks.
    pub fn decode_private_contribution(
        &self,
        sender: u8,
        recipient: u8,
        bytes: &[u8],
    ) -> Result<PrivateContribution, Error> {
        self.party(sender)?;
        let size = self.private_size(recipient)?;
        let mut reader = self.reader(PRIVATE, size, bytes)?;
        if reader.array::<2>()? != [sender, recipient] {
            return Err(Error::Participant);
        }
        let statement = reader.array()?;
        let mut salt = Zeroizing::new([0; 32]);
        salt.copy_from_slice(reader.bytes(32)?);
        let p = self.config.sharing.projection;
        let shares = self.layout[self.party(recipient)?]
            .keys()
            .map(|index| {
                let input = (0..p.components())
                    .map(|_| reader.polynomial(p.ring()))
                    .collect::<Result<_, _>>()?;
                let mask = reader.polynomial(p.response_ring())?;
                let share = PrivateShare { input, mask };
                self.check_private_share(&share)?;
                Ok((index.clone(), share))
            })
            .collect::<Result<_, Error>>()?;
        reader.finish()?;
        Ok(PrivateContribution {
            context: self.context,
            contributor: sender,
            recipient,
            statement,
            salt,
            shares,
        })
    }

    /// Encodes a second broadcast after validating its sender and indexed shapes.
    pub fn encode_verification(&self, message: &VerificationMessage) -> Result<Vec<u8>, Error> {
        let size = self.verification_size(message.participant)?;
        self.check_verification(message.participant, &message.shares)?;
        let mut writer = self.writer(VERIFICATION, size)?;
        writer.bytes(&[message.participant])?;
        writer.bytes(&message.agreement)?;
        let q = self.config.sharing.projection.ring().modulus();
        for polynomial in message.shares.values().flat_map(Vector::entries) {
            writer.row(polynomial.coefficients(), q)?;
        }
        Ok(writer.finish())
    }

    /// Decodes a second broadcast; the consumed round checks its agreement and images.
    pub fn decode_verification(
        &self,
        sender: u8,
        bytes: &[u8],
    ) -> Result<VerificationMessage, Error> {
        let size = self.verification_size(sender)?;
        let mut reader = self.reader(VERIFICATION, size, bytes)?;
        if reader.array::<1>()?[0] != sender {
            return Err(Error::Participant);
        }
        let agreement = reader.array()?;
        let p = self.config.sharing.projection;
        let rows = p.components() - self.config.columns;
        let shares = self.layout[self.party(sender)?]
            .keys()
            .map(|index| {
                let entries = (0..rows)
                    .map(|_| reader.polynomial(p.ring()))
                    .collect::<Result<_, _>>()?;
                let vector = Vector::new(entries).map_err(|_| Error::Shape)?;
                Ok((index.clone(), vector))
            })
            .collect::<Result<_, Error>>()?;
        reader.finish()?;
        Ok(VerificationMessage {
            participant: sender,
            agreement,
            shares,
        })
    }

    /// Validates a one-based identity before converting it to a layout index.
    fn party(&self, participant: u8) -> Result<usize, Error> {
        if participant == 0 || usize::from(participant) > self.layout.len() {
            return Err(Error::Participant);
        }
        Ok(usize::from(participant - 1))
    }

    /// Requires the full pinned session/configuration identity.
    fn check_context(&self, context: &Identifier) -> Result<(), Error> {
        if context != &self.context {
            return Err(Error::Binding);
        }
        Ok(())
    }

    /// Checks one input/mask shape and the direct private input coefficient bound.
    fn check_private_share(&self, share: &PrivateShare) -> Result<(), Error> {
        let c = self.config.sharing;
        let p = c.projection;
        if share.input.len() != p.components()
            || share.mask.ring() != p.response_ring()
            || share.input.iter().any(|v| v.ring() != p.ring())
        {
            return Err(Error::Shape);
        }
        if share
            .input
            .iter()
            .flat_map(Polynomial::centered)
            .any(|v| v.unsigned_abs() > c.private_limit)
        {
            return Err(Error::PrivateBound);
        }
        Ok(())
    }

    /// Checks exact path, ring, and row dimensions of a public image collection.
    fn check_verification(
        &self,
        sender: u8,
        shares: &BTreeMap<Index, Vector>,
    ) -> Result<(), Error> {
        let p = self.config.sharing.projection;
        if !shares.keys().eq(self.layout[self.party(sender)?].keys())
            || shares.values().any(|v| {
                v.ring() != p.ring() || v.dimension() != p.components() - self.config.columns
            })
        {
            return Err(Error::Shape);
        }
        Ok(())
    }

    /// Computes and checks the full fixed-size contribution packet length.
    fn contribution_size(&self) -> Result<usize, Error> {
        self.size(1 + 64 * self.layout.len(), self.count, 256)
    }

    /// Computes and checks one recipient's fixed-size confidential packet length.
    fn private_size(&self, recipient: u8) -> Result<usize, Error> {
        let count = self.layout[self.party(recipient)?].len();
        self.size(98, count, self.config.sharing.projection.columns() + 256)
    }

    /// Computes and checks one sender's fixed-size verification packet length.
    fn verification_size(&self, sender: u8) -> Result<usize, Error> {
        let p = self.config.sharing.projection;
        let coordinates = (p.components() - self.config.columns) * p.ring().degree();
        self.size(65, self.layout[self.party(sender)?].len(), coordinates)
    }

    /// Uses checked arithmetic and applies the limit before any message allocation.
    fn size(&self, metadata: usize, shares: usize, coordinates: usize) -> Result<usize, Error> {
        let size = shares
            .checked_mul(coordinates)
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(metadata))
            .and_then(|n| n.checked_add(HEADER))
            .ok_or(Error::Limit)?;
        if size > self.limits.packet_bytes {
            return Err(Error::Limit);
        }
        Ok(size)
    }

    /// Reserves an entire bounded output before writing its header or private body.
    fn writer(&self, kind: u8, size: usize) -> Result<Writer, Error> {
        let mut writer = Writer::with_limit(self.limits.packet_bytes);
        writer.reserve_body(size)?;
        writer.bytes(&[b'H', b'R', b'D', b'K', 1, kind])?;
        writer.bytes(&self.context)?;
        Ok(writer)
    }

    /// Checks exact packet length and framing before allocating coefficients or paths.
    fn reader<'a>(&self, kind: u8, size: usize, bytes: &'a [u8]) -> Result<Reader<'a>, Error> {
        if bytes.len() > self.limits.packet_bytes {
            return Err(Error::Limit);
        }
        if bytes.len() < size {
            return Err(Error::Truncated);
        }
        if bytes.len() > size {
            return Err(Error::Trailing);
        }
        let mut reader = Reader::from_bytes(bytes);
        if reader.bytes(6)? != [b'H', b'R', b'D', b'K', 1, kind] {
            return Err(Error::Header);
        }
        self.check_context(&reader.array()?)?;
        Ok(reader)
    }
}
