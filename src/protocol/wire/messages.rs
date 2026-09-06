//! Message codecs that rebuild validated protocol state from canonical fields.

use std::{collections::BTreeMap, sync::Arc};

use super::super::{
    Commitment, PartialSignature, PublicKey, PublicKeyPackage, RefreshProposal, RefreshToken,
    Signature, SigningPackage, VerifiedRefresh, support,
};
use super::{
    Codec, Error, ProtocolError, SecretPacket,
    primitives::{self, Kind, Reader, Writer},
};
use crate::{
    linear::{Matrix, Vector},
    sharing::Shares,
};

impl Codec {
    /// Encodes a long-term verification key under this codec's pinned profile.
    pub fn encode_public_key(&self, key: &PublicKey) -> Result<Vec<u8>, Error> {
        self.check_key(key)?;
        let mut writer = Writer::new(self, Kind::PublicKey)?;
        self.write_key(&mut writer, key)?;
        Ok(writer.finish())
    }

    /// Decodes a canonical key; its provenance must still be authenticated.
    pub fn decode_public_key(&self, bytes: &[u8]) -> Result<PublicKey, Error> {
        let mut reader = Reader::new(self, Kind::PublicKey, bytes)?;
        let key = self.read_key(&mut reader)?;
        reader.finish()?;
        Ok(key)
    }

    /// Encodes the key, epoch, and complete indexed verification material.
    pub fn encode_public_package(&self, keys: &PublicKeyPackage) -> Result<Vec<u8>, Error> {
        self.check_key(&keys.key)?;
        self.check_body_size(self.public_package_size()?)?;
        let mut writer = Writer::new(self, Kind::PublicPackage)?;
        self.write_key(&mut writer, &keys.key)?;
        writer.u64(keys.epoch)?;
        self.write_shares(&mut writer, &keys.verification_shares)?;
        Ok(writer.finish())
    }

    /// Validates all public reconstructions and their rounded long-term key.
    pub fn decode_public_package(&self, bytes: &[u8]) -> Result<PublicKeyPackage, Error> {
        self.share_budget()?;
        let mut reader = Reader::new(self, Kind::PublicPackage, bytes)?;
        reader.require(self.public_package_size()?)?;
        let key = self.read_key(&mut reader)?;
        let epoch = reader.u64()?;
        if epoch > self.parameters.config().refresh_limit {
            return Err(ProtocolError::EpochMismatch.into());
        }
        let shares = self.read_shares(&mut reader)?;
        reader.finish()?;
        let full_key = support::reconstruct_public(&key, &shares)?;
        #[cfg(feature = "experimental-dkg")]
        if !self.parameters.matches_dkg_full_key(&full_key) {
            return Err(ProtocolError::KeyMismatch.into());
        }
        if support::round(&full_key, self.parameters.config().public_key_bits, false)?
            != key.rounded_key
        {
            return Err(ProtocolError::KeyMismatch.into());
        }
        let mut keys = PublicKeyPackage {
            key: Arc::new(key),
            epoch,
            verification_shares: Arc::new(shares),
            full_key,
            id: [0; 64],
        };
        keys.id = support::package_id(&keys);
        Ok(keys)
    }

    /// Encodes a preprocessing token after checking its public package binding.
    pub fn encode_commitment(
        &self,
        keys: &PublicKeyPackage,
        token: &Commitment,
    ) -> Result<Vec<u8>, Error> {
        self.check_key(&keys.key)?;
        support::validate_commitment(keys, token)?;
        let mut writer = Writer::new(self, Kind::Commitment)?;
        self.write_commitment(&mut writer, token)?;
        Ok(writer.finish())
    }

    /// Decodes and validates a participant's preprocessing token for this epoch.
    pub fn decode_commitment(
        &self,
        keys: &PublicKeyPackage,
        bytes: &[u8],
    ) -> Result<Commitment, Error> {
        self.check_key(&keys.key)?;
        let mut reader = Reader::new(self, Kind::Commitment, bytes)?;
        let token = self.read_commitment(&mut reader)?;
        reader.finish()?;
        support::validate_commitment(keys, &token)?;
        Ok(token)
    }

    /// Encodes only common signing inputs; derived caches are never serialized.
    pub fn encode_signing_package(
        &self,
        keys: &PublicKeyPackage,
        request: &SigningPackage,
    ) -> Result<Vec<u8>, Error> {
        self.check_key(&keys.key)?;
        if request.epoch != keys.epoch {
            return Err(ProtocolError::EpochMismatch.into());
        }
        if request.package_id != keys.id {
            return Err(ProtocolError::KeyMismatch.into());
        }
        if request.message.len() > self.limits.message_bytes {
            return Err(Error::Limit);
        }
        let mut writer = Writer::new(self, Kind::SigningPackage)?;
        writer.u64(request.message.len() as u64)?;
        writer.bytes(&request.message)?;
        for token in &request.commitments {
            self.write_commitment(&mut writer, token)?;
        }
        Ok(writer.finish())
    }

    /// Validates the exact signer set and recomputes all binding factors/challenges.
    pub fn decode_signing_package(
        &self,
        keys: &PublicKeyPackage,
        bytes: &[u8],
    ) -> Result<SigningPackage, Error> {
        self.check_key(&keys.key)?;
        let mut reader = Reader::new(self, Kind::SigningPackage, bytes)?;
        let length = usize::try_from(reader.u64()?).map_err(|_| Error::Limit)?;
        if length > self.limits.message_bytes {
            return Err(Error::Limit);
        }
        let message = reader.bytes(length)?;
        let token_bytes = self
            .commitment_size()?
            .checked_mul(usize::from(self.parameters.config().committee.threshold()))
            .ok_or(Error::Limit)?;
        reader.require(token_bytes)?;
        let tokens = (0..self.parameters.config().committee.threshold())
            .map(|_| self.read_commitment(&mut reader))
            .collect::<Result<_, _>>()?;
        reader.finish()?;
        Ok(SigningPackage::new(keys, message, tokens)?)
    }

    /// Encodes a structurally valid response; call verify_share for its equation.
    pub fn encode_partial_signature(&self, partial: &PartialSignature) -> Result<Vec<u8>, Error> {
        self.check_party(partial.participant)?;
        let c = self.parameters.config();
        let mut writer = Writer::new(self, Kind::PartialSignature)?;
        writer.bytes(&[partial.participant])?;
        writer.bytes(&partial.session_id)?;
        writer.vector(&partial.response, c.ring, c.columns)?;
        Ok(writer.finish())
    }

    /// Decodes a response without authenticating its sender or verifying its norm.
    pub fn decode_partial_signature(&self, bytes: &[u8]) -> Result<PartialSignature, Error> {
        let c = self.parameters.config();
        let mut reader = Reader::new(self, Kind::PartialSignature, bytes)?;
        let participant = reader.array::<1>()?[0];
        self.check_party(participant)?;
        let session_id = reader.array()?;
        let response = reader.vector(c.ring, c.columns)?;
        reader.finish()?;
        Ok(PartialSignature {
            participant,
            session_id,
            response,
        })
    }

    /// Checks shape and norm before encoding; message verification is separate.
    pub fn encode_signature(&self, signature: &Signature) -> Result<Vec<u8>, Error> {
        support::validate_signature(&self.parameters, signature)?;
        let c = self.parameters.config();
        let mut writer = Writer::new(self, Kind::Signature)?;
        writer.row(signature.challenge.coefficients(), c.ring.modulus())?;
        writer.vector(&signature.response, c.ring, c.columns)?;
        writer.coefficients(
            &signature.hint,
            c.ring,
            c.rows,
            c.ring
                .rounded_modulus(c.commitment_bits)
                .map_err(ProtocolError::from)?,
        )?;
        Ok(writer.finish())
    }

    /// Checks shape and norm; PublicKey::verify must still check the signed message.
    pub fn decode_signature(&self, bytes: &[u8]) -> Result<Signature, Error> {
        let c = self.parameters.config();
        let mut reader = Reader::new(self, Kind::Signature, bytes)?;
        let challenge = reader.polynomial(c.ring)?;
        let response = reader.vector(c.ring, c.columns)?;
        let hint = reader.coefficients(
            c.ring,
            c.rows,
            c.ring
                .rounded_modulus(c.commitment_bits)
                .map_err(ProtocolError::from)?,
        )?;
        reader.finish()?;
        let signature = Signature {
            challenge,
            response,
            hint,
        };
        support::validate_signature(&self.parameters, &signature)?;
        Ok(signature)
    }

    /// Encodes a globally verified proposal for the next epoch.
    pub fn encode_refresh_proposal(
        &self,
        keys: &PublicKeyPackage,
        proposal: &RefreshProposal,
    ) -> Result<Vec<u8>, Error> {
        self.check_key(&keys.key)?;
        self.check_body_size(
            self.public_shares_size()?
                .checked_add(72)
                .ok_or(Error::Limit)?,
        )?;
        proposal.verify(keys)?;
        let mut writer = Writer::new(self, Kind::RefreshProposal)?;
        writer.bytes(&proposal.source_id)?;
        writer.u64(proposal.source_epoch)?;
        self.write_shares(&mut writer, &proposal.verification_shares)?;
        Ok(writer.finish())
    }

    /// Checks canonical encoding and global preservation of the old full key.
    pub fn decode_refresh_proposal(
        &self,
        keys: &PublicKeyPackage,
        bytes: &[u8],
    ) -> Result<RefreshProposal, Error> {
        self.check_key(&keys.key)?;
        self.share_budget()?;
        let mut reader = Reader::new(self, Kind::RefreshProposal, bytes)?;
        let source_id = reader.array()?;
        let source_epoch = reader.u64()?;
        if source_epoch != keys.epoch {
            return Err(ProtocolError::EpochMismatch.into());
        }
        if source_id != keys.id {
            return Err(ProtocolError::KeyMismatch.into());
        }
        let verification_shares = self.read_shares(&mut reader)?;
        reader.finish()?;
        let proposal = RefreshProposal {
            source_id,
            source_epoch,
            verification_shares,
        };
        proposal.verify(keys)?;
        Ok(proposal)
    }

    /// Verifies and encodes a confidential token into a zeroizing owned buffer.
    pub fn encode_refresh_token(
        &self,
        keys: &PublicKeyPackage,
        refresh: &VerifiedRefresh,
        token: &RefreshToken,
    ) -> Result<SecretPacket, Error> {
        self.check_key(&keys.key)?;
        self.share_budget()?;
        let c = self.parameters.config();
        let rows = token
            .updates
            .len()
            .checked_mul(c.columns)
            .ok_or(Error::Limit)?;
        let body = primitives::byte_count(rows, c.ring.degree())?
            .checked_add(129)
            .ok_or(Error::Limit)?;
        self.check_body_size(body)?;
        refresh.verify_token(keys, token)?;
        let mut writer = Writer::new(self, Kind::RefreshToken)?;
        writer.reserve_body(body)?;
        writer.bytes(&[token.participant])?;
        writer.bytes(&token.source_id)?;
        writer.bytes(&token.target_id)?;
        for value in token.updates.values() {
            writer.vector(value, c.ring, c.columns)?;
        }
        Ok(writer.finish_secret())
    }

    /// Verifies a confidential token; the caller must erase its input byte buffer.
    pub fn decode_refresh_token(
        &self,
        keys: &PublicKeyPackage,
        refresh: &VerifiedRefresh,
        bytes: &[u8],
    ) -> Result<RefreshToken, Error> {
        self.check_key(&keys.key)?;
        self.share_budget()?;
        let c = self.parameters.config();
        let mut reader = Reader::new(self, Kind::RefreshToken, bytes)?;
        let participant = reader.array::<1>()?[0];
        self.check_party(participant)?;
        let source_id = reader.array()?;
        let target_id = reader.array()?;
        if source_id != keys.id || target_id != refresh.next.id {
            return Err(ProtocolError::KeyMismatch.into());
        }
        let count = self.counts[usize::from(participant - 1)];
        reader.require(primitives::byte_count(
            count.checked_mul(c.columns).ok_or(Error::Limit)?,
            c.ring.degree(),
        )?)?;
        let mut updates = BTreeMap::new();
        for index in keys.verification_shares[usize::from(participant - 1)].keys() {
            updates.insert(index.clone(), reader.vector(c.ring, c.columns)?);
        }
        reader.finish()?;
        let token = RefreshToken {
            participant,
            source_id,
            target_id,
            updates,
        };
        refresh.verify_token(keys, &token)?;
        Ok(token)
    }

    /// Checks trusted object configuration against this codec's fixed profile.
    fn check_key(&self, key: &PublicKey) -> Result<(), Error> {
        if key.parameters != self.parameters {
            return Err(Error::Parameters);
        }
        Ok(())
    }

    /// Validates one-based participant identifiers before indexing.
    fn check_party(&self, participant: u8) -> Result<(), Error> {
        if participant == 0 || participant > self.parameters.config().committee.parties() {
            return Err(ProtocolError::Participant.into());
        }
        Ok(())
    }

    /// Checks the total share-path allocation budget before constructing layouts.
    fn share_budget(&self) -> Result<usize, Error> {
        let count = self
            .counts
            .iter()
            .try_fold(0_usize, |a, &b| a.checked_add(b))
            .ok_or(Error::Limit)?;
        if count > self.limits.indexed_shares {
            return Err(Error::Limit);
        }
        Ok(count)
    }

    /// Rejects an impossible output before expensive validation or cloning.
    fn check_body_size(&self, body: usize) -> Result<(), Error> {
        let total = body
            .checked_add(6 + self.parameters.to_bytes().len())
            .ok_or(Error::Limit)?;
        if total > self.limits.packet_bytes {
            return Err(Error::Limit);
        }
        Ok(())
    }

    /// Computes the exact public-share coefficient section size.
    fn public_shares_size(&self) -> Result<usize, Error> {
        let c = self.parameters.config();
        let rows = self
            .share_budget()?
            .checked_mul(c.rows)
            .ok_or(Error::Limit)?;
        primitives::byte_count(rows, c.ring.degree())
    }

    /// Computes the complete fixed-size public-package body.
    fn public_package_size(&self) -> Result<usize, Error> {
        let c = self.parameters.config();
        let key = primitives::byte_count(c.rows * (c.columns + 1), c.ring.degree())?;
        let shares = self.public_shares_size()?;
        key.checked_add(8)
            .and_then(|n| n.checked_add(shares))
            .ok_or(Error::Limit)
    }

    /// Computes one commitment's metadata and coefficient body size.
    fn commitment_size(&self) -> Result<usize, Error> {
        let c = self.parameters.config();
        primitives::byte_count(c.rows * c.repetitions, c.ring.degree())?
            .checked_add(89)
            .ok_or(Error::Limit)
    }

    /// Writes the fixed-size matrix and rounded public-key body.
    fn write_key(&self, writer: &mut Writer, key: &PublicKey) -> Result<(), Error> {
        let c = self.parameters.config();
        for row in key.matrix.rows() {
            writer.vector(row, c.ring, c.columns)?;
        }
        writer.coefficients(
            &key.rounded_key,
            c.ring,
            c.rows,
            self.rounding_bound(c.public_key_bits),
        )
    }

    /// Reads a public key and derives its transform and identity locally.
    fn read_key(&self, reader: &mut Reader<'_>) -> Result<PublicKey, Error> {
        let c = self.parameters.config();
        reader.require(primitives::byte_count(
            c.rows * (c.columns + 1),
            c.ring.degree(),
        )?)?;
        let rows = (0..c.rows)
            .map(|_| reader.vector(c.ring, c.columns))
            .collect::<Result<_, _>>()?;
        let matrix = Matrix::new(rows).map_err(ProtocolError::from)?;
        let rounded_key =
            reader.coefficients(c.ring, c.rows, self.rounding_bound(c.public_key_bits))?;
        #[cfg(feature = "experimental-dkg")]
        if !self.parameters.matches_dkg_key(&matrix, &rounded_key) {
            return Err(ProtocolError::KeyMismatch.into());
        }
        let transformed = matrix
            .transform(self.parameters.ntt().clone())
            .map_err(ProtocolError::from)?;
        let mut key = PublicKey {
            parameters: self.parameters.clone(),
            matrix,
            transformed,
            rounded_key,
            id: [0; 64],
        };
        key.id = support::key_id(&key);
        Ok(key)
    }

    /// Writes indexed public values in the profile's implicit party/path order.
    fn write_shares(&self, writer: &mut Writer, shares: &Shares<Vector>) -> Result<(), Error> {
        self.share_budget()?;
        let c = self.parameters.config();
        c.committee
            .validate_layout(shares)
            .map_err(ProtocolError::from)?;
        for party in shares {
            for value in party.values() {
                writer.vector(value, c.ring, c.rows)?;
            }
        }
        Ok(())
    }

    /// Preflights the entire collection before allocating its implicit layout.
    fn read_shares(&self, reader: &mut Reader<'_>) -> Result<Shares<Vector>, Error> {
        let count = self.share_budget()?;
        let c = self.parameters.config();
        reader.require(primitives::byte_count(
            count.checked_mul(c.rows).ok_or(Error::Limit)?,
            c.ring.degree(),
        )?)?;
        c.committee
            .layout()
            .into_iter()
            .map(|party| {
                party
                    .into_keys()
                    .map(|index| Ok((index, reader.vector(c.ring, c.rows)?)))
                    .collect()
            })
            .collect()
    }

    /// Writes one prevalidated commitment body without nesting another header.
    fn write_commitment(&self, writer: &mut Writer, token: &Commitment) -> Result<(), Error> {
        let c = self.parameters.config();
        writer.bytes(&[token.participant])?;
        writer.u64(token.epoch)?;
        writer.bytes(&token.package_id)?;
        writer.bytes(&token.sequence.to_le_bytes())?;
        for value in &token.values {
            writer.coefficients(
                value,
                c.ring,
                c.rows,
                self.rounding_bound(c.preprocessing_bits),
            )?;
        }
        Ok(())
    }

    /// Reads exactly the configured number of commitment repetitions.
    fn read_commitment(&self, reader: &mut Reader<'_>) -> Result<Commitment, Error> {
        let c = self.parameters.config();
        let participant = reader.array::<1>()?[0];
        self.check_party(participant)?;
        let epoch = reader.u64()?;
        let package_id = reader.array()?;
        let sequence = u128::from_le_bytes(reader.array()?);
        reader.require(primitives::byte_count(
            c.repetitions * c.rows,
            c.ring.degree(),
        )?)?;
        let values = (0..c.repetitions)
            .map(|_| reader.coefficients(c.ring, c.rows, self.rounding_bound(c.preprocessing_bits)))
            .collect::<Result<_, _>>()?;
        Ok(Commitment {
            participant,
            epoch,
            package_id,
            sequence,
            values,
        })
    }

    /// Returns the exclusive bound for unreduced rounded coefficients.
    fn rounding_bound(&self, bits: u32) -> u64 {
        ((self.parameters.config().ring.modulus() - 1 + (1 << (bits - 1))) >> bits) + 1
    }
}
