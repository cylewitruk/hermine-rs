//! One-shot preprocessing, common signing requests, and verification.

use std::{collections::BTreeMap, error, sync::Arc};

use rand_core::TryCryptoRng;

use super::{
    AbortReport, Coefficients, Commitment, Error, Identifier, NonceState, PartialSignature,
    PublicKey, PublicKeyPackage, SecretShare, Signature, SigningPackage, support,
};
use crate::{
    linear::Vector,
    ring::Polynomial,
    transcript::{Domain, Transcript},
};

impl SecretShare {
    /// Reserves and samples one message-independent signing nonce.
    ///
    /// Reservations are burned before sampling, including on entropy failure.
    /// Refreshing shares never resets this lifetime counter.
    /// Experimental DKG profiles also reject oversized joint nonce pairs with
    /// `Error::NonceBound`; these failed reservations remain burned.
    pub fn preprocess<R: TryCryptoRng>(
        &mut self,
        keys: &PublicKeyPackage,
        rng: &mut R,
    ) -> Result<NonceState, Error>
    where
        R::Error: error::Error + Send + Sync + 'static,
    {
        self.check_package(keys)?;
        if self.issued >= keys.key.parameters.per_party_preprocessing_limit() {
            return Err(Error::Limit);
        }
        let sequence = self.issued;
        self.issued += 1;
        let c = keys.key.parameters.config();
        let mut values = Vec::with_capacity(c.repetitions);
        let mut nonces = Vec::with_capacity(c.repetitions);
        for _ in 0..c.repetitions {
            let r = support::sample_vector(c.ring, c.columns, c.nonce_sigma, rng)?;
            let e = support::sample_vector(c.ring, c.rows, c.nonce_sigma, rng)?;
            #[cfg(feature = "experimental-dkg")]
            if let Some(bound) = keys.key.parameters.nonce_pair_bound()
                && r.norm_squared() + e.norm_squared() > u128::from(bound).pow(2)
            {
                return Err(Error::NonceBound);
            }
            let w = keys.key.transformed.multiply(&r)?.add(&e)?;
            values.push(support::round(&w, c.preprocessing_bits, false)?);
            nonces.push(r);
        }
        Ok(NonceState {
            commitment: Commitment {
                participant: self.participant,
                epoch: self.epoch,
                package_id: self.package_id,
                sequence,
                values,
            },
            nonces,
        })
    }

    /// Consumes a preprocessing nonce and signs a validated common request.
    pub fn sign(
        &self,
        keys: &PublicKeyPackage,
        package: &SigningPackage,
        nonce: NonceState,
    ) -> Result<PartialSignature, Error> {
        self.check_package(keys)?;
        package.check_package(keys)?;
        let position = package.position(self.participant)?;
        if nonce.commitment != package.commitments[position] {
            return Err(Error::CommitmentMismatch);
        }
        let index = &package.indices[position].1;
        let secret = self.shares.get(index).ok_or(Error::Malformed)?;
        let mut response = secret.multiply_polynomial(&package.challenge)?.scale(2);
        for (factor, r) in package.factors.iter().zip(&nonce.nonces) {
            response = response.add(&r.monomial(factor.exponent(), factor.is_negative())?)?;
        }
        Ok(PartialSignature {
            participant: self.participant,
            session_id: package.id,
            response,
        })
    }
}

impl NonceState {
    /// Borrows the public token corresponding to this one-shot private state.
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }
}

impl SigningPackage {
    /// Validates exactly T commitments in strictly increasing participant order.
    pub fn new(
        keys: &PublicKeyPackage,
        message: &[u8],
        commitments: Vec<Commitment>,
    ) -> Result<Self, Error> {
        let c = keys.key.parameters.config();
        let active: Vec<_> = commitments.iter().map(|v| v.participant).collect();
        let indices = c.committee.recover(&active)?;
        for token in &commitments {
            support::validate_commitment(keys, token)?;
        }
        let factors = session_transcript(Domain::Binding, keys, message, &commitments)
            .binding_factors(c.ring, c.repetitions)?;
        let id = session_transcript(Domain::Session, keys, message, &commitments).digest();
        let mut aggregate = Vector::zero(c.ring, c.rows)?;
        let mut combined = Vec::with_capacity(commitments.len());
        for token in &commitments {
            let mut w = Vector::zero(c.ring, c.rows)?;
            for (factor, value) in factors.iter().zip(&token.values) {
                let lifted = support::lift(value, c.ring, c.preprocessing_bits)?;
                w = w.add(&lifted.monomial(factor.exponent(), factor.is_negative())?)?;
            }
            aggregate = aggregate.add(&w)?;
            combined.push(w);
        }
        let rounded_commitment = support::round(&aggregate, c.commitment_bits, true)?;
        let challenge = support::challenge(&keys.key, message, &rounded_commitment)?;
        Ok(Self {
            package_id: keys.id,
            epoch: keys.epoch,
            message: Arc::from(message),
            commitments,
            indices,
            factors,
            combined,
            rounded_commitment,
            challenge,
            id,
        })
    }

    /// Returns the identity of all common signing inputs.
    pub fn id(&self) -> &Identifier {
        &self.id
    }
    /// Borrows the signed message bytes.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
    /// Borrows the selected public preprocessing commitments.
    pub fn commitments(&self) -> &[Commitment] {
        &self.commitments
    }
    /// Borrows the common sparse challenge polynomial.
    pub fn challenge(&self) -> &Polynomial {
        &self.challenge
    }

    /// Checks one authenticated participant's response and residual norm.
    pub fn verify_share(
        &self,
        keys: &PublicKeyPackage,
        response: &PartialSignature,
    ) -> Result<(), Error> {
        self.check_package(keys)?;
        let position = self.position(response.participant)?;
        if response.session_id != self.id {
            return Err(Error::SessionMismatch);
        }
        let c = keys.key.parameters.config();
        support::validate_vector(&response.response, c.ring, c.columns)?;
        let index = &self.indices[position].1;
        let vk = keys.verification_shares[usize::from(response.participant - 1)]
            .get(index)
            .ok_or(Error::Malformed)?;
        let relation = keys
            .key
            .transformed
            .multiply(&response.response)?
            .subtract(&vk.multiply_polynomial(&self.challenge)?)?;
        let residual = self.combined[position].subtract(&relation)?;
        let norm = response.response.norm_squared() + residual.norm_squared();
        if norm > u128::from(keys.key.parameters.partial_bound()).pow(2) {
            return Err(Error::InvalidShare {
                participant: response.participant,
            });
        }
        Ok(())
    }

    /// Classifies invalid and absent responses without attributing transport faults.
    ///
    /// Sender identities must be authenticated by the application. Duplicate or
    /// unexpected senders are rejected as malformed collection structure.
    pub fn identify_abort(
        &self,
        keys: &PublicKeyPackage,
        responses: &[PartialSignature],
    ) -> Result<AbortReport, Error> {
        self.check_package(keys)?;
        let ordered = self.responses_by_party(responses)?;
        let mut report = AbortReport {
            invalid: Vec::new(),
            missing: Vec::new(),
        };
        for (party, _) in &self.indices {
            match ordered.get(party) {
                None => report.missing.push(*party),
                Some(response) if self.verify_share(keys, response).is_err() => {
                    report.invalid.push(*party)
                }
                Some(_) => {}
            }
        }
        Ok(report)
    }

    /// Verifies all T contributions and checks the resulting final signature.
    pub fn aggregate(
        &self,
        keys: &PublicKeyPackage,
        responses: &[PartialSignature],
    ) -> Result<Signature, Error> {
        self.check_package(keys)?;
        let ordered = self.responses_by_party(responses)?;
        if ordered.len() != self.indices.len() {
            return Err(Error::Participant);
        }
        let c = keys.key.parameters.config();
        let mut response = Vector::zero(c.ring, c.columns)?;
        for partial in ordered.values() {
            self.verify_share(keys, partial)?;
            response = response.add(&partial.response)?;
        }
        let rounded = verification_commitment(&keys.key, &self.challenge, &response)?;
        let modulus = c.ring.rounded_modulus(c.commitment_bits)?;
        let hint = self
            .rounded_commitment
            .iter()
            .zip(rounded)
            .map(|(w, u)| {
                w.iter()
                    .zip(u)
                    .map(|(&w, u)| (w + modulus - u) % modulus)
                    .collect()
            })
            .collect();
        let signature = Signature {
            challenge: self.challenge.clone(),
            response,
            hint,
        };
        keys.key.verify(&self.message, &signature)?;
        Ok(signature)
    }

    /// Validates that this request belongs to the supplied epoch and public shares.
    fn check_package(&self, keys: &PublicKeyPackage) -> Result<(), Error> {
        if self.epoch != keys.epoch {
            return Err(Error::EpochMismatch);
        }
        if self.package_id != keys.id {
            return Err(Error::KeyMismatch);
        }
        Ok(())
    }

    /// Locates the selected participant and its corresponding cached values.
    fn position(&self, participant: u8) -> Result<usize, Error> {
        self.indices
            .binary_search_by_key(&participant, |(party, _)| *party)
            .map_err(|_| Error::Participant)
    }

    /// Rejects unexpected or repeated participant identifiers.
    fn responses_by_party<'a>(
        &self,
        responses: &'a [PartialSignature],
    ) -> Result<BTreeMap<u8, &'a PartialSignature>, Error> {
        let mut ordered = BTreeMap::new();
        for response in responses {
            self.position(response.participant)?;
            if ordered.insert(response.participant, response).is_some() {
                return Err(Error::Participant);
            }
        }
        Ok(ordered)
    }
}

impl PublicKey {
    /// Verifies a final signature's canonical shape, norm, and Fiat–Shamir challenge.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let c = self.parameters.config();
        support::validate_signature(&self.parameters, signature)?;
        let modulus = c.ring.rounded_modulus(c.commitment_bits)?;
        let mut commitment =
            verification_commitment(self, &signature.challenge, &signature.response)?;
        for (row, hint) in commitment.iter_mut().zip(&signature.hint) {
            for (value, &h) in row.iter_mut().zip(hint) {
                *value = (*value + h) % modulus;
            }
        }
        if support::challenge(self, message, &commitment)? != signature.challenge {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

/// Binds the complete key, epoch, message, signer set, and preprocessing tokens.
fn session_transcript(
    domain: Domain,
    keys: &PublicKeyPackage,
    message: &[u8],
    commitments: &[Commitment],
) -> Transcript {
    let mut transcript = Transcript::new(domain);
    support::append_key(&mut transcript, &keys.key);
    transcript
        .append(b"package", &keys.id)
        .append_u64(b"epoch", keys.epoch)
        .append(b"message", message);
    transcript.append_u64(b"participants", commitments.len() as u64);
    for token in commitments {
        transcript
            .append_u64(b"participant", u64::from(token.participant))
            .append(b"sequence", &token.sequence.to_le_bytes());
        for values in &token.values {
            transcript.append(b"preprocessing", &support::encode(values));
        }
    }
    transcript
}

/// Reconstructs round_nu_w(Az - 2^nu_t c t_top) modulo q_nu_w.
fn verification_commitment(
    key: &PublicKey,
    challenge: &Polynomial,
    response: &Vector,
) -> Result<Coefficients, Error> {
    let c = key.parameters.config();
    let lifted = support::lift(&key.rounded_key, c.ring, c.public_key_bits)?;
    let value = key
        .transformed
        .multiply(response)?
        .subtract(&lifted.multiply_polynomial(challenge)?)?;
    support::round(&value, c.commitment_bits, true)
}
