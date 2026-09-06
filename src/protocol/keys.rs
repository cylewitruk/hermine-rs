//! Trusted-dealer generation of public and secret Vandermonde shares.

use std::{collections::BTreeMap, error};

use rand_core::TryCryptoRng;

use super::support::SecretPair;
use super::{
    Coefficients, Error, Identifier, KeySet, PublicKey, PublicKeyPackage, SecretShare, support,
};
use crate::{
    linear::{Matrix, Vector},
    parameters::{KeyOrigin, Parameters},
    sampling,
    sharing::Shares,
};

/// Generates a fresh key and N private shares using a trusted dealer.
///
/// The caller must distribute each secret share confidentially and authenticate
/// the common public package. This is not a distributed key generation protocol.
pub fn dealer_keygen<R: TryCryptoRng>(parameters: Parameters, rng: &mut R) -> Result<KeySet, Error>
where
    R::Error: error::Error + Send + Sync + 'static,
{
    if parameters.origin() != KeyOrigin::TrustedDealer {
        return Err(Error::KeyOrigin);
    }
    let c = parameters.config();
    let matrix = Matrix::new(
        (0..c.rows)
            .map(|_| {
                let entries = (0..c.columns)
                    .map(|_| sampling::uniform_polynomial(c.ring, rng))
                    .collect::<Result<_, _>>()?;
                Ok::<_, Error>(Vector::new(entries)?)
            })
            .collect::<Result<_, _>>()?,
    )?;
    let transformed = matrix.transform(parameters.ntt().clone())?;
    let mut sample = || SecretPair::sample(&parameters, rng);
    let secret = sample()?;
    let full_key = secret.public_image(&transformed)?;
    let shared = c
        .committee
        .try_share(secret, sample, SecretPair::subtract)?;
    let mut verification_shares = Vec::with_capacity(shared.len());
    let mut shares = Vec::with_capacity(shared.len());
    for (party, paths) in shared.into_iter().enumerate() {
        let mut public = BTreeMap::new();
        let mut private = BTreeMap::new();
        for (index, pair) in paths {
            let value = pair.public_image(&transformed)?;
            public.insert(index.clone(), value);
            private.insert(index, pair.secret);
        }
        verification_shares.push(public);
        shares.push(SecretShare {
            participant: party as u8 + 1,
            epoch: 0,
            package_id: [0; 64],
            shares: private,
            issued: 0,
        });
    }
    let public = support::assemble_public(
        parameters,
        matrix,
        transformed,
        full_key,
        verification_shares,
    )?;
    for share in &mut shares {
        share.package_id = public.id;
    }
    Ok(KeySet { public, shares })
}

impl PublicKey {
    /// Borrows the validated explicit parameters.
    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }
    /// Returns the identity of the complete long-term verification key.
    pub fn id(&self) -> &Identifier {
        &self.id
    }
    /// Borrows the public matrix A.
    pub fn matrix(&self) -> &Matrix {
        &self.matrix
    }
    /// Borrows the integer-rounded public key coefficients.
    pub fn rounded_key(&self) -> &Coefficients {
        &self.rounded_key
    }
}

impl PublicKeyPackage {
    /// Borrows the long-term verification key.
    pub fn key(&self) -> &PublicKey {
        &self.key
    }
    /// Returns the current refresh generation.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Returns the identity binding all public shares and this epoch.
    pub fn id(&self) -> &Identifier {
        &self.id
    }
    /// Borrows each participant's indexed public verification shares.
    pub fn verification_shares(&self) -> &Shares<Vector> {
        &self.verification_shares
    }
    /// Borrows the full-resolution reconstructed public key.
    pub fn full_key(&self) -> &Vector {
        &self.full_key
    }
}

impl SecretShare {
    /// Returns this share's one-based owner identifier.
    pub fn participant(&self) -> u8 {
        self.participant
    }
    /// Returns this share's refresh generation.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Returns the number of lifetime preprocessing reservations already burned.
    pub fn issued(&self) -> u128 {
        self.issued
    }
    /// Checks epoch and public package identity before using secret material.
    pub fn check_package(&self, keys: &PublicKeyPackage) -> Result<(), Error> {
        if self.epoch != keys.epoch {
            return Err(Error::EpochMismatch);
        }
        if self.package_id != keys.id {
            return Err(Error::KeyMismatch);
        }
        Ok(())
    }
}
