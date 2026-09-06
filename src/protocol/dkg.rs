//! Consuming bridge from checked candidate DKG output to experimental signing.

use std::collections::BTreeMap;

use super::{Error, PublicKeyPackage, SecretShare, support};
use crate::{
    dkg::DkgOutput,
    linear::Vector,
    parameters::{Config, Parameters},
};

/// One participant's signing material from a completed candidate DKG.
#[derive(Debug)]
pub struct ParticipantKeys {
    /// Common public key and verification sharing.
    pub public: PublicKeyPackage,
    /// Only this participant's private signing share.
    pub secret: SecretShare,
}

impl DkgOutput {
    /// Consumes a completed candidate output and derives its experimental signing profile.
    ///
    /// Pins DKG provenance and checked share bounds into the key identity. The
    /// signing configuration must use the DKG's ring, root, committee, and matrix
    /// dimensions. This enables composition experiments; it does not establish
    /// privacy, unforgeability, or a production security profile.
    ///
    /// ```rust,compile_fail
    /// use hermine::{dkg::DkgOutput, parameters::Config};
    /// fn import_twice(output: DkgOutput, config: Config) {
    ///     let _ = output.into_signing(config.clone());
    ///     let _ = output.into_signing(config);
    /// }
    /// ```
    pub fn into_signing(self, config: Config) -> Result<ParticipantKeys, Error> {
        let output = self.public();
        let parameters = Parameters::for_dkg(config, output)?;
        let c = parameters.config();
        let transformed = output.matrix().transform(parameters.ntt().clone())?;
        let mut shares = BTreeMap::new();
        for (index, input) in self.shares() {
            let secret = Vector::new(input[..c.columns].to_vec())?;
            let error = Vector::new(input[c.columns..].to_vec())?;
            let image = transformed.multiply(&secret)?.add(&error)?.scale(2);
            if image != output.verification_shares()[usize::from(self.participant() - 1)][index] {
                return Err(Error::KeyMismatch);
            }
            shares.insert(index.clone(), secret);
        }
        let public = support::assemble_public(
            parameters,
            output.matrix().clone(),
            transformed,
            output.full_key().clone(),
            output.verification_shares().clone(),
        )?;
        let secret = SecretShare {
            participant: self.participant(),
            epoch: 0,
            package_id: *public.id(),
            shares,
            issued: 0,
        };
        Ok(ParticipantKeys { public, secret })
    }
}
