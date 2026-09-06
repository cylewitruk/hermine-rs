//! Validated bridge from local MPC outputs to Hermine signing material.

use std::collections::BTreeMap;

use super::{Error, PublicKeyPackage, SecretShare, support};
use crate::{
    linear::{Matrix, Vector},
    parameters::Parameters,
    sharing::{Index, Shares},
};

/// Assembles an MPC result and validates this participant's private/public relation.
pub fn assemble_mpc(
    parameters: Parameters,
    matrix: Matrix,
    full_key: Vector,
    verification: Shares<Vector>,
    private: BTreeMap<Index, (Vector, Vector)>,
    party: usize,
) -> Result<(PublicKeyPackage, SecretShare), Error> {
    let transformed = matrix.transform(parameters.ntt().clone())?;
    if party >= verification.len() || !private.keys().eq(verification[party].keys()) {
        return Err(Error::KeyMismatch);
    }
    let mut shares = BTreeMap::new();
    for (index, (secret, error)) in private {
        if transformed.multiply(&secret)?.add(&error)?.scale(2) != verification[party][&index] {
            return Err(Error::KeyMismatch);
        }
        shares.insert(index, secret);
    }
    let public = support::assemble_public(parameters, matrix, transformed, full_key, verification)?;
    if support::reconstruct_public(public.key(), public.verification_shares())?
        != *public.full_key()
    {
        return Err(Error::KeyMismatch);
    }
    let secret = SecretShare {
        participant: party as u8 + 1,
        epoch: 0,
        package_id: *public.id(),
        shares,
        issued: 0,
    };
    Ok((public, secret))
}
