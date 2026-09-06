//! Explicit correctness bounds for a completed candidate DKG output.

use super::{Config, Error, KeyOrigin, Parameters, sqrt_ceil};
use crate::{
    Identifier,
    dkg::PublicOutput,
    linear::{Matrix, Vector},
    transcript::{Domain, Transcript},
};

/// Cached public-material hashes derived from an immutable completed DKG output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgMaterial {
    /// Binding of A and the selected bit-rounded long-term key.
    key: Identifier,
    /// Binding of the full-resolution key preserved by refreshes.
    full: Identifier,
}

impl Parameters {
    /// Derives an experimental profile bound to a completed candidate DKG output.
    ///
    /// Ring, committee, NTT root, and matrix dimensions must match. Initial share
    /// bounds use the DKG's checked coefficient limit; `secret_sigma` controls
    /// subsequent refreshes. This establishes no privacy or hardness claim.
    pub fn for_dkg(config: Config, output: &PublicOutput) -> Result<Self, Error> {
        let dkg = output.config();
        if config.ring != dkg.sharing.projection.ring()
            || config.root != dkg.root
            || config.committee != dkg.sharing.committee
            || config.columns != dkg.columns
            || config.rows != dkg.sharing.projection.components() - dkg.columns
        {
            return Err(Error::DkgMismatch);
        }
        let mut parameters = Self::build(
            config,
            KeyOrigin::ExperimentalDkg {
                output: *output.id(),
                contribution_limit: dkg.sharing.private_limit,
            },
        )?;
        let rounded = output
            .full_key()
            .entries()
            .iter()
            .map(|p| {
                p.round(parameters.config.public_key_bits)
                    .map_err(|_| Error::Rounding)
            })
            .collect::<Result<Vec<_>, _>>()?;
        parameters.dkg_material = Some(DkgMaterial {
            key: key_material(output.matrix(), &rounded),
            full: full_material(output.full_key()),
        });
        Ok(parameters)
    }

    /// Returns the enforced joint nonce-pair bound for a DKG profile.
    ///
    /// Dealer profiles retain their original sampling behavior and return None.
    /// Each DKG preprocessing pair must pass this check before a token is issued.
    pub fn nonce_pair_bound(&self) -> Option<u64> {
        match self.origin {
            KeyOrigin::TrustedDealer => None,
            #[cfg(feature = "experimental-mpc")]
            KeyOrigin::ExperimentalMpc { .. } => None,
            KeyOrigin::ExperimentalDkg { .. } => {
                let c = &self.config;
                let dimension = c.ring.degree() as u128 * (c.rows + c.columns) as u128;
                // This positive term is included M times in the validated u64
                // partial bound, so representability follows from construction.
                Some(
                    (u128::from(c.tail_multiplier)
                        * u128::from(c.nonce_sigma)
                        * sqrt_ceil(dimension)) as u64,
                )
            }
        }
    }

    /// Checks long-term key material against the locally completed DKG output.
    ///
    /// Dealer profiles have no material pin and return true. DKG profiles bind
    /// both A and the selected rounded key, beyond their serialized origin label.
    pub fn matches_dkg_key(&self, matrix: &Matrix, rounded_key: &[Vec<u64>]) -> bool {
        self.dkg_material
            .as_ref()
            .is_none_or(|expected| expected.key == key_material(matrix, rounded_key))
    }

    /// Checks the reconstructed full key against the locally completed DKG output.
    ///
    /// Dealer profiles return true; every DKG epoch must preserve this full key.
    pub fn matches_dkg_full_key(&self, full_key: &Vector) -> bool {
        self.dkg_material
            .as_ref()
            .is_none_or(|expected| expected.full == full_material(full_key))
    }
}

/// Hashes explicit matrix dimensions and coefficient rows without temporary bytes.
fn key_material(matrix: &Matrix, rounded: &[Vec<u64>]) -> Identifier {
    let mut transcript = Transcript::new(Domain::Dkg);
    transcript
        .append(b"kind", b"signing-material-v1")
        .append_u64(b"degree", matrix.ring().degree() as u64)
        .append_u64(b"modulus", matrix.ring().modulus())
        .append_u64(b"rows", matrix.row_count() as u64)
        .append_u64(b"columns", matrix.column_count() as u64);
    for row in matrix.rows() {
        for polynomial in row.entries() {
            append_row(&mut transcript, b"matrix", polynomial.coefficients());
        }
    }
    transcript.append_u64(b"rounded-rows", rounded.len() as u64);
    for row in rounded {
        append_row(&mut transcript, b"rounded", row);
    }
    transcript.digest()
}

/// Hashes the full-resolution key independently of the current verification sharing.
fn full_material(full: &Vector) -> Identifier {
    let mut transcript = Transcript::new(Domain::Dkg);
    transcript
        .append(b"kind", b"signing-full-key-v1")
        .append_u64(b"degree", full.ring().degree() as u64)
        .append_u64(b"modulus", full.ring().modulus())
        .append_u64(b"rows", full.dimension() as u64);
    for polynomial in full.entries() {
        append_row(&mut transcript, b"full", polynomial.coefficients());
    }
    transcript.digest()
}

/// Frames one public coefficient row and its length without allocating bytes.
fn append_row(transcript: &mut Transcript, kind: &[u8], values: &[u64]) {
    transcript
        .append(b"row", kind)
        .append_u64(b"length", values.len() as u64);
    for &value in values {
        transcript.append_u64(b"coefficient", value);
    }
}
