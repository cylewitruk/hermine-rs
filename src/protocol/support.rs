//! Shared protocol arithmetic and transcript encoding.

use std::{error, sync::Arc};

use rand_core::TryCryptoRng;

use super::{Coefficients, Commitment, Error, Identifier, PublicKey, PublicKeyPackage, Signature};
use crate::{
    linear::{Matrix, NttMatrix, Vector},
    parameters::Parameters,
    ring::{Polynomial, Ring},
    sampling::Gaussian,
    sharing::Shares,
    transcript::{Domain, Transcript},
};

/// Assembles a checked full-resolution sharing and its rounded verification key.
pub fn assemble_public(
    parameters: Parameters,
    matrix: Matrix,
    transformed: NttMatrix,
    full_key: Vector,
    verification_shares: Shares<Vector>,
) -> Result<PublicKeyPackage, Error> {
    let rounded_key = round(&full_key, parameters.config().public_key_bits, false)?;
    #[cfg(feature = "experimental-dkg")]
    if !parameters.matches_dkg_key(&matrix, &rounded_key)
        || !parameters.matches_dkg_full_key(&full_key)
    {
        return Err(Error::KeyMismatch);
    }
    let mut key = PublicKey {
        parameters,
        matrix,
        transformed,
        rounded_key,
        id: [0; 64],
    };
    key.id = key_id(&key);
    let mut public = PublicKeyPackage {
        key: Arc::new(key),
        epoch: 0,
        verification_shares: Arc::new(verification_shares),
        full_key,
        id: [0; 64],
    };
    public.id = package_id(&public);
    Ok(public)
}

/// A private secret/noise pair shared through the same Vandermonde recursion.
#[derive(Clone)]
pub struct SecretPair {
    /// Secret matrix input.
    pub secret: Vector,
    /// Public-key error term.
    pub error: Vector,
}

impl SecretPair {
    /// Samples both vectors from the configured secret distribution.
    pub fn sample<R: TryCryptoRng>(parameters: &Parameters, rng: &mut R) -> Result<Self, Error>
    where
        R::Error: error::Error + Send + Sync + 'static,
    {
        let c = parameters.config();
        Ok(Self {
            secret: sample_vector(c.ring, c.columns, c.secret_sigma, rng)?,
            error: sample_vector(c.ring, c.rows, c.secret_sigma, rng)?,
        })
    }

    /// Subtracts matching secret/noise pairs.
    pub fn subtract(&self, rhs: &Self) -> Result<Self, Error> {
        Ok(Self {
            secret: self.secret.subtract(&rhs.secret)?,
            error: self.error.subtract(&rhs.error)?,
        })
    }

    /// Computes the public image 2(As + e).
    pub fn public_image(&self, matrix: &NttMatrix) -> Result<Vector, Error> {
        Ok(matrix.multiply(&self.secret)?.add(&self.error)?.scale(2))
    }
}

/// Samples independent Gaussian polynomial components.
pub fn sample_vector<R: TryCryptoRng>(
    ring: Ring,
    dimension: usize,
    sigma: u64,
    rng: &mut R,
) -> Result<Vector, Error>
where
    R::Error: error::Error + Send + Sync + 'static,
{
    let gaussian = Gaussian::new(sigma)?;
    let entries = (0..dimension)
        .map(|_| gaussian.polynomial(ring, rng))
        .collect::<Result<_, _>>()?;
    Ok(Vector::new(entries)?)
}

/// Encodes dimensions and canonical integer coefficients.
pub fn encode(values: &Coefficients) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for row in values {
        bytes.extend_from_slice(&(row.len() as u64).to_le_bytes());
        for value in row {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes
}

/// Copies canonical polynomial coefficients into a public transcript value.
pub fn coefficients(vector: &Vector) -> Coefficients {
    vector
        .entries()
        .iter()
        .map(|p| p.coefficients().to_vec())
        .collect()
}

/// Validates a rectangular integer coefficient message before arithmetic.
pub fn validate(
    values: &Coefficients,
    ring: Ring,
    rows: usize,
    exclusive_bound: u64,
) -> Result<(), Error> {
    if values.len() != rows
        || values
            .iter()
            .any(|row| row.len() != ring.degree() || row.iter().any(|&v| v >= exclusive_bound))
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Validates the shape and ring of a response vector.
pub fn validate_vector(vector: &Vector, ring: Ring, dimension: usize) -> Result<(), Error> {
    if vector.ring() != ring || vector.dimension() != dimension {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Rounds each component, optionally reducing modulo the rounded modulus.
pub fn round(vector: &Vector, bits: u32, reduce: bool) -> Result<Coefficients, Error> {
    let modulus = vector.ring().rounded_modulus(bits)?;
    vector
        .entries()
        .iter()
        .map(|p| {
            let mut row = p.round(bits)?;
            if reduce {
                for v in &mut row {
                    *v %= modulus;
                }
            }
            Ok(row)
        })
        .collect()
}

/// Lifts public integer coefficients by a power of two into R_q.
pub fn lift(values: &Coefficients, ring: Ring, bits: u32) -> Result<Vector, Error> {
    let entries = values
        .iter()
        .map(|row| {
            let row: Vec<_> = row
                .iter()
                .map(|&v| ((u128::from(v) << bits) % u128::from(ring.modulus())) as u64)
                .collect();
            ring.polynomial(&row)
        })
        .collect::<Result<_, _>>()?;
    Ok(Vector::new(entries)?)
}

/// Binds every long-term verification input rather than only its identifier.
pub fn append_key(transcript: &mut Transcript, key: &PublicKey) {
    transcript.append(b"parameters", &key.parameters.to_bytes());
    for row in key.matrix.rows() {
        transcript.append(b"matrix-row", &encode(&coefficients(row)));
    }
    transcript.append(b"rounded-key", &encode(&key.rounded_key));
}

/// Derives the identity of an immutable public share package.
pub fn package_id(package: &PublicKeyPackage) -> Identifier {
    let mut transcript = Transcript::new(Domain::Key);
    transcript.append(b"kind", b"share-package");
    append_key(&mut transcript, &package.key);
    transcript.append_u64(b"epoch", package.epoch);
    for (party, shares) in package.verification_shares.iter().enumerate() {
        transcript.append_u64(b"participant", party as u64 + 1);
        for (index, vector) in shares {
            transcript.append(b"path", index.to_string().as_bytes());
            transcript.append(b"share", &encode(&coefficients(vector)));
        }
    }
    transcript.digest()
}

/// Derives H_c from the verification key, message, and rounded aggregate.
pub fn challenge(
    key: &PublicKey,
    message: &[u8],
    commitment: &Coefficients,
) -> Result<Polynomial, Error> {
    let mut transcript = Transcript::new(Domain::Challenge);
    append_key(&mut transcript, key);
    transcript
        .append(b"message", message)
        .append(b"commitment", &encode(commitment));
    let c = key.parameters.config();
    Ok(transcript.challenge(c.ring, c.challenge_weight)?)
}

/// Validates signature shape and the norm bound without verifying H_c.
pub fn validate_signature(parameters: &Parameters, signature: &Signature) -> Result<(), Error> {
    let c = parameters.config();
    if signature.challenge.ring() != c.ring {
        return Err(Error::Malformed);
    }
    let mut weight = 0;
    for &v in signature.challenge.coefficients() {
        if v == 1 || v == c.ring.modulus() - 1 {
            weight += 1;
        } else if v != 0 {
            return Err(Error::Malformed);
        }
    }
    if weight != c.challenge_weight {
        return Err(Error::Malformed);
    }
    validate_vector(&signature.response, c.ring, c.columns)?;
    let modulus = c.ring.rounded_modulus(c.commitment_bits)?;
    validate(&signature.hint, c.ring, c.rows, modulus)?;
    let lifted_hint = lift(&signature.hint, c.ring, c.commitment_bits)?;
    if signature.response.norm_squared() + lifted_hint.norm_squared()
        > u128::from(parameters.signature_bound()).pow(2)
    {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

/// Checks one preprocessing token's metadata, dimensions, and canonical ranges.
pub fn validate_commitment(keys: &PublicKeyPackage, token: &Commitment) -> Result<(), Error> {
    let c = keys.key.parameters.config();
    if token.participant == 0 || token.participant > c.committee.parties() {
        return Err(Error::Participant);
    }
    if token.epoch != keys.epoch {
        return Err(Error::EpochMismatch);
    }
    if token.package_id != keys.id {
        return Err(Error::KeyMismatch);
    }
    if token.sequence >= keys.key.parameters.per_party_preprocessing_limit() {
        return Err(Error::Limit);
    }
    if token.values.len() != c.repetitions {
        return Err(Error::Malformed);
    }
    let bound =
        ((c.ring.modulus() - 1 + (1 << (c.preprocessing_bits - 1))) >> c.preprocessing_bits) + 1;
    for value in &token.values {
        validate(value, c.ring, c.rows, bound)?;
    }
    Ok(())
}

/// Hashes the full long-term verification key with its key-kind marker.
pub fn key_id(key: &PublicKey) -> Identifier {
    let mut transcript = Transcript::new(Domain::Key);
    transcript.append(b"kind", b"verification-key");
    append_key(&mut transcript, key);
    transcript.digest()
}

/// Validates public share dimensions and checks every authorized reconstruction.
pub fn reconstruct_public(key: &PublicKey, shares: &Shares<Vector>) -> Result<Vector, Error> {
    let c = key.parameters.config();
    c.committee.validate_layout(shares)?;
    for party in shares {
        for value in party.values() {
            validate_vector(value, c.ring, c.rows)?;
        }
    }
    Ok(c.committee.check(shares, |a, b| {
        a.add(b)
            .expect("all public-share rings and dimensions were validated")
    })?)
}
