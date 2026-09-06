//! Shared framing for experimental DKG subprotocols.

use crate::{
    ring::Polynomial,
    transcript::{Domain, Transcript},
};

/// Starts a framed DKG subprotocol transcript.
pub fn transcript(kind: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(Domain::Dkg);
    transcript.append(b"kind", kind);
    transcript
}

/// Streams a canonical polynomial with its purpose and explicit ring identity.
pub fn append_polynomial(transcript: &mut Transcript, kind: &[u8], polynomial: &Polynomial) {
    transcript
        .append(b"polynomial", kind)
        .append_u64(b"degree", polynomial.ring().degree() as u64)
        .append_u64(b"modulus", polynomial.ring().modulus());
    for &value in polynomial.coefficients() {
        transcript.append_u64(b"coefficient", value);
    }
}
