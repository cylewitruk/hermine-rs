//! One candidate verifiable contribution and a rejected private-payload alteration.
//!
//! This in-process harness stands in for confidential delivery and consistent
//! broadcast. It does not implement DKG agreement or produce signing keys.

use std::error::Error;

use hermine::{
    dkg::{ContributionError, Masking, ProjectionParameters, SharingConfig, SharingSession},
    ring::Ring,
    sharing::Vandermonde,
};
use rand::rngs::SysRng;
use rand_core::TryRng;

/// Simulates one contributor and three independent recipient validation steps.
fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = SysRng;
    let mut session_id = [0; 64];
    rng.try_fill_bytes(&mut session_id)?;
    let session = SharingSession::new(
        SharingConfig {
            projection: ProjectionParameters::new(Ring::new(4, 12289)?, 2, 256)?,
            committee: Vandermonde::new(2, 3)?,
            input_sigma: 1,
            masking: Masking::Gaussian { sigma: 8 },
            private_limit: 64,
        },
        &session_id,
    )?;
    let mut contribution = session.contribute(1, &mut rng)?;
    for private in &contribution.recipients {
        let checked = session.check_contribution(1, contribution.public.clone())?;
        checked.check_recipient(private.recipient, private)?;
    }
    println!("All three recipients accepted one experimental short-sharing contribution.");

    let checked = session.check_contribution(1, contribution.public)?;
    contribution.recipients[0].salt[0] ^= 1;
    match checked.check_recipient(1, &contribution.recipients[0]) {
        Err(ContributionError::Commitment) => println!("Altered private payload rejected."),
        Err(error) => return Err(error.into()),
        Ok(()) => return Err("altered private payload was accepted".into()),
    }
    println!("Contribution experiment only; see the dkg example for the candidate rounds.");
    Ok(())
}
