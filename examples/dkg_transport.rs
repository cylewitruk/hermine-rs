//! DKG byte transport and fail-closed abort demonstrations with OS randomness.
//!
//! This harness simulates consistent authenticated broadcast and confidential
//! pairwise delivery; it does not implement network authentication or encryption.
//! Every scenario uses a fresh session and separate consumed participant states.

use std::{collections::BTreeMap, error::Error};

use hermine::dkg::{
    ContributionError, DkgConfig, DkgSession, Masking, ProjectionParameters, RoundError,
    SharingConfig,
    wire::{Codec, Limits},
};
use rand::rngs::SysRng;
use rand_core::TryRng;

mod support;

/// Delivery behavior exercised by one fresh simulated session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    /// All authenticated messages arrive unchanged.
    Honest,
    /// A contributor supplies a salt that does not open its commitment.
    AlteredOpening,
    /// A required first-round broadcast never arrives.
    MissingBroadcast,
    /// A second-round sender acknowledges a different contribution transcript.
    DisagreedAcknowledgment,
}

/// Runs both successful byte delivery and three independent abort scenarios.
fn main() -> Result<(), Box<dyn Error>> {
    for scenario in [
        Scenario::Honest,
        Scenario::AlteredOpening,
        Scenario::MissingBroadcast,
        Scenario::DisagreedAcknowledgment,
    ] {
        run(scenario)?;
    }
    println!("Research simulation only; a local rejection is not public blame evidence.");
    Ok(())
}

/// Owns all participants only as a network simulator, routing each private packet once.
fn run(scenario: Scenario) -> Result<(), Box<dyn Error>> {
    let signing = support::parameters()?.config().clone();
    let mut rng = SysRng;
    let mut session_id = [0; 64];
    rng.try_fill_bytes(&mut session_id)?;
    let session = DkgSession::new(
        DkgConfig {
            sharing: SharingConfig {
                projection: ProjectionParameters::for_consistency(
                    signing.ring,
                    signing.rows + signing.columns,
                )?,
                committee: signing.committee,
                input_sigma: 1,
                masking: Masking::Uniform,
                private_limit: 64,
            },
            root: signing.root,
            columns: signing.columns,
        },
        &session_id,
    )?;
    let codec = Codec::new(&session, Limits::default())?;
    let mut states = BTreeMap::new();
    let mut broadcast_bytes = BTreeMap::new();
    let mut incoming: BTreeMap<_, BTreeMap<_, _>> = (1..=3).map(|p| (p, BTreeMap::new())).collect();
    for sender in 1..=3 {
        let round = session.start(sender, &mut rng)?;
        broadcast_bytes.insert(sender, codec.encode_contribution(&round.broadcast)?);
        for (recipient, mut payload) in round.private {
            if scenario == Scenario::AlteredOpening && sender == 2 && recipient == 1 {
                payload.salt[0] ^= 1;
            }
            let packet = codec.encode_private_contribution(&payload)?;
            incoming
                .get_mut(&recipient)
                .ok_or("unknown recipient")?
                .insert(sender, packet);
        }
        states.insert(sender, round.state);
    }
    if scenario == Scenario::MissingBroadcast {
        broadcast_bytes.remove(&2);
    }
    let mut next = BTreeMap::new();
    let mut verification_bytes = BTreeMap::new();
    for (recipient, state) in states {
        // Map keys stand in for authenticated channel identities, not packet fields.
        let broadcasts = broadcast_bytes
            .iter()
            .map(|(&sender, packet)| Ok((sender, codec.decode_contribution(sender, packet)?)))
            .collect::<Result<_, Box<dyn Error>>>()?;
        let private = incoming
            .remove(&recipient)
            .ok_or("missing inbox")?
            .into_iter()
            .map(|(sender, packet)| {
                // Packet ownership erases the decrypted buffer after this decode.
                Ok((
                    sender,
                    codec.decode_private_contribution(sender, recipient, packet.as_bytes())?,
                ))
            })
            .collect::<Result<_, Box<dyn Error>>>()?;
        let mut round = match state.accept(broadcasts, private) {
            Ok(round) => round,
            Err(RoundError::Contribution {
                participant: 2,
                error: ContributionError::Commitment,
            }) if scenario == Scenario::AlteredOpening => {
                println!("{scenario:?}: rejected the private opening; no DKG output released.");
                return Ok(());
            }
            Err(RoundError::Participants) if scenario == Scenario::MissingBroadcast => {
                println!(
                    "{scenario:?}: rejected the incomplete sender set; no DKG output released."
                );
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if scenario == Scenario::DisagreedAcknowledgment && recipient == 2 {
            round.broadcast.agreement[0] ^= 1;
        }
        verification_bytes.insert(recipient, codec.encode_verification(&round.broadcast)?);
        next.insert(recipient, round.state);
    }
    let mut common = None;
    for (recipient, state) in next {
        let messages = verification_bytes
            .iter()
            .map(|(&sender, bytes)| Ok((sender, codec.decode_verification(sender, bytes)?)))
            .collect::<Result<_, Box<dyn Error>>>()?;
        let output = match state.finish(messages) {
            Ok(output) => output,
            Err(RoundError::Binding) if scenario == Scenario::DisagreedAcknowledgment => {
                println!(
                    "{scenario:?}: rejected the transcript disagreement; no DKG output released."
                );
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if common.is_some_and(|id| output.public().id() != &id) {
            return Err("completed outputs disagree".into());
        }
        common = Some(*output.public().id());
        println!(
            "{scenario:?}: party {recipient} completed byte transport with {} local shares.",
            output.shares().len()
        );
    }
    if scenario != Scenario::Honest {
        return Err("expected an abort".into());
    }
    Ok(())
}
