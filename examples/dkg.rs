//! Complete candidate DKG rounds with separate participant states and OS entropy.
//!
//! This in-process harness simulates confidential authenticated channels and
//! consistent broadcast. These tiny parameters have no security claim. The
//! completed outputs sign and receive dealer-assisted zero-share refreshes under
//! explicit DKG correctness bounds. Cryptographic composition remains unproved.

use std::{collections::BTreeMap, env, error::Error};

use hermine::{
    Signature, SigningPackage, dealer_refresh,
    dkg::{DkgConfig, DkgSession, Masking, ParticipantKeys, ProjectionParameters, SharingConfig},
};
use rand::rngs::SysRng;
use rand_core::TryRng;

mod support;

/// Routes private messages to their owners and common broadcasts to all parties.
fn main() -> Result<(), Box<dyn Error>> {
    let uniform = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--uniform" => true,
        _ => return Err("usage: dkg [--uniform]".into()),
    };
    let mut rng = SysRng;
    let signing = support::parameters()?.config().clone();
    let components = signing.rows + signing.columns;
    let (projection, masking) = if uniform {
        (
            ProjectionParameters::for_consistency(signing.ring, components)?,
            Masking::Uniform,
        )
    } else {
        (
            ProjectionParameters::new(signing.ring, components, 256)?,
            Masking::Gaussian { sigma: 8 },
        )
    };
    println!("Experimental mask variant: {masking:?}");
    let mut session_id = [0; 64];
    rng.try_fill_bytes(&mut session_id)?;
    let session = DkgSession::new(
        DkgConfig {
            sharing: SharingConfig {
                projection,
                committee: signing.committee,
                input_sigma: 1,
                masking,
                private_limit: 64,
            },
            root: signing.root,
            columns: signing.columns,
        },
        &session_id,
    )?;
    let mut states = BTreeMap::new();
    let mut broadcast = BTreeMap::new();
    let mut inboxes: BTreeMap<_, BTreeMap<_, _>> = (1..=3).map(|p| (p, BTreeMap::new())).collect();
    for sender in 1..=3 {
        let round = session.start(sender, &mut rng)?;
        for (recipient, payload) in round.private {
            inboxes
                .get_mut(&recipient)
                .ok_or("unknown recipient")?
                .insert(sender, payload);
        }
        states.insert(sender, round.state);
        broadcast.insert(sender, round.broadcast);
    }
    let mut next = BTreeMap::new();
    let mut acknowledgments = BTreeMap::new();
    for (participant, state) in states {
        let incoming = inboxes
            .remove(&participant)
            .ok_or("missing private delivery")?;
        let round = state.accept(broadcast.clone(), incoming)?;
        acknowledgments.insert(participant, round.broadcast);
        next.insert(participant, round.state);
    }
    let mut common_id = None;
    let mut participants = BTreeMap::new();
    for (participant, state) in next {
        let output = state.finish(acknowledgments.clone())?;
        if let Some(id) = common_id {
            if output.public().id() != &id {
                return Err("public output disagreement".into());
            }
        } else {
            common_id = Some(*output.public().id());
        }
        println!(
            "Party {participant} accepted the common output and retained {} private indexed shares.",
            output.shares().len()
        );
        participants.insert(participant, output.into_signing(signing.clone())?);
    }
    let signature = sign(&mut participants, &[1, 3], b"before refresh", &mut rng)?;
    let public = participants.get(&1).ok_or("missing party")?.public.clone();
    let refresh = dealer_refresh(&public, &mut rng)?;
    let verified = refresh.public.verify(&public)?;
    for token in refresh.tokens {
        let participant = participants
            .get_mut(&token.participant)
            .ok_or("wrong refresh recipient")?;
        let issued = participant.secret.issued();
        participant
            .secret
            .apply_refresh(&participant.public, &verified, token)?;
        participant.public = verified.next().clone();
        assert_eq!(participant.secret.issued(), issued);
    }
    sign(&mut participants, &[2, 3], b"after refresh", &mut rng)?;
    verified
        .next()
        .key()
        .verify(b"before refresh", &signature)?;
    println!("Two different subsets signed before and after a verified zero-share refresh.");
    println!("The original signature remains valid and nonce reservations were preserved.");
    println!("Research composition only; DKG privacy and unforgeability remain unproved.");
    Ok(())
}

/// Signs locally and aggregates public responses for one authorized subset.
fn sign(
    participants: &mut BTreeMap<u8, ParticipantKeys>,
    active: &[u8],
    message: &[u8],
    rng: &mut SysRng,
) -> Result<Signature, Box<dyn Error>> {
    let public = participants
        .get(&active[0])
        .ok_or("missing signer")?
        .public
        .clone();
    let mut nonces = Vec::new();
    for participant in active {
        let local = participants.get_mut(participant).ok_or("missing signer")?;
        nonces.push(local.secret.preprocess(&local.public, rng)?);
    }
    let request = SigningPackage::new(
        &public,
        message,
        nonces
            .iter()
            .map(|nonce| nonce.commitment().clone())
            .collect(),
    )?;
    let mut responses = Vec::new();
    for (participant, nonce) in active.iter().zip(nonces) {
        let local = participants.get(participant).ok_or("missing signer")?;
        responses.push(local.secret.sign(&local.public, &request, nonce)?);
    }
    let signature = request.aggregate(&public, &responses)?;
    public.key().verify(message, &signature)?;
    Ok(signature)
}
