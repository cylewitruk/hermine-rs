//! Four independent MPC actors; only two remain online to sign.
//! Tiny parameters and an ideal in-process transport are for experiments only.

use hermine::{
    Commitment, PartialSignature, PublicKeyPackage, SigningPackage,
    mpc::{
        self, Statistics,
        local::{self, Endpoint},
    },
    parameters::Config,
    sharing::Vandermonde,
};
use rand::rngs::SysRng;
use rand_core::TryRng;
use std::{
    error::Error,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

mod support;

/// Public completion notification, optionally including a signing commitment.
struct Ready {
    /// Common public key package.
    public: PublicKeyPackage,
    /// Public preprocessing token of a selected signer.
    commitment: Option<Commitment>,
    /// This participant's circuit costs.
    statistics: Statistics,
}

/// Generates and retains one private output, then optionally answers a signing request.
fn actor(
    config: Config,
    session: [u8; 64],
    mut endpoint: Endpoint,
    selected: bool,
    ready: Sender<Ready>,
    request: Receiver<SigningPackage>,
) -> Result<Option<PartialSignature>, mpc::Error> {
    let mut output = mpc::keygen(config, session, &mut endpoint, &mut SysRng)?;
    drop(endpoint);
    let nonce = if selected {
        Some(output.secret.preprocess(&output.public, &mut SysRng)?)
    } else {
        None
    };
    ready
        .send(Ready {
            public: output.public.clone(),
            commitment: nonce.as_ref().map(|n| n.commitment().clone()),
            statistics: output.statistics,
        })
        .map_err(|_| mpc::Error::Transport)?;
    drop(ready);
    if let Some(nonce) = nonce {
        let package = request
            .recv_timeout(Duration::from_secs(60))
            .map_err(|_| mpc::Error::Transport)?;
        Ok(Some(output.secret.sign(&output.public, &package, nonce)?))
    } else {
        // Non-signers are now offline. Their private outputs never enter the coordinator.
        Ok(None)
    }
}

/// Coordinates public messages without receiving any participant's private shares.
fn main() -> Result<(), Box<dyn Error>> {
    let mut config = support::parameters()?.config().clone();
    config.committee = Vandermonde::new(2, 4)?;
    config.refresh_limit = 0;
    let mut session = [0; 64];
    SysRng.try_fill_bytes(&mut session)?;
    let start = Instant::now();
    let endpoints = local::network(Duration::from_secs(60))?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut requests = Vec::new();
    let mut handles = Vec::new();
    for (party, endpoint) in endpoints.into_iter().enumerate() {
        let (request_tx, request_rx) = mpsc::channel();
        requests.push(request_tx);
        let ready = ready_tx.clone();
        let config = config.clone();
        handles.push(thread::spawn(move || {
            actor(
                config,
                session,
                endpoint,
                party == 0 || party == 3,
                ready,
                request_rx,
            )
        }));
    }
    drop(ready_tx);
    let mut completed = Vec::new();
    for _ in 0..4 {
        completed.push(ready_rx.recv_timeout(Duration::from_secs(60))?);
    }
    let elapsed = start.elapsed();
    let public = completed[0].public.clone();
    assert!(completed.iter().all(|o| o.public.id() == public.id()));
    let message = b"Hermine dealer-equivalent MPC prototype";
    let mut commitments: Vec<_> = completed
        .iter_mut()
        .filter_map(|o| o.commitment.take())
        .collect();
    commitments.sort_by_key(|commitment| commitment.participant);
    let request = SigningPackage::new(&public, message, commitments)?;
    for index in [0, 3] {
        requests[index].send(request.clone())?;
    }
    let mut responses = Vec::new();
    for handle in handles {
        if let Some(response) = handle.join().expect("MPC actor panicked")? {
            responses.push(response);
        }
    }
    let signature = request.aggregate(&public, &responses)?;
    public.key().verify(message, &signature)?;
    let bytes: u64 = completed.iter().map(|o| o.statistics.sent_words * 8).sum();
    let stats = completed[0].statistics;
    println!("Verified 2-of-4 signature; MPC plus selected-signers' preprocessing: {elapsed:?}");
    println!(
        "{} rounds; {} logical remote bytes; {} gates per participant; {} peak outgoing payload bytes per participant",
        stats.rounds,
        bytes,
        stats.multiplication_gates,
        stats.peak_outgoing_words * 8
    );
    Ok(())
}
