//! Complete MPC-to-signing integration and invocation-boundary tests.
#![cfg(feature = "experimental-mpc")]

use hermine::{
    KeySet, dealer_keygen,
    mpc::{self, Transport, local},
    parameters::{Config, KeyOrigin, Parameters},
    wire::{Codec, Limits},
};
use std::{thread, time::Duration};

#[path = "support/protocol.rs"]
mod protocol;
mod support;
use support::TestRng;

/// Returns a small 2-of-4 profile supported by the prototype.
fn config() -> Config {
    let mut c = protocol::parameters(2, 4).config().clone();
    c.refresh_limit = 0;
    c
}

#[test]
fn independent_mpc_outputs_sign_with_every_threshold_subset() {
    let endpoints = local::network(Duration::from_secs(30)).unwrap();
    let handles: Vec<_> = endpoints
        .into_iter()
        .enumerate()
        .map(|(party, mut endpoint)| {
            thread::spawn(move || {
                let mut rng = TestRng::new(&[party as u8, 81]);
                mpc::keygen(config(), [73; 64], &mut endpoint, &mut rng).unwrap()
            })
        })
        .collect();
    let outputs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let public = outputs[0].public.clone();
    for (party, output) in outputs.iter().enumerate() {
        assert_eq!(output.public.id(), public.id());
        assert_eq!(output.secret.participant(), party as u8 + 1);
        assert_eq!(output.statistics.rounds, 995);
        assert_eq!(output.statistics.multiplication_gates, 29184);
    }
    std::assert_matches!(
        public.key().parameters().origin(),
        KeyOrigin::ExperimentalMpc { session: [73, ..] }
    );
    let codec = Codec::new(public.key().parameters().clone(), Limits::default());
    let bytes = codec.encode_public_package(&public).unwrap();
    assert_eq!(
        codec.decode_public_package(&bytes).unwrap().id(),
        public.id()
    );
    let other = Codec::new(
        Parameters::for_mpc(config(), [74; 64]).unwrap(),
        Limits::default(),
    );
    assert!(other.decode_public_package(&bytes).is_err());
    let mut keys = KeySet {
        public,
        shares: outputs.into_iter().map(|o| o.secret).collect(),
    };
    let mut rng = TestRng::new(b"MPC signing tests");
    for a in 0..4 {
        for b in a + 1..4 {
            let message = [a as u8, b as u8, 199];
            let (request, responses) = protocol::session(&mut keys, &[a, b], &message, &mut rng);
            let signature = request.aggregate(&keys.public, &responses).unwrap();
            keys.public.key().verify(&message, &signature).unwrap();
            assert!(
                keys.public
                    .key()
                    .verify(b"other message", &signature)
                    .is_err()
            );
        }
    }
    std::assert_matches!(
        dealer_keygen(keys.public.key().parameters().clone(), &mut rng),
        Err(hermine::Error::KeyOrigin)
    );
}

#[test]
fn unsupported_profiles_are_rejected_without_sampling() {
    let mut variants = vec![];
    let mut c = config();
    c.secret_sigma = 2;
    variants.push(c);
    let mut c = config();
    c.refresh_limit = 1;
    variants.push(c);
    variants.push(protocol::parameters(2, 3).config().clone());
    let mut c = config();
    c.rows = 64;
    c.columns = 64;
    variants.push(c);
    for c in variants {
        let mut endpoints = local::network(Duration::from_secs(1)).unwrap();
        let mut rng = TestRng::new(b"unused entropy");
        assert!(mpc::keygen(c, [1; 64], &mut endpoints[0], &mut rng).is_err());
        assert_eq!(rng.bytes_read, 0);
    }
    assert!(Parameters::for_mpc(config(), [0; 64]).is_err());
    let a = Parameters::for_mpc(config(), [1; 64]).unwrap();
    let b = Parameters::for_mpc(config(), [2; 64]).unwrap();
    assert_ne!(a.to_bytes(), b.to_bytes());
    assert_eq!(&a.to_bytes()[..8], &3u64.to_le_bytes());
}

#[test]
fn mismatched_sessions_and_entropy_failure_abort_peers() {
    for mismatch in [true, false] {
        let handles: Vec<_> = local::network(Duration::from_secs(5))
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(party, mut endpoint)| {
                thread::spawn(move || {
                    let mut rng = TestRng::new(&[party as u8]);
                    if !mismatch && party == 0 {
                        rng.fail_after = 0;
                    }
                    let session = if mismatch && party == 0 {
                        [2; 64]
                    } else {
                        [1; 64]
                    };
                    let result = mpc::keygen(config(), session, &mut endpoint, &mut rng);
                    if result.is_err() {
                        endpoint.abort();
                    }
                    result
                })
            })
            .collect();
        for handle in handles {
            assert!(handle.join().unwrap().is_err());
        }
    }
}

#[test]
fn confidential_payload_debug_is_redacted() {
    let payload = mpc::Payload::new(vec![123456789]);
    assert!(!format!("{payload:?}").contains("123456789"));
}
