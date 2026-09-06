//! Bounded parser and canonical re-encoding checks for every wire message type.
#![no_main]

use std::sync::OnceLock;

use hermine::{
    PublicKeyPackage, VerifiedRefresh,
    parameters::{Config, Parameters},
    ring::Ring,
    sharing::Vandermonde,
    wire::{Codec, Limits},
};
use libfuzzer_sys::fuzz_target;

/// Immutable public fixture used by all parser invocations.
struct Context {
    /// Codec pinned to the independent vector's tiny parameters.
    codec: Codec,
    /// Authenticated public package represented by the seed fixture.
    keys: PublicKeyPackage,
    /// Validated next epoch for confidential token decoding.
    refresh: VerifiedRefresh,
}

/// Loads one public-seed wire fixture without an external file at runtime.
fn packet(label: &str) -> Vec<u8> {
    let text = include_str!("../../tests/data/wire.txt");
    let hex = text
        .lines()
        .find_map(|line| line.strip_prefix(label).and_then(|s| s.strip_prefix(' ')))
        .unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Initializes the known public context once, outside per-input decoding work.
fn context() -> &'static Context {
    static CONTEXT: OnceLock<Context> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        let parameters = Parameters::new(Config {
            ring: Ring::new(16, 12289).unwrap(),
            root: 5860,
            committee: Vandermonde::new(2, 3).unwrap(),
            rows: 2,
            columns: 2,
            entropy_bits: 8,
            challenge_weight: 3,
            repetitions: 5,
            secret_sigma: 1,
            nonce_sigma: 8,
            public_key_bits: 1,
            commitment_bits: 2,
            preprocessing_bits: 1,
            tail_multiplier: 2,
            preprocessing_limit: 1000,
            refresh_limit: 2,
        })
        .unwrap();
        let codec = Codec::new(
            parameters,
            Limits {
                packet_bytes: 4096,
                message_bytes: 1024,
                indexed_shares: 64,
            },
        );
        let keys = codec.decode_public_package(&packet("package")).unwrap();
        let refresh = codec
            .decode_refresh_proposal(&keys, &packet("proposal"))
            .unwrap()
            .verify(&keys)
            .unwrap();
        Context {
            codec,
            keys,
            refresh,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Context {
        codec,
        keys,
        refresh,
    } = context();
    if let Ok(value) = codec.decode_public_key(data) {
        assert_eq!(codec.encode_public_key(&value).unwrap(), data);
    }
    if let Ok(value) = codec.decode_public_package(data) {
        assert_eq!(codec.encode_public_package(&value).unwrap(), data);
    }
    if let Ok(value) = codec.decode_commitment(keys, data) {
        assert_eq!(codec.encode_commitment(keys, &value).unwrap(), data);
    }
    if let Ok(value) = codec.decode_signing_package(keys, data) {
        assert_eq!(codec.encode_signing_package(keys, &value).unwrap(), data);
    }
    if let Ok(value) = codec.decode_partial_signature(data) {
        assert_eq!(codec.encode_partial_signature(&value).unwrap(), data);
    }
    if let Ok(value) = codec.decode_signature(data) {
        assert_eq!(codec.encode_signature(&value).unwrap(), data);
    }
    if let Ok(value) = codec.decode_refresh_proposal(keys, data) {
        assert_eq!(codec.encode_refresh_proposal(keys, &value).unwrap(), data);
    }
    if let Ok(value) = codec.decode_refresh_token(keys, refresh, data) {
        assert_eq!(
            codec
                .encode_refresh_token(keys, refresh, &value)
                .unwrap()
                .as_bytes(),
            data
        );
    }
});
