//! Bounded DKG decoding with exact re-encoding for both experimental variants.
#![no_main]

use std::sync::OnceLock;

use hermine::{
    dkg::{
        DkgConfig, DkgSession, Masking, ProjectionParameters, SharingConfig,
        wire::{Codec, Limits},
    },
    ring::Ring,
    sharing::Vandermonde,
};
use libfuzzer_sys::fuzz_target;

/// Caches both independently seeded wire profiles outside per-input work.
fn codecs() -> &'static [Codec; 2] {
    static CODECS: OnceLock<[Codec; 2]> = OnceLock::new();
    CODECS.get_or_init(|| {
        [false, true].map(|uniform| {
            let ring = Ring::new(4, 12289).unwrap();
            let projection = if uniform {
                ProjectionParameters::for_consistency(ring, 2).unwrap()
            } else {
                ProjectionParameters::new(ring, 2, 256).unwrap()
            };
            let session = DkgSession::new(
                DkgConfig {
                    sharing: SharingConfig {
                        projection,
                        committee: Vandermonde::new(2, 3).unwrap(),
                        input_sigma: 1,
                        masking: if uniform {
                            Masking::Uniform
                        } else {
                            Masking::Gaussian { sigma: 8 }
                        },
                        private_limit: 64,
                    },
                    root: 4043,
                    columns: 1,
                },
                &[42; 64],
            )
            .unwrap();
            Codec::new(
                &session,
                Limits {
                    packet_bytes: 16_384,
                    indexed_shares: 5,
                },
            )
            .unwrap()
        })
    })
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 3 {
        return;
    }
    let codec = &codecs()[usize::from(input[0] & 1)];
    let sender = input[1];
    let recipient = input[2];
    let packet = &input[3..];
    if let Ok(message) = codec.decode_contribution(sender, packet) {
        assert_eq!(codec.encode_contribution(&message).unwrap(), packet);
    }
    if let Ok(message) = codec.decode_private_contribution(sender, recipient, packet) {
        assert_eq!(
            codec
                .encode_private_contribution(&message)
                .unwrap()
                .as_bytes(),
            packet
        );
    }
    if let Ok(message) = codec.decode_verification(sender, packet) {
        assert_eq!(codec.encode_verification(&message).unwrap(), packet);
    }
});
