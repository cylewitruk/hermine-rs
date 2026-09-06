# hermine-rs

A Rust implementation of [Hermine](https://hermine-th.org/), a lattice-based
threshold signature scheme with offline preprocessing, identifiable aborts, and
proactive refresh, based on [ePrint 2026/419](https://eprint.iacr.org/2026/419).

This research implementation provides ring and matrix
arithmetic, NTT, rounding, centered norms, integer-width discrete Gaussian
sampling, SHAKE transcripts, Vandermonde sharing, trusted-dealer key generation,
one-shot preprocessing, threshold signing, identifiable aborts, verification, and
dealer-assisted proactive refresh, and bounded wire codecs. No validated security
profile, constant-time guarantee, external audit, or official wire compatibility
is claimed.

See the [implementation plan](docs/IMPLEMENTATION.md) for the complete goal and
[specification notes](docs/SPECIFICATION.md) for paper discrepancies and decisions.
The current paper assumes trusted-dealer key generation; the DKG advertised on
the website is not fully specified by that paper.

[Sampling notes](docs/SAMPLING.md) document the exact-rational rejection method
and its finite-integer limits. [Transcript notes](docs/TRANSCRIPTS.md) specify the
local domain separation and field encoding.
[Protocol notes](docs/PROTOCOL.md) describe the signing API, parameter checks,
source mapping, and application responsibilities.
[Wire-format notes](docs/WIRE.md) specify canonical packets, validation boundaries,
resource limits, and confidential refresh-token handling.
[Architecture](docs/ARCHITECTURE.md), [benchmarks](docs/BENCHMARKS.md), and
[fuzzing instructions](fuzz/README.md) describe the implementation and its checks.
[Validation results](docs/VALIDATION.md) map the deliverables to their evidence:
68 passing integration tests, four Rustdoc tests, 94.71% library line coverage,
independent Python vectors, and two completed sanitizer fuzz runs.

An [experimental DKG implementation](docs/DKG.md) investigates
verifiable short Vandermonde sharing starting from the paper's recommendations;
no DKG security guarantees or production-use recommendations are made.
The [projection primitive](docs/DKG-SUBMERSION.md) and
[candidate verifiable contributions](docs/DKG-SHARING.md) feed
[consumed DKG rounds](docs/DKG-ROUNDS.md) through the `experimental-dkg` feature.
Their [experimental signing bridge](docs/DKG-COMPOSITION.md) uses explicit DKG
bounds and preserves nonce accounting across refreshes. Privacy and cryptographic
composition remain unproved. The explicit [uniform-mask variant](docs/DKG-UNIFORM-MASK.md)
provides a comparison with the Gaussian candidate; its
[hash-challenge proof obligations](docs/DKG-ORACLES.md) remain open.

```sh
cargo nextest run --all-targets --features experimental-dkg
cargo run --features experimental-dkg --example dkg_projection
cargo run --features experimental-dkg --example dkg_contribution
cargo run --features experimental-dkg --example dkg
cargo run --features experimental-dkg --example dkg -- --uniform
cargo run --features experimental-dkg --example dkg_transport
```

A separate [dealer-equivalent MPC prototype](docs/MPC.md) uses four-party
Maurer replicated sharing, a secret bounded Gaussian circuit, and 2-of-4 signing.
The `experimental-mpc` feature includes independent actors over an ideal local
transport, tests, and exact-arithmetic sampler certification. It targets one
static malicious participant; network deployment and security proofs remain open.

```sh
cargo run --release --features experimental-mpc --example mpc
python3 scripts/mpc_gaussian_table.py
```

## Development

Requires Rust 1.96 or later and cargo-nextest.

```sh
cargo nextest run --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo doc --no-deps
cargo run --example sharing
cargo run --example signing
cargo run --example refresh
cargo run --example identifiable_abort
cargo run --example transport
python3 scripts/check_vectors.py
cargo bench --bench protocol -- --iterations=30
```

For a coverage report with cargo-llvm-cov installed:

```sh
RUSTC_WRAPPER= CARGO_TARGET_DIR=target/coverage cargo llvm-cov nextest --all-targets --html
```

The sharing example uses deterministic integers to illustrate reconstruction;
it is not a cryptographic sampler. Polynomial and transformed coefficient storage
is zeroized on drop. The arithmetic backend currently uses variable-time modular
division and is intended for correctness validation and further implementation.
The coverage command disables compiler-cache path remapping to avoid duplicate
source paths in the report.

Independent Python implementations generate the checked-in primitive vectors:

```sh
python3 scripts/sampling_reference.py
python3 scripts/transcript_reference.py
python3 scripts/parameters_reference.py
python3 scripts/protocol_reference.py
```

The signing example uses operating-system randomness with deliberately insecure
small parameters. The Python protocol reference independently computes a complete
2-of-3 session using schoolbook convolution and exact integer arithmetic.
