# Benchmarks

Run the release harness with an explicit sample count:

```sh
cargo bench --bench protocol -- --iterations=30
```

It prints CSV with arithmetic-mean microseconds per operation. Each iteration
generates a fresh key, preprocesses for two participants, signs, verifies,
encodes/decodes the signature, and refreshes all shares. Randomness uses `StdRng`
seeded from the operating system. Setup for earlier stages is excluded from later
timers. Verified aggregation includes its own partial and final verification;
the separate verification measurements are additional observations, not costs to
add to the aggregation measurement.

The workload uses degree 512, modulus 998244353, a 4-by-3 matrix, a 2-of-3 committee,
challenge weight 32, 14 repetitions, and explicit Gaussian widths 1024 and 2^17.
The complete configuration is in `benches/protocol.rs`. These are **uncertified
benchmark parameters**, unsuitable for selecting a deployment security level.
They do not reproduce the paper's Table 3 profiles or benchmark methodology.

Example local run on 2026-09-05: aarch64 macOS 26.5.2, Rust 1.98.0, 30 iterations.
These are illustrative measurements from one machine, without a performance
guarantee or comparison against the authors' implementation.

| Operation | Samples | Mean microseconds |
| ---- | ---- | ---- |
| Dealer key generation | 30 | 6281.047 |
| Preprocess one participant | 60 | 33551.231 |
| Build signing package | 30 | 1523.035 |
| Sign one participant | 60 | 841.083 |
| Verify one partial response | 60 | 1166.844 |
| Verified aggregation | 30 | 4680.040 |
| Verify final signature | 30 | 1242.608 |
| Dealer refresh | 30 | 4226.132 |
| Apply refresh to all shares | 30 | 824.533 |
| Encode signature | 30 | 24.267 |
| Decode signature | 30 | 19.001 |

The harness accepts `--iterations=1..10000`; it does not set a timing threshold in
CI. Rejection sampling and modular arithmetic are variable-time, so throughput
measurements do not establish side-channel resistance.

Experimental DKG phase and transport measurements are documented separately in
[DKG-BENCHMARKS.md](DKG-BENCHMARKS.md), with explicit parameters and a public seed.
