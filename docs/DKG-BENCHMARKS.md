# Experimental DKG benchmarks

```sh
cargo bench --features experimental-dkg --bench dkg --locked -- --iterations=10 --seed=20260906
```

The release harness prints CSV arithmetic-mean microseconds on stdout and encoded
byte counts on stderr. It accepts `--iterations=1..10000` and a u64 public seed.
The pinned dependency graph and fixed seed make input generation repeatable;
wall-clock timings remain machine- and load-dependent. No network is measured.

## Workload and timing boundaries

Both Gaussian and uniform variants use degree 512, modulus 998244353, NTT root
258648936, a 4-by-3 matrix, input width 1024, and private coefficient limit 32768.
The Gaussian comparison adds mask width 131072 and response limit 4194304. Each
variant runs a 2-of-3 and 3-of-5 committee. The signing import uses challenge
weight 32, 14 repetitions, and the explicit configuration in `benches/dkg.rs`.
These are uncertified arithmetic workloads, not the paper's Table 3 profiles or
recommended security parameters.

Each iteration uses a distinct public session identifier and samples fresh
contributions from the benchmark stream. It encodes each sender's broadcast once,
decodes it separately for each recipient, routes every confidential packet to its
owner, completes every consumed round, checks agreement, and imports every local
output into the experimental signing profile. A sampling/validation failure stops
the run rather than being silently retried or omitted from the report.

| Operation | Timed work | Samples per iteration |
| ---- | ---- | ---- |
| Setup | Session validation, context construction, and NTT setup | 1 |
| Contribute party | Input/mask sampling, sharing, commitments, projection, and local public checks | N |
| Accept party | All incoming public/private contribution checks, private aggregation, matrix derivation, and local public images | N |
| Finish party | All acknowledgments, public-image consistency, and output identity | N |
| Import party | DKG signing bounds, material pins, local image checks, and signing package construction | N |
| Encode contribution/verification | One sender's public packet | N each |
| Decode contribution/verification | Each receiver's independent public-message decoding, including its own message | N² each |
| Encode/decode private | Each confidential sender-recipient packet, excluding self-delivery | N(N-1) each |

Input preparation and earlier phases are outside a later operation's timer.
Successful results are passed through `black_box`. Local state and caches are
created as in the normal API; there is no parallel participant execution, warm-up
pass, CPU pinning, or confidence-interval calculation. Means include first-use
costs and may be affected by cache, scheduling, or thermal changes. The four
profiles run in the listed order, so small between-variant differences should
not be interpreted as an algorithmic speed advantage.

## Recorded local run

2026-09-06, aarch64 macOS 26.5.2, Rust 1.98.0, release mode, ten iterations per
profile, seed 20260906. All iterations completed without validation failure.
The [complete CSV](data/dkg-benchmark.csv) includes codec measurements and counts.

| Mean microseconds | Gaussian 2-of-3 | Uniform 2-of-3 | Gaussian 3-of-5 | Uniform 3-of-5 |
| ---- | ---- | ---- | ---- | ---- |
| Setup | 24.571 | 9.967 | 10.575 | 12.762 |
| Contribute party | 9973.289 | 9271.196 | 26122.298 | 27443.897 |
| Accept party | 6238.546 | 6288.101 | 15585.022 | 16260.665 |
| Finish party | 813.329 | 806.539 | 1726.212 | 1791.233 |
| Import party | 1514.190 | 1507.592 | 1873.130 | 1959.721 |

Both variants have the same fixed packet dimensions:

| Encoded bytes per session | 2-of-3 | 3-of-5 |
| ---- | ---- | ---- |
| Contribution broadcasts, each encoded once | 31,509 | 155,555 |
| All private sender-recipient deliveries | 308,208 | 1,846,560 |
| Verification broadcasts, each encoded once | 82,325 | 246,435 |

These byte counts exclude authentication, encryption, framing by the application,
and broadcast implementation overhead. Sending every broadcast separately to
N-1 peers multiplies each public total by N-1. They are not measured network
traffic. The benchmark does not time a distributed broadcast protocol or establish
constant-time behavior, completeness probabilities, or cryptographic security.
