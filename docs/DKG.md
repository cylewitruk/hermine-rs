# Experimental Hermine DKG

The `experimental-dkg` feature provides two research candidates, consumed DKG
rounds, a signing bridge, bounded codecs, examples, independent tests, fuzzing,
and benchmarks. **Neither candidate has an established DKG security theorem.**
No security guarantees or production-use recommendations are made.

The [construction review](DKG-REVIEW.md) records the implementation assessment and
requirement audit. The result is an explicit executable research construction
with conditional arguments and unresolved proof obligations, not a claim that
the paper already specifies or proves this DKG.

## Start here

```sh
cargo nextest run --all-targets --all-features --locked
cargo test --doc --all-features --locked
cargo run --features experimental-dkg --example dkg
cargo run --features experimental-dkg --example dkg -- --uniform
cargo run --features experimental-dkg --example dkg_transport
```

The complete example performs DKG, signing with different authorized subsets,
and dealer-assisted zero-share refresh. The transport example exercises canonical
bytes and three abort cases. Both use OS randomness and deliberately uncertified
parameters. Their network harnesses simulate separate participants; an actual
participant must receive only its own confidential deliveries.

| Topic | Specification and evidence |
| ---- | ---- |
| Source-inspired projection and shortness predicate | [DKG-SUBMERSION.md](DKG-SUBMERSION.md) |
| Gaussian-mask contribution and recipient checks | [DKG-SHARING.md](DKG-SHARING.md) |
| Uniform masks and fixed-projection privacy identity | [DKG-UNIFORM-MASK.md](DKG-UNIFORM-MASK.md) |
| Session setup, consumed rounds, and agreement | [DKG-ROUNDS.md](DKG-ROUNDS.md) |
| Signing/refresh bounds and material provenance | [DKG-COMPOSITION.md](DKG-COMPOSITION.md) |
| Canonical transport, private buffers, and abort example | [DKG-WIRE.md](DKG-WIRE.md) |
| Fiat–Shamir, simulation, and quantum proof gaps | [DKG-ORACLES.md](DKG-ORACLES.md) |
| Short-share leakage, convolution, and completeness | [DKG-DISTRIBUTION.md](DKG-DISTRIBUTION.md) |
| Reproducible phase timings and byte accounting | [DKG-BENCHMARKS.md](DKG-BENCHMARKS.md) |
| Construction review and requirement audit | [DKG-REVIEW.md](DKG-REVIEW.md) |

## Primary-source baseline

| Source | Relevant material and interpretation |
| ---- | ---- |
| [Hermine, ePrint 2026/419](https://eprint.iacr.org/2026/419), 2026-08-20 revision | Sections 1.2–1.3 recommend individual short contributions and verifiable Vandermonde sharing; concrete DKG security analysis is deferred. Figures 5–7 supply the sharing/signing baseline |
| [Flood and Submerse, ePrint 2024/959](https://eprint.iacr.org/2024/959) | Figure 4, Sections 4.3, 5.1, 6, and Appendix E motivate the projection mechanism. Its Shamir-sharing and Pelican theorems are not automatically Hermine theorems |
| [Earlier short-sharing work, ePrint 2025/871](https://eprint.iacr.org/2025/871) | Withdrawn and superseded; no algorithm is inferred from its abstract |
| [Quorus, ePrint 2025/1163](https://eprint.iacr.org/2025/1163) | Alternative replicated-sharing/MPC direction; Hermine identifies extension to Vandermonde as open |
| [ZF FROST DKG](https://docs.rs/frost-core/latest/frost_core/keys/dkg/index.html) | Engineering reference for transport and round state; its discrete-log commitments/proofs are not used as the post-quantum mechanism |

Flood and Submerse was retrieved on 2026-09-06: 76 pages, SHA-256
`ac0e1e3d0d0a650c79799e66ad4173537d10c64972082b77d434100dd85f0f58`.
The algorithms on page 20 and distribution/bound statements on page 30 were
visually checked. The Hermine baseline and digest are in `IMPLEMENTATION.md`.
Additional primary proof sources and their applicability limits are in
`DKG-ORACLES.md` and `DKG-SUBMERSION.md`.

## Threat model and application contract

The candidate targets static malicious corruption of fewer than T parties,
confidentiality of honest contributions under the documented leakage model,
and agreement/correctness with abort. These are intended properties; the ledger
below distinguishes implemented checks from unfinished security arguments.

The implemented domain is `2 <= T < N <= 64`, with `N >= 2T-1`, validated
algebra, and explicit work/storage bounds. The committee restriction leaves at
least T honest recipients when at most T-1 are corrupt. The application supplies
fixed authenticated identities, agreed parameters, a fresh common session,
confidential authenticated pairwise channels, and consistent authenticated
broadcast. Receiving N ordinary messages does not implement broadcast.

Missing or invalid messages abort; there is no robust exclusion, public complaint
opening, dynamic membership, adaptive-corruption guarantee, timeout service,
or guaranteed termination. Fresh states and entropy are required for restart.
In-memory ownership and counters do not implement durable rollback protection.
No real network or persistent secret/nonce store is included.

## Security-obligation ledger

| Property | Current evidence and limit |
| ---- | ---- |
| Linear reconstruction | Algebraic compatibility; independent schoolbook and symbolic checks; every small authorized reconstruction |
| Commitment before challenge | Complete salted X/Y payloads and context are hashed before R; full binding/extraction query accounting remains open |
| Sharing consistency | Conditional fixed-input separation argument and public/private checks; no overall ROM/QROM reduction |
| Shortness | Direct local coefficient checks; uniform root bound T*L from honest reconstruction; Gaussian variant additionally has a conditional projection bound |
| Privacy | Uniform masks give an exact fixed-R identity relative to revealed X_C; short X_C still leaks, and commitment/hash simulation remains unproved |
| Completeness and distribution | Conservative sufficient conditions and explicit convolution/posterior analysis; no certified profile-specific losses or final hardness distribution |
| Public matrix | Derived after all accepted contribution statements; independence and adversarial grinding analysis remain open |
| Signing/refresh | Deterministic correctness bounds, material pins, and lifetime accounting are implemented; composed privacy and unforgeability remain open |
| Agreement with abort | Consumed rounds pin local messages, compare acknowledgments, and check public consistency; consistent broadcast remains external |
| Quantum security | No complete quantum reduction is established for this distributed verifier; using SHAKE or lattices does not supply one |

## Validation snapshot

Local checks on 2026-09-06:

- 110 integration tests pass with all features on Rust 1.98 and Rust 1.96.
- 70 tests pass without the experimental feature; nine all-feature Rustdoc tests pass.
- Sixteen independent fixture files regenerate unchanged, including both DKG
  variants, complete signing results, and 24 DKG packets.
- The fixed-projection model passes 72 exact finite-group comparisons; the
  integer-Gaussian model passes 14 posterior checks and distinguishes convolution
  from exact width rescaling. Symbolic sharing is checked through 15 parties.
- The last library coverage measurement, before adding the symbolic-only test,
  was 94.71% lines; DKG message code was 99.61%. Coverage is not a security proof.
- The seeded DKG parser completed 6,950,886 AddressSanitizer inputs without a
  crash in a 60-second smoke run. Local symbolizer warnings are recorded in
  `fuzz/README.md`.
- Both complete DKG modes and the transport/abort example ran with OS randomness.
- Benchmarks completed both variants at degree 512 for 2-of-3 and 3-of-5;
  explicit configuration, timing boundaries, and CSV are retained.
- Formatting, Clippy/rustdoc with warnings denied, MSRV compilation, locked fuzz
  compilation, reference models, actionlint, and whitespace checks pass.

CI includes the experimental feature, examples, models, coverage, and fuzz target.
Hosted CI and an external audit have not been run. The existing dealer fixtures
remain unchanged. See `DKG-REVIEW.md` for the requirement-by-requirement audit and
precise boundaries of these results.
