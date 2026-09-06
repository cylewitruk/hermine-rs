# DKG construction and implementation review

Reviewed on 2026-09-06 against the implemented candidate, examples, independent
fixtures, and executable checks. This is a development review by the implementer,
not an independent cryptographic audit. The research implementation is usable for
experiments; neither variant has an established DKG security theorem.

## Source fidelity and deliberate changes

The starting point is Hermine's recommendation to combine individual Gaussian
contributions, short Vandermonde sharing, and a verifiable-sharing mechanism
inspired by Flood and Submerse. Hermine leaves the DKG security analysis for
future work. The implemented protocol is therefore an explicitly specified
adaptation, not a claim to implement a complete author-specified DKG algorithm.

| Construction decision | Review conclusion |
| ---- | ---- |
| Figure 5 short sharing | Reuses the existing combinatorial implementation and exact discrete sampler; independent vectors and symbolic reconstruction checks support algebraic fidelity |
| Salted whole-recipient commitments | Replaces the source's Merkle tree with an ordered list for N<=64; commits to input and mask, complete paths, identities, context, and secret salt |
| Gaussian response predicate | Uses a documented infinity-norm variant rather than importing the source's Euclidean submersion theorem or the related normal-substitution heuristic |
| Uniform-mask alternative | A separate construction with distinct domains, no projected shortness predicate, and root shortness derived from checked private shares; not an interchangeable sampler under the Gaussian proof |
| Matrix timing | Derived after the accepted contribution statements; implemented ordering is explicit, while independence and adversarial grinding remain unproved |
| Agreement | Two consumed broadcast rounds with external consistent authenticated broadcast; this is agreement with abort, not robust exclusion or a broadcast implementation |
| Signing import | Uses deterministic DKG bounds and pins completed public material; does not reuse the dealer distribution assumption |
| Refresh | Retains the existing dealer-assisted zero-share refresh; does not claim a newly implemented distributed refresh protocol |
| FROST relationship | Reuses engineering ideas such as authenticated participant maps and consumed state; no discrete-log commitments or Schnorr knowledge proofs are transplanted |

The exact formats and formulas are in `DKG-SUBMERSION.md`, `DKG-SHARING.md`,
`DKG-UNIFORM-MASK.md`, `DKG-ROUNDS.md`, `DKG-COMPOSITION.md`, and `DKG-WIRE.md`.
A documentation mismatch about salt timing was corrected during review: the
implementation samples each salt before validating that recipient's input shape
and bound. All values are still fixed before deriving the projection challenge.

## Implementation invariants checked

| Invariant | Implementation and evidence |
| ---- | ---- |
| Parameter and workload limits precede large allocations | Projection/sharing/session constructors validate dimensions, committee restrictions, and scalar work/storage budgets; boundary tests cover invalid and oversized configurations |
| A variant cannot silently acquire the other's semantics | `Masking` and optional response predicate are validated as a pair; separate contexts/challenge encodings propagate into output and signing identities; cross-variant tests reject replay |
| Secret and mask are committed before challenge extraction | Contribution generation constructs all salted recipient hashes before R; the primitive API explicitly leaves this obligation to direct callers |
| Public validation cannot replace private validation | Exact projected layout/rings and VandCheck precede local bounds, opening, and equation checks; tests separately alter each layer |
| No participant receives the committee's private secret collection | Round state retains only its own payload or local aggregate; outgoing per-recipient messages are routed by the application; only test/example network harnesses own all participant states |
| Failed transitions cannot be retried with the same owned state | `accept`, `finish`, and `into_signing` consume their states, including on error; compile-fail tests cover reuse/duplication |
| Local messages cannot be substituted by a delivered copy | First round pins its original statement; second round pins its original public message; replay/equivocation tests exercise both |
| Local incomplete or invalid rounds cannot release a key | Exact authenticated sender sets, common acknowledgments, and public-image consistency are checked before output; missing/invalid deliveries abort |
| Local signing bounds survive refresh and nonce failures | Checked contribution/refresh/nonce norms, deterministic accumulation, and lifetime reservation accounting are tested at equality, excess, replay, and exhaustion |
| Origin labels cannot authorize substituted material | Parameters derived from immutable `PublicOutput` additionally pin matrix/rounded key and full-resolution key; tests include a consistent full-key substitution hidden by rounding |
| Network bytes cannot negotiate allocations or paths | DKG codec pins configuration, checks exact byte counts before coefficient allocation, and derives canonical paths locally; malformed packets and every truncation are tested |
| Confidential packet allocations do not reallocate after receiving secrets | Shared bounded writer reserves the full private output first; owned secret packet and coefficient temporaries erase on drop; caller copies remain the caller's responsibility |
| Decoder success cannot bypass round validation | Explicit post-decode tests reject a changed opening and transcript acknowledgment; the API returns untrusted message types |
| Dealer behavior remains independently checked | Original parameter, signing, refresh, and wire fixtures remain byte-identical; default-feature tests and all-feature tests exercise the common I/O extraction |
| Rust implementation remains explicit and bounded | Unsafe code is forbidden; missing public documentation is denied; Clippy/formatting checks pass; no new third-party dependency was needed for DKG |

These checks review the implemented acceptance rules. They do not prove that the
rules realize a secure ideal DKG functionality. In particular, ownership APIs
cannot prevent a caller from deliberately copying borrowed private coefficients,
and in-memory counters do not provide durable rollback protection.

## Cryptographic status

| Property | Status and evidence |
| ---- | ---- |
| Honest linear reconstruction/public images | Algebraic identity, independently checked across small committees and schoolbook reference arithmetic |
| Private-share and signing norm bounds | Deterministic bounds for checked inputs, with exact integer boundary tests |
| Honest completeness | Conservative sufficient conditions and ideal Gaussian tail union bounds in `DKG-DISTRIBUTION.md`; no certified parameter-specific failure probability |
| Consistency under a fixed independent projection | Conditional separation argument with a per-pair `2^-256` probability; not an overall protocol security level |
| Uniform-mask public-view privacy for fixed R | Exact finite-group identity and 72 enumerated comparisons, conditional on already exposed private input shares |
| Salted commitment/hash-derived challenge security | A conditional classical simulation outline exists; full bad-event/query accounting and extraction are open |
| Quantum security | No applicable complete QROM reduction has been established for this distributed verifier; generic Fiat–Shamir citations do not close the gap |
| Aggregate-key hardness | Coalition observations, Gaussian convolution, wrapping, private rejection, malicious contributions, and selective abort require a complete conditional distribution argument |
| Composed unforgeability | The DKG/signing/refresh execution works under checked correctness bounds; its security reduction remains open |

No secure parameter preset, constant-time guarantee, robustness claim, adaptive
corruption claim, or production-use recommendation follows from this work. The
research outcome is an explicit testable candidate and analysis of what would
be required to support those claims.

## Requirement audit

| Requested deliverable | Evidence |
| ---- | ---- |
| Paper-based DKG investigation | Primary-source ledger in `DKG.md`; construction decisions above; oracle and distribution analyses |
| Rust implementation within hermine-rs | Feature-gated projection, contribution, consumed rounds, signing bridge, and codecs under `src/dkg`, `src/parameters/dkg.rs`, and `src/protocol/dkg.rs` |
| Full examples | `dkg_projection`, `dkg_contribution`, both modes of `dkg`, and `dkg_transport`; successful OS-randomness runs and abort demonstrations |
| Comprehensive tests | Projection/bounds, contributions, all small authorized subsets, agreement, origin/material pins, nonce/refresh boundaries, wire malformed-input tests, and compile-fail ownership tests |
| Independent validation | Sixteen complete fixture files; Python arithmetic/hash/wire references; finite-group and high-precision distribution models; symbolic sharing test |
| Fuzzing | Seeded DKG parser target with canonical re-encoding invariants; 6,950,886 sanitizer inputs without a crash in the recorded smoke run |
| Reproducible benchmarks | Degree-512 phase and codec harness, fixed public seed, two committee sizes, both variants, recorded CSV and byte accounting |
| Idiomatic, maintainable Rust | Existing ring/sharing/sampling/transcript reuse, shared byte I/O and benchmark timing utilities, consumed private state, explicit errors, minimal dependencies, compiler and Clippy gates |
| Documentation and experimental status | Normative local formats, setup/transport contracts, source departures, conditional mathematics, observed validation, and unresolved proof obligations are all linked from `DKG.md` |

The implementation/research deliverables are distinct from a future proof or
external audit. The open entries above are recorded research conclusions, not
properties inferred from successful tests.
