# Implementation validation

The paper's specified trusted-dealer algorithms are implemented and locally
validated against the 2026-08-20 revision of ePrint 2026/419. This report records
the completion audit on 2026-09-05. It is an internal source review with separately
written Python reference implementations, not an external cryptographic audit.

## Deliverable evidence

| Deliverable | Implementation and evidence |
| ---- | ---- |
| Ring arithmetic and NTT | `src/ring/`, `src/ring.rs`, `tests/ring.rs`, `tests/ntt.rs`; exhaustive small cases and differential products through degree 4096 and 48-bit moduli |
| Matrix/vector algebra | `src/linear.rs`, `tests/linear.rs`; rectangular products compared with schoolbook arithmetic |
| Gaussian sampling | `src/sampling.rs`, `tests/sampling.rs`; independent rational vectors, distribution checks, and entropy-failure injection |
| Sharing and reconstruction | `src/sharing.rs`, `tests/sharing.rs`; every authorized subset through nine parties, corruption checks, and selected 64-party cases |
| Parameters and transcripts | `src/parameters.rs`, `src/transcript.rs`, corresponding tests; exact Python entropy/bound calculations and SHAKE vectors |
| Key generation and signing | `src/protocol/keys.rs`, `src/protocol/signing.rs`, `tests/protocol.rs`; independent full-session vectors and every subset through five parties |
| Refresh and abort handling | `src/protocol/refresh.rs`, protocol/refresh tests; two epochs, altered responses/tokens, replay rejection, and failure atomicity |
| Exact norm predicates | `tests/boundaries.rs`; equality accepted and excess rejected for partial, final, and individual refresh checks |
| Canonical transport | `src/protocol/wire/`, `tests/wire.rs`; eight independently encoded packets, every truncation/suffix, malformed metadata and resource limits |
| Examples | `examples/`; sharing, signing, refresh, identifiable aborts, and transport, all executed locally |
| Documentation and maintenance | Rustdoc, source mapping, architecture, sampling/transcript/wire notes, benchmark harness, licenses, and `.github/workflows/ci.yml` |

All six checked-in vector files reproduce exactly via
`python3 scripts/check_vectors.py`. The reference protocol uses Python integers,
schoolbook convolution, OpenSSL SHAKE, and separately expressed sharing steps;
it does not call the Rust implementation. It shares the documented interpretation
of the paper, so agreement cannot establish that those interpretations are
author-approved.

## Local results

| Check | Result |
| ---- | ---- |
| `cargo nextest run --all-targets --locked` | 68 tests passed, none skipped |
| Rustdoc tests | Four passed, including nonce-reuse and RNG-bound compile-fail cases |
| Rust 1.96 MSRV | All targets checked; all integration tests and doctests passed across the main and final boundary-test runs |
| Formatting and Clippy | Root/fuzz formatting passed; all-target Clippy passed with warnings denied |
| Documentation | Built with rustdoc warnings denied |
| Independent vectors | All six fixture files unchanged |
| LLVM coverage | 94.71% library lines, 90.62% regions; 68 tests passed in the coverage run |
| AddressSanitizer fuzzing | Two 60-second runs completed without crashes: 5,217,079 wire inputs and 715,631 arithmetic inputs |
| Benchmark | 30 complete iterations at degree 512; measurements in `BENCHMARKS.md` |
| CI configuration | actionlint passed; hosted Linux/macOS/Windows jobs are configured but have not run |

Tests ran on aarch64 macOS using Rust 1.98.0 and 1.96.0; fuzzing used
nightly-2026-08-29. Commands are in the README, `fuzz/README.md`, and CI workflow.
Coverage is a measurement of exercised code, not a proof of correctness or a
claim of 100% test coverage. Bounded fuzz runs are smoke tests.

## Final source review

The review traced the paper-to-API mapping in `PROTOCOL.md`, the discrepancies in
`SPECIFICATION.md`, and the following implementation properties:

- Ring and dimension limits bound schoolbook accumulators below 2^108 and joint
  vector squared norms below 2^114. Both fit the chosen 128-bit arithmetic.
  Parameter formulas use bounded inputs and reject unrepresentable output bounds.
- Norm predicates accept equality. Canonical shapes and ring identities are
  checked before arithmetic on externally constructible protocol messages.
- A private nonce has one owner and signing consumes it. Failed preprocessing
  burns its reservation; refresh preserves lifetime counters. Package, epoch,
  participant, and session bindings are checked at their corresponding boundaries.
- Global refresh consistency and individual increment/error norms are separate
  checks. Replacement shares are prepared before state changes, including the
  in-process committee update.
- Private polynomial and transformed storage zeroizes on drop. Temporary
  convolution/sampling buffers and confidential output packets also zeroize.
  Secret packet encoding reserves capacity before copying confidential contents.
  This does not guarantee erasure of registers, caller copies, swap, or snapshots.
- Wire decoding pins parameters, checks lengths and implicit share counts before
  allocation, rejects trailing/noncanonical data, and reconstructs cached values.
  Decoding a signature or partial response does not replace message verification.
- Unsafe code is forbidden, private protocol internals remain module-private,
  and public API items are documented. Common algebra and validation operations
  are reused rather than duplicated across signing, refresh, and codecs.

## Residual limitations

There are no validated security presets. The paper does not fully determine the
exact modulus, the interpretation of Table 3's widths, or all concrete heuristic
bounds. Algebraic validation does not establish MLWE/MSIS hardness or statistical
hiding. Example and benchmark configurations must not be treated as security
recommendations. Sampling supports integer widths and reports finite-arithmetic
errors; modular arithmetic and sampling are variable-time.

The implemented key generation uses a trusted dealer. The paper leaves dealerless
DKG security analysis for future work. Optional sharing optimizations are not
needed by the implemented Figure 5 algorithms. The locally specified transcript
and wire format have no official interoperability vectors or compatibility claim.

Applications supply authenticated transport, confidential share delivery, common
request/epoch agreement, and an appropriate cryptographic RNG. Safe in-memory
ownership cannot prevent process forks or snapshot rollback. Persistent private
shares and nonces therefore have no serialization API; durable accounting and
recovery require an additional design. No production deployment readiness is
claimed by completion of this implementation goal.
