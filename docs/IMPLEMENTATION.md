# Implementation goal

Implement the Hermine algorithms in ePrint 2026/419 in idiomatic Rust, with
examples, API documentation, comprehensive correctness and rejection tests, and
reproducible validation. Keep the design small and explicit. Implementation and
local validation of the specified trusted-dealer algorithms are complete; see
[VALIDATION.md](VALIDATION.md) for evidence and the limits of that conclusion.

## Source baseline

- [Paper](https://eprint.iacr.org/2026/419), revision dated 2026-08-20, 56 pages.
- Retrieved 2026-09-05. PDF SHA-256:
  `829325488c40838840837ac0c6bd784ca9cfe0383e5e4794889911b4028e840a`.
- [Project website](https://hermine-th.org/).
- [NIST preview](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/Hermine-PW01.pdf),
  version 1.0, 2026-01-19, is supplementary and predates the paper revision.
- The [official organization](https://github.com/PQ-Hermine) exposed no public
  repositories when checked on 2026-09-05. No official interoperability vectors
  are currently available.

## Deliverables

- [x] Reference ring arithmetic, rounding, centered norms, and NTT with
  independent differential validation.
- [x] Bounded matrix/vector operations with precomputed NTT multiplication.
- [x] Discrete Gaussian sampling using exact rational acceptance probabilities
  for integer widths, with explicit finite-integer errors.
- [x] Domain-separated SHAKE transcript primitive, challenge extraction, and
  binding factors. Complete protocol field schemas remain below.
- [x] VandShare, VandRecover, and VandCheck (Figures 5 and 6), with pluggable
  additive group operations and sampling.
- [x] Trusted-dealer key generation and per-party public verification material.
- [x] Offline preprocessing, single-use nonce ownership, online signing.
- [x] Partial verification, identifiable aborts, aggregation, final verification.
- [x] Dealer refresh, global and individual refresh verification, atomic updates,
  epoch binding, and invalidation of old preprocessing material.
- [x] Explicit, bounded, canonical serialization and malformed-input rejection.
- [x] Document concrete parameter ambiguities and require explicit inputs. No
  security profiles are declared while those ambiguities remain unresolved;
  mathematical validity is distinguished from cryptanalytic claims.
- [x] End-to-end examples for signing, blame, refresh, and transport integration.
- [x] Unit/property tests, exhaustive small-committee tests, independent arithmetic
  and protocol vectors, adversarial-input tests, fuzz targets, and coverage report.
- [x] Rustdoc, architecture notes, protocol/source mapping, operational assumptions,
  benchmarks, CI, formatting, Clippy, nextest, and documentation tests.
- [x] Final source review, cross-checks with independently written reference
  algorithms, and explicit residual limitations. This is not an external audit.

## Scope of distributed key generation

The website advertises DKG. The current paper's Section 1.2 instead assumes a
trusted dealer and leaves concrete DKG security analysis for future work. Section
1.3 explains why earlier DKG material was omitted. The initial implementation
therefore targets every specified algorithm, including dealer-assisted proactive
refresh. A dealerless extension requires its own specification and validation;
it must not silently replace the paper's Keygen algorithm.

## Validation requirements

Tests must check mathematical properties and independently computed answers, not
merely round-trip the same implementation. Exercise every small signer subset,
odd committee sizes, 1-of-N and N-of-N boundaries, malformed and duplicate IDs,
altered commitments/responses, wrong messages and keys, stale epochs, refresh
tampering, replay prevention, and noncanonical encodings. Norm checks use exact
integer squared norms and fail closed on overflow. Production security and
official interoperability are separate claims requiring evidence beyond passing
tests.

## Progress

2026-09-05: Goal created; latest paper retrieved and algorithm figures inspected.
Repository initially contained only README and gitignore. Arithmetic and sharing
foundation implemented. The 21 integration tests cover every signer subset for
all thresholds through N=9, selected N=64 cases, every single-share corruption
through N=7, small exhaustive ring products, and NTT differential tests through
degree 4096 and 48-bit moduli. Two Rustdoc examples, the runnable sharing example,
Clippy with denied warnings, formatting, and documentation builds pass. See
SPECIFICATION.md for source issues.

Coverage of the current library: 93.84% lines and 95.05% regions using
cargo-llvm-cov with nextest and compiler caching disabled. This measures only the
implemented foundation, not completion of the signature scheme.

2026-09-05, second milestone: matrix/vector operations, exact-rational integer-width
Gaussian sampling, and length-framed SHAKE transcripts implemented. Independent
Python Fraction/OpenSSL vectors cover Gaussian widths from 1 through 2^36,
challenge polynomials, binding factors, and digests. Statistical checks cover the
discrete mass function and large-width moments; entropy-failure injection checks
error propagation. The suite now has 39 passing integration tests.
Three Rustdoc tests (including rejection of non-cryptographic RNG bounds),
Clippy with denied warnings, formatting, and documentation builds pass.
Current library coverage is 91.22% of lines and 89.69% of regions. The final full
nextest coverage run passed all 39 tests without warnings.

2026-09-05, third milestone: explicit algebraic parameter validation, conservative
integer norm bounds, full protocol transcript schemas, trusted-dealer key
generation, offline preprocessing, consumed nonce ownership, signing, partial
verification, identifiable abort classification, aggregation, and final
verification implemented. Every signer subset through five parties signs and
verifies. A complete independent Python schoolbook 2-of-3 vector matches key,
package, and session identities, both partial responses, and the final signature.
Python big-integer reference cases check entropy and correctness-bound formulas.
The suite has 49 integration tests and four Rustdoc tests. Clippy and rustdoc with
warnings denied pass; the operating-system-randomness signing example runs.
Current library coverage is 92.61% of lines and 89.49% of regions.

2026-09-05, fourth milestone: dealer-assisted zero sharing, global refresh
verification, individual secret/error norm verification, transactional updates,
epoch transitions, stale nonce and replay rejection, and preservation of lifetime
preprocessing counters implemented. Every threshold and subset through five
participants signs across two refresh epochs. Invalid final tokens leave all
in-process shares unchanged; individual failures also preserve usable old state.
Independent Python vectors match every confidential increment and the complete
next public-package identity. Refresh and identifiable-abort examples run with
operating-system entropy and explicit toy parameters. The suite has 57 passing
integration tests and four Rustdoc tests; Clippy and documentation checks pass.
Current library coverage is 93.32% of lines and 90.25% of regions; the refresh
module has 98.95% line coverage.

2026-09-05, fifth milestone: bounded canonical codecs for all eight public and
refresh message types implemented with pinned parameters, implicit share paths,
allocation preflight checks, strict coefficient ranges, and zeroizing confidential
refresh buffers. Signing caches and public identities are rebuilt from decoded
inputs. Every packet matches independently generated Python bytes. Tests reject
every truncation and suffix, altered framing/parameters, noncanonical coefficients,
oversized lengths, inconsistent public shares, and forged refresh metadata.
The transport example signs, verifies, and refreshes through byte boundaries.
The suite has 65 passing integration tests and four Rustdoc tests; Clippy and
documentation checks pass. Library coverage is 94.60% of lines and 90.55% of regions.
The wire message implementation has 99.33% line coverage.

2026-09-05, completion audit: added exact norm-boundary tests, seeded wire and ring
fuzz targets, a release benchmark, architecture and validation notes, dual-license
texts, and pinned CI workflows. All 68 integration tests and four Rustdoc tests
pass locally. Library coverage is 94.71% of lines and 90.62% of regions. Two
60-second AddressSanitizer fuzz runs completed without crashes, processing
5,217,079 wire inputs and 715,631 arithmetic inputs. The degree-512 benchmark ran
30 complete signing/refresh iterations. CI configuration passes actionlint;
hosted runner execution has not been performed.

Concrete profiles remain explicit and uncertified because the paper does not
determine all required cryptanalytic inputs. DKG remains a separate specification
gap. Persistent private shares and nonces require a separate durable accounting
design and have no naive wire serialization. These limitations are recorded in
the final validation report rather than presented as implemented features.
