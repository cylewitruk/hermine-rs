# Experimental dealer-equivalent MPC

The `experimental-mpc` feature implements a complete four-party key-generation
circuit and feeds its outputs into Hermine signing. Four independent actors run
DKG; any two can subsequently sign. The example keeps private outputs inside
actors and takes the two non-signers offline before signing.

```sh
cargo run --release --features experimental-mpc --example mpc
cargo nextest run --all-targets --all-features --locked
python3 scripts/mpc_gaussian_table.py
```

## Protocol and security model

The backend follows [Maurer's replicated-sharing MPC, Sections 6.1–6.2
(2006)](https://crypto.ethz.ch/publications/files/Maurer06.pdf). A value has four
additive components; party i holds all except component i. Holders privately
cross-check duplicate components. For multiplication, every co-holder of each
product term independently shares it; the parties open differences and require
zero. At least one co-holder is honest when at most one party is corrupted.
Three copies allow majority reconstruction of each component. This implementation
aborts on complaints instead of using the paper's recovery paths.

The selected arithmetic protocol is information-theoretic in its ideal classical
communication model: its checks do not depend on factoring, discrete logarithms,
Fiat–Shamir, OT, or FHE. That is the reason for choosing it for a post-quantum
research prototype. The contract is:

| Property | Prototype scope |
| ---- | ---- |
| Online DKG members | Exactly four |
| Signing threshold | Exactly two |
| Corruption | At most one static malicious participant |
| Communication | Synchronous private authenticated channels and consistent broadcast |
| Failure | Abort permitted; no guaranteed output or fairness |
| Randomness | Independent private cryptographic RNG at each honest participant |
| Sampler | Sigma 1; support -16 through 16; 192 secret uniform bits per coefficient |
| Size | At most 1,024 root/split coefficients; batches of at most 256 |
| Refresh | Disabled for this prototype |

This is an implementation and composition experiment, not a quantum security
proof. The adaptation, Boolean-to-modular conversion, Rust implementation, and
composition with signing have not received a formal simulation proof or external
review. [Quantum lifting results](https://arxiv.org/abs/0910.2912) have specific
hypotheses; they are not a blanket certificate for this implementation. The
[Hermine paper](https://eprint.iacr.org/2026/419) still requires the separate
signing/DKG proof work described in [the research analysis](DKG-INTERACTIVE.md).
No production security profile or production-use recommendation is provided.

## What executes inside MPC

1. Agree on the complete versioned parameter encoding and fresh session identifier.
2. Jointly generate uniform A from VSS-shared private modular contributions, then
   open only their sum. Individual contributions are fixed before reconstruction.
3. Jointly generate secret binary tapes by XORing VSS-shared random inputs.
4. Evaluate a fixed inverse-CDF circuit on those tapes. Bitwise gates evaluate 64
   samples in parallel; control flow and array indexing depend on public constants.
5. Convert six output bit-planes to modular sharings. Each binary component's
   co-holders VSS-share its bits and check equality. Three modular XOR operations
   combine the four components; a public weighted sum yields the coefficient.
6. Use the existing Figure 5 Vandermonde recursion on secret root and split
   vectors. Compute `2(As+e)` locally on each replicated component.
7. Open the public key and verification shares. Reconstruct private `(s,e)` shares
   only to their owner; validate each owner's public relation and the common
   Vandermonde sharing. Return only after an all-accept barrier.

No actor reconstructs the root, the sampler tape, or another actor's private
output. The private error vectors are temporary: the signing output stores only
s. An owner could already derive its e from its s and full verification share.

The MPC circuit reproduces the *joint* dealer sampling/sharing construction,
subject to the bounded sampler's approximation. It does not sum four independently
sampled Gaussian secrets, which would change the distribution. The existing
trusted-dealer and candidate-DKG implementations remain separate features.

## Sampler certificate and equivalence limit

The target integer mass is proportional to `exp(-x²/2)`. The table first conditions
on `|x| <= 16`, then floors each normalized CDF boundary onto the 192-bit grid.
A uniform draw maps to the number of boundaries it crosses, minus 16.

`scripts/mpc_gaussian_table.py` reproduces every constant and certifies its floor
using rational alternating-series bounds and directed 512-bit interval squaring.
It also verifies, using rational inequalities,

```text
tail <= 2 exp(-17²/2) / (1 - exp(-17.5))
TV(one sample, ideal discrete Gaussian) <= tail + 32 / 2^192 < 2^-186
TV(up to 1024 independent samples, ideal dealer samples) < 2^-176
```

Deterministic sharing, public images, and private output selection cannot increase
this distributional distance. These bounds concern the sampling distribution,
not signing security bits. They do not justify conditioning on successful runs
under adversarial selective abort; a composition proof must model abort and
repeated attempts explicitly. The runtime has no floating-point sampling,
secret-dependent rejection loop, or public secret-seed reconstruction.

## Rust and transport boundaries

`mpc::keygen(config, session, transport, rng)` runs one participant. Its `Output`
contains a public package, that participant's move-only `SecretShare`, and cost
statistics. `Parameters::for_mpc` pins `KeyOrigin::ExperimentalMpc` and the session
into encoding version 3. Provenance metadata is not an attestation that MPC ran.
Trusted-dealer generation rejects this origin; existing wire codecs use the
provided parameter encoding and preserve its identity.

`mpc::Transport` is an ideal-service interface. `mpc::local::network` implements
it in trusted process memory with separate, move-only endpoints, bounded messages,
round checks, deadlines, and abort propagation. It is a test service: its router
necessarily handles all addressed buffers, and the shared address space is not
an isolation boundary against native-code compromise.

There is **no network deployment backend** here. Replacing the local service
requires private authenticated post-quantum channels, consistent broadcast,
identity/session/round binding, bounded canonical framing, and failure handling.
Sending the broadcast vector independently over four sockets would not satisfy
the broadcast contract. Fresh invocation identifiers and process isolation are
application responsibilities. Failed invocations and endpoints must be discarded.

Secret shares and confidential heap buffers zeroize on drop; payload Debug is
redacted. This does not erase compiler temporaries, reallocations, registers,
caller copies, swap, or snapshots. Modular arithmetic remains variable-time.
No adaptive corruption, concurrent composition, durable recovery, membership
changes, or side-channel resistance is claimed.

## Validation and feasibility

Tests exercise both packed binary and modular multiplication, private output
isolation, correction of one faulty reconstruction sender, rejection of inconsistent
VSS deliveries and independently shared products, round replay, omissions,
configuration/session mismatch, RNG failure, and all six 2-of-4 signing subsets.
The sampler circuit is compared against clear integer evaluation immediately
before, at, and after all 32 boundaries, plus both extreme inputs (98 cases).
The all-feature suite passes 121 tests on Rust 1.98 and the Rust 1.96 MSRV, plus
nine Rustdoc tests on the MSRV. LLVM coverage reports 94.86% library lines. Clippy
and Rustdoc pass with warnings denied; the default feature build also checks.

Existing sharing and arithmetic tests supply separate coverage of the reused
Vandermonde and NTT operations.

For the example's degree-16, 2-by-2 matrix, the dealer circuit samples 256
coefficients (root plus three split vectors). Measured locally on aarch64 macOS
with Rust 1.98 release builds:

| Cost | Result |
| ---- | ---- |
| Synchronous rounds | 995 |
| Logical remote traffic, all four actors | 454,927,392 bytes |
| Multiplication gates per actor | 29,184 packed/scalar gates |
| Peak aggregate outgoing payload per actor | 3,981,312 bytes |
| MPC plus selected-signers' preprocessing | About 1.20 seconds |
| Entire example, including signing and verification | About 1.50 seconds |
| Entire example peak resident memory | 95,911,936 bytes (about 91.5 MiB) |

Traffic counts exclude self-delivery and count broadcast once per remote
recipient; they exclude framing, cryptographic transport, and retransmission.
RSS was measured for the example process using macOS child-process resource
usage; it includes all actors and the ideal router. Timing is a single-host feasibility observation,
not a WAN or security-parameter benchmark. The example also reports elapsed time
including selected signers' preprocessing.

The dominant next engineering tasks are reducing communication/round depth,
supporting the intended larger Gaussian widths and parameter sets, and implementing
a separately justified network service. The present sigma-1 parameters are tiny
functional fixtures, not a lattice hardness recommendation.
