# Signing lifecycle

The implementation follows Figures 5–7 of ePrint 2026/419, revision 2026-08-20.
The executable `examples/signing.rs` demonstrates the complete lifecycle with
operating-system entropy and deliberately insecure small parameters.

| Paper operation | Rust API | Purpose |
| ---- | ---- | ---- |
| Keygen | `dealer_keygen` | Sample A, secret/noise pairs, and Vandermonde shares |
| Preprocess | `SecretShare::preprocess` | Reserve a nonce and produce a public commitment |
| Common Sign inputs | `SigningPackage::new` | Validate T commitments and derive H_beta/H_c |
| Sign | `SecretShare::sign` | Consume the matching nonce and produce z_i |
| PartialVerify | `SigningPackage::verify_share` | Check the response and residual norm |
| Identifiable abort | `SigningPackage::identify_abort` | Classify invalid and absent responses |
| Combine | `SigningPackage::aggregate` | Verify contributions, form z/h, and verify the result |
| Verify | `PublicKey::verify` | Check canonical shape, norm, and challenge equality |
| RefreshDealer | `dealer_refresh` | Share zero and form new public shares and private increments |
| RefreshVerify | `RefreshProposal::verify` | Check all reconstructions preserve the full key |
| RefreshVerifyInd | `VerifiedRefresh::verify_token` | Check each private increment and implied error |
| RefreshUpdate | `SecretShare::apply_refresh` | Validate and atomically install one participant's update |

Key generation uses the paper's trusted dealer. Each participant receives only
its `SecretShare`; everyone receives the same `PublicKeyPackage`. The long-term
`PublicKey` suffices for final verification. The package also contains indexed
verification shares for partial verification and the full-resolution public key.
Secret vectors use the same zeroizing polynomial storage as the arithmetic layer.

Preprocessing is independent of the eventual message and signer set. A
`NonceState` owns its secret masking vectors, exposes a cloneable public
`Commitment`, and implements neither `Clone` nor secret-bearing `Debug`.
Signing consumes the nonce even when it returns an error. A compile-fail doctest
checks that safe Rust code cannot sign twice with the same nonce object.

Commitments must arrive in strictly increasing participant order and contain
exactly T distinct participants. Their dimensions, coefficient ranges, epoch,
package identity, and sequence allowance are checked before deriving a challenge.
Partial responses may arrive in any order; repeated or unexpected participants
are rejected. Aggregation verifies every contribution and the final signature.

## Proactive refresh

The dealer requires only the existing public package and a fresh entropy source.
It shares the zero secret/noise pair with Figure 5's Gaussian sharing distribution,
then forms each next public share as `vk'_i = vk_i + 2(A * increment_i + error_i)`.
The common `RefreshProposal` is untrusted until verified. `RefreshToken` contains
confidential increments and must be delivered only to its intended participant.
Its public fields permit explicit transport integration; Debug redacts them and
their polynomial storage zeroizes on drop.

`RefreshProposal::verify` validates every share's shape and layout, runs VandCheck,
and requires equality with the original full-resolution public key. It returns a
`VerifiedRefresh` containing the next immutable public package. The long-term
matrix, rounded public key, parameters, and key identity remain unchanged.
The refresh epoch and package identity change. The original public key continues
to verify signatures from every epoch.

Individual verification computes
`error_i = inverse(2) * (vk'_i - vk_i) - A * increment_i` in the odd-modulus ring.
For every expected path it checks the combined squared norm of the increment and
implied error against the configured refresh bound. A globally consistent public
proposal can still fail this individual check; tests explicitly cover that case.
Tokens bind both source and target package identities and the recipient.

`SecretShare::apply_refresh` verifies first and builds all replacement vectors
before changing the share. Any error preserves the old secret state and nonce
counter. Success advances its epoch and package identity without resetting the
lifetime preprocessing allowance. Pre-refresh nonce objects remain owned by
their callers, but neither their commitments nor old signing packages can be
used with the refreshed share. Drop those unused objects to erase their storage.

`KeySet::apply_refresh` provides atomicity across all N in-process shares: it
prepares every update before installing any of them. This convenience is useful
in tests and dealer demonstrations. It is not a distributed commit protocol.
Distributed applications must coordinate epoch agreement and recovery while each
recipient performs its own global and individual verification. The example
`examples/refresh.rs` illustrates those per-recipient calls.

Applied epochs are bounded by `refresh_limit`. A stale token cannot update a share
twice, and a token for another proposed next package is rejected. Restoring an old
process snapshot remains an application persistence concern, as with nonces.

## Explicit parameters

`parameters::Config` contains every algebraic, sampling, rounding, entropy, and
usage input. `Parameters::new` checks dimensions, ring/NTT compatibility, supported
Gaussian widths, rounding exponents, random-oracle output sizes, and integer
representability. These checks do **not** establish MLWE/MSIS hardness, the
paper's statistical-hiding inequalities, or a claimed security level. There are
no certified profiles or default parameters. The small example is unsuitable
for protecting data or authorizing transactions.

Challenge support is checked with the exact inequality
`binomial(n, omega) * 2^omega >= 2^entropy_bits`. Binding factors use
`(2n)^(rep-1) >= 2^entropy_bits`, including the fixed first factor. The integer
tail multiplier satisfies the conservative sufficient condition
`3n(alpha-1)^2 >= entropy_bits`. Bounds use Section 6.1's unconditional formulas,
with every square root rounded upward separately. For the inconsistent final
rounding constants on pp. 26 and 30, the larger expression is used. Intermediate
arithmetic is exact `u128`; unrepresentable final bounds return an error.

The global preprocessing allowance is divided conservatively among N parties
using integer division. A party reserves its next sequence number **before** any
sampling; failed and discarded attempts consume allowance. This enforces a local
lifetime accounting convention for the paper's query bound, not an enforcement
mechanism against malicious participants. The refresh allowance is included in
the norm bounds from key generation onward.

## Transcript convention

The underlying framing is specified in `TRANSCRIPTS.md`. All coefficient matrices
encode `u64_le(rows)` followed by each row's `u64_le(length)` and `u64_le`
coefficients. Matrix rows, rounded keys, and public shares use canonical
nonnegative representatives. Rounded preprocessing values retain their integer
endpoint; aggregate commitments and hints reduce modulo the rounded modulus.

H_c binds the entire parameter encoding, every row of A, the rounded public key,
the message, and the rounded aggregate commitment. H_beta binds the same full key,
public package identity, epoch, message, participant count, and each participant's
identifier, u128 LE sequence number, and all preprocessing values. Extraction
then binds the ring and challenge weight or repetition count.

Key and public-package identities are separate 64-byte SHAKE256 outputs in the
Key domain, distinguished by `verification-key` and `share-package` kind fields.
The package identity includes every participant's indexed verification material,
using the canonical Figure 5 path display. A session identity uses the Session
domain and the same common inputs as H_beta. These metadata bindings are a local
encoding convention; the paper does not publish a canonical wire format.

## Application responsibilities

Applications must provide an appropriate `TryCryptoRng`, confidential share
distribution, authenticated participant identities, and agreement on the common
signing request. `identify_abort` can attribute only authenticated supplied
messages; it lists absent responses separately. An application must handle
transport faults and broadcast consistency itself.

Nonce ownership prevents reuse within the safe in-memory API. It cannot prevent
process forks, restored snapshots, copied persistence state, or rolled-back
randomness. Durable state and crash recovery need an application-level design
before secret serialization can be supported. Private serialization is currently
absent. Secret arithmetic and rejection sampling remain variable-time.

## Independent validation

`scripts/protocol_reference.py` computes a complete 2-of-3 signing vector with
Python big integers, schoolbook negacyclic convolution, OpenSSL SHAKE, and the
independent rational Gaussian sampler. It spells out both 2-of-3 sharing splits.
Rust tests compare the complete key/package/session identities, challenge, both
partial responses, aggregate response, and hint. These are local cross-language
vectors, not official Hermine interoperability vectors.
The same reference also generates a zero sharing, every confidential refresh
increment, and the complete next public-package identity. Refresh tests exercise
each small threshold/subset across two consecutive epochs, corrupted layouts and
norms, unchanged old signatures, and failure atomicity.

`scripts/parameters_reference.py` separately checks exact entropy counts through
degree 4096 and 256-bit targets, and bound formulas through 64 participants and
2^32 refreshes. End-to-end tests cover every threshold and authorized subset
through five participants, including 1-of-N and N-of-N algebraic boundaries;
the paper's threshold security theorem has a narrower scope.
