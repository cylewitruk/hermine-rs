# Candidate DKG rounds

The `experimental-dkg` feature implements a two-broadcast-round research
construction with abort. It combines the candidate contributions specified in
[DKG-SHARING.md](DKG-SHARING.md), derives a common matrix, and returns public
verification shares plus each participant's own secret/error shares. The result
is a distinct `DkgOutput`; its consuming [signing bridge](DKG-COMPOSITION.md) uses
explicit DKG correctness bounds. Privacy, key distribution, and cryptographic
signing composition remain unproved.

## Setup and transport contract

`DkgConfig` contains a validated contribution configuration, an NTT root, and
the number of secret components. The remaining input components are errors;
both counts must be in `1..=64`. All parties agree on these values and a fresh
64-byte session identity. Contribution restrictions, including `N >= 2T-1`,
still apply.

The application supplies consistent authenticated broadcast and confidential
authenticated pairwise delivery. Incoming map keys are authenticated sender
identities, not values copied from untrusted message bodies. Broadcast maps
contain exactly parties `1..=N`; first-round private maps contain every party
except the recipient itself. Reordering arrivals does not change their canonical
map order. Repeated deliveries must be handled by the transport before forming
these maps; replacing a map entry does not implement duplicate detection.

A failed or missing delivery aborts the session. Transitions consume their
private state on success and error, and states cannot be cloned. Starting again
requires a fresh common session identity and entropy; the library has no global
registry preventing an application from reusing an identity. No state recovery,
timeout service, reliable broadcast implementation, or robust exclusion protocol
is provided.

## Transitions

1. `DkgSession::start` samples one contribution without internal retries. It
   returns a public statement, N-1 confidential outgoing payloads, and a
   `ContributionRound` retaining the participant's own payload. Only the
   contributor temporarily knows all shares of its own contribution.
2. `ContributionRound::accept` consumes all N public statements and the N-1
   incoming private payloads. It checks every public contribution and every
   locally addressed opening/equation, and pins the local party's original
   statement identity. It sums the input vectors at each local index modulo q.
   Masks and salts are dropped and their storage zeroized.
3. The same transition hashes the ordered complete contribution transcript and
   derives A from that digest. For each local sum `(s_i,e_i)`, it computes
   `v_i = 2(A s_i + e_i)` using the NTT. It returns a `VerificationRound` and a
   broadcast `VerificationMessage` containing the transcript acknowledgment and
   all local indexed public images.
4. `VerificationRound::finish` consumes all N second-round broadcasts. It checks
   authenticated identities, identical acknowledgments, the unchanged original
   local broadcast, and exact image layouts, rings, and dimensions. `VandCheck`
   must accept every public reconstruction. The returned `DkgOutput` contains the
   common matrix, verification sharing, reconstructed unrounded public key,
   and only this participant's confidential summed secret/error shares.

The research `shares()` accessor borrows that participant's secret/error
components for experiments. Polynomial storage is zeroized on drop and Debug
does not print coefficients. The existing variable-time arithmetic and sampling
limitations remain. This accessor is not a checked import into Hermine signing.

## Algebra and agreement limits

For honest contributions, linearity of sharing and the public-image map gives
`VandRecover(v_i) = 2(A sum_d s_d + sum_d e_d)` for every authorized subset.
The implementation checks this against independent arithmetic and all small
eligible committees. More generally, the corresponding claim for accepting
honest recipients depends on the conditional consistency argument in
`DKG-SHARING.md`. Verifying public images alone would not prove consistency of
their private preimages in the kernel of the public-image map.

With consistent second-round broadcast and collision-resistant transcript
binding, completed honest participants use the same contribution digest and
public image sharing. A peer that saw another valid first-round contribution
cannot acknowledge both digests with one second-round broadcast. The tests
exercise this same-session equivocation. This check does not build broadcast
from ordinary authenticated channels: a malicious network could otherwise give
different complete second-round views to different recipients.

At least T honest recipients remain under the initial corruption restriction.
Their unchanged images anchor the full public key if the candidate private
sharing consistency argument holds. `finish` returns no partial result if any
required broadcast is absent or rejected. Agreement does not guarantee
termination, simultaneous output, or a public proof identifying a faulty peer.

A is derived after every included contribution statement, including its masked
public sharing. This fixes the implementation's ordering. It does not establish
that A is independent of adversarially chosen contributions or that transcript
grinding and selective abort preserve a desired distribution. The random-oracle
and quantum analyses remain open.

## Norms and resources

Each accepted local contribution coefficient has absolute centered value at
most L. Consequently each locally summed coefficient has absolute centered value
at most `N*L`, and the joint squared norm is at most `m*(N*L)^2`. Modular reduction
can only decrease the centered norm relative to the unreduced integer sum. This
deterministic bound is not a Gaussian distribution claim or a signing bound.

For K total indexed shares in one contribution and m flattened input
coefficients, setup additionally requires:

- `N*K*m*256 <= 2^29` scalar projection terms for generating all contributions.
- `N*K*(m+256) <= 2^23` private scalar coefficients across all contributors.

These conservative whole-session limits supplement the contribution limits and
are checked before allocating a layout. They are implementation resource caps,
not cryptographic parameters or total-runtime estimates; recipients repeat
projection work during validation. In-memory messages are bounded structurally during
validation; canonical bounded message decoders are specified in
[DKG-WIRE.md](DKG-WIRE.md).

## Transcript encoding

All integer values below are u64 little endian; identifiers are 64 bytes. Fields
use the framing in [TRANSCRIPTS.md](TRANSCRIPTS.md). DKG transcripts use domain 7
and start with a `kind` field. Polynomial fields use the helper schema in
`DKG-SHARING.md`. This is a local format, not an author-published encoding.

| Kind | Fields in order |
| ---- | ---- |
| `round-context-v1` | `session`, `root`, `columns`; digest becomes the session field of `sharing-context-v1` (Gaussian) or `sharing-context-v2` (uniform), which binds all other configuration fields |
| `round-contributions-v1` | `context`; for every party in ascending order, `participant`, `statement` |
| `round-output-v1` | `context`, `agreement`, `rows`, `columns`; row-major matrix polynomials with purpose `matrix`; for each party, `participant`, `shares`, then each ordered `path` and its public-vector polynomials with purpose `verification`; finally full-key polynomials with purpose `full-key` |

Matrix derivation uses domain 3 with fields `kind = dkg-matrix-v1`, `agreement`,
`ring-degree`, `ring-modulus`, `matrix-rows`, `matrix-columns`. Expand the SHAKE256
stream directly. Each scalar coefficient uses the existing unbiased extraction:
take the low `ceil(log2(q))` bits of the next 16 little-endian bytes and reject
values >= q. Fill polynomial coefficients, columns, then rows. The NTT root is
already bound through the contribution context.

## Reproducing the experiments

```sh
cargo run --features experimental-dkg --example dkg
cargo nextest run --features experimental-dkg --test dkg_rounds
python3 scripts/check_vectors.py
```

The example simulates separate participants and routes confidential messages only
to their intended owners. A network harness may hold all participant states; an
actual participant must not receive other recipients' payloads. The independent
Python fixture includes all contribution identities, local sums, matrix
coefficients, public images, full key, and final output identity. Its public-key
calculation uses schoolbook negacyclic multiplication instead of the Rust NTT.

The [signing bridge and bounds](DKG-COMPOSITION.md) are now implemented and tested.
Bounded [DKG codecs and transport/abort examples](DKG-WIRE.md) are also implemented.
The DKG codec has a seeded sanitizer fuzz target.
[Benchmarks](DKG-BENCHMARKS.md) and a [construction review](DKG-REVIEW.md) document
the implementation evidence. The security ledger
in [DKG.md](DKG.md) remains open regardless of passing implementation tests.
