# Candidate verifiable short Vandermonde contribution

Status: implemented experimental contribution mechanism, not a completed DKG.
The cryptographic arguments below are conditional research arguments. In
particular, a privacy theorem and composition with Hermine signing are unfinished.
No security guarantees or production-use recommendations are made.

This document specifies the Gaussian comparison variant. The explicit uniform-mask
variant and its changed context, challenge, and bound predicate are specified in
[DKG-UNIFORM-MASK.md](DKG-UNIFORM-MASK.md). Both share the recipient commitment,
layout, opening, and local equation checks below.

## Configuration and messages

`SharingConfig` contains the projection parameters, committee `(T,N)`, Gaussian
input width, mask distribution, and private input coefficient limit L. Here the
mask distribution is `Masking::Gaussian { sigma }`. Both
widths apply to the corresponding root and every independent Figure 5 split.
`SharingSession::new` requires `2 <= T < N <= 64` and `N >= 2T-1`, validates the
widths and `0 < L <= floor(q/2)`, and hashes every configuration field with a
caller-chosen fresh 64-byte session identifier.

Before allocating share paths, it counts all indexed shares K and requires
`256*K*m <= 2^28` and `K*(m+256) <= 2^22`, where m is the flattened input
dimension. These are implementation work/storage limits, not security bounds.
The latter limits private scalar storage to 32 MiB before container overhead;
public projections, copies, and allocator behavior require additional memory.

| Message or object | Contents and handling |
| ---- | ---- |
| `Contribution` | Context, contributor, N recipient commitments, all public projected shares; requires consistent authenticated broadcast |
| `PrivateContribution` | Context, contributor, recipient, complete statement identity, secret 32-byte salt, exact indexed private input/mask map; confidential authenticated delivery |
| `PrivateShare` | Input polynomial vector and degree-256 masking polynomial |
| `ContributionSet` | One contributor's public statement and N private deliveries; that contributor naturally knows its own entire input, but not other contributors' secrets |
| `CheckedContribution` | Immutable checked public statement, statement identity, pinned session and cached projection; recipients still need to check their private deliveries |

Canonical bounded transport codecs for these messages are described in
`DKG-WIRE.md`; consumed distributed round states are in `DKG-ROUNDS.md`. Polynomial storage and salts zeroize
on drop; the private delivery is not Clone and Debug omits its payload and salt.
Private fields remain accessible for explicit transport integration.

## Generation and validation

For contributor j, `contribute` performs the following operations without an
internal retry loop:

1. Sample the input root x and share it with Figure 5, using independent samples
   at every split. Input polynomials contain the eventual secret/error components.
2. Independently sample a 256-coordinate mask root y and share it with the same
   Figure 5 layout and its own Gaussian width.
3. For each recipient i, combine its X/Y maps, validate shapes and the direct
   input limit `||X_i[path]||_infinity <= L`, and hash the complete recipient
   payload with an independent secret salt. The implementation samples the salt
   before this local shape/bound check.
4. Hash the ordered list of all N recipient commitments to produce the root
   commitment. Derive R using the existing projection primitive and that root.
5. Publish `V_i[path] = R*X_i[path] + Y_i[path] mod q` for every indexed share.
   Check VandCheck and the reconstructed response's infinity-norm limit C.
6. Hash the complete public statement, and bind every private delivery to that
   statement identity. Drop root/split temporaries when no longer needed.

The code samples each salt before validating that recipient's shape and norm;
every payload and salt is fixed before R is derived. A failure returns an error
and drops partial private outputs. Failure/retry conditioning is not ignored:
the enclosing DKG must abort the attempt and use a fresh session on restart.

`check_contribution(sender, public)` checks the authenticated sender argument,
context, full commitment count, exact public path layout and rings, VandCheck,
and the reconstructed response norm. Only then does it cache R and the complete
statement identity.

`check_recipient(recipient, private)` checks the intended recipient argument,
contributor, context and statement identity, exact private layout and shapes,
direct input norms, salted commitment opening, and every local projection
equation. Success is local acceptance only. It does not establish that other
recipients accepted or that a distributed key may be released.

A flat ordered list of N salted commitments replaces the source paper's Merkle
tree. At N<=64 this adds at most 4096 commitment bytes to the common statement
and avoids a separate path verifier. The root binds every recipient commitment;
the list is public, but its salts and leaf preimages remain private.

## Hash schemas

All hashes use the existing Domain 7 framed SHAKE transcript and 64-byte digests.
Every listed integer is u64 LE and every field retains the existing label/length
framing. Paths use the canonical Figure 5 `Index` display. The following field
sequences are normative for this local research convention:

| Kind | Fields after `kind`, in order |
| ---- | ---- |
| `sharing-context-v1` | `session`, `degree`, `modulus`, `components`, `response-limit`, `threshold`, `parties`, `input-sigma`, `mask-sigma`, `private-limit` |
| `sharing-leaf-v1` | `context`, `contributor`, `recipient`, `salt`, `shares`; for each ordered path: `path`, `components`, each input polynomial, then the mask polynomial |
| `sharing-root-v1` | `context`, `contributor`, `recipients`, each recipient digest under `leaf` |
| `sharing-statement-v1` | The root fields; then for each recipient: `recipient`, `shares`, and for each ordered share: `path`, projected polynomial |

A polynomial is framed as `polynomial` (ASCII purpose `input`, `mask`, or
`projected`), `degree`, `modulus`, and each canonical coefficient under the repeated
label `coefficient`. Input and mask coefficients are streamed into SHAKE without
allocating a plaintext serialization buffer. `statement` is deliberately absent
from the leaf preimage: it is computed after the projected values exist and is
checked against the complete statement on reception, avoiding a hash cycle.

## Conditional consistency and shortness arguments

Fix all salted private leaf preimages before an independently sampled R, and
assume binding commitments and common public-statement agreement. For two fixed
T-party reconstructions S and S', local equations and public VandCheck imply
`R*(x_S-x_S') + (y_S-y_S') = 0 mod q` if every participant involved accepts.
If the input difference is nonzero, fix one nonzero coordinate and condition on
every other entry in a projection row. Over an odd modulus, the three possible
values are distinct, with maximum point probability 1/2. Independent rows bound
the equality probability by `2^-256`. A zero input difference with a nonzero mask
difference cannot satisfy the equation at all.

With at least T honest recipients, select a fixed canonical T-party honest set
before the challenge. Comparing every other honest T-party set to it costs at
most `binomial(N,T)-1` such events. Applying the fixed-input coefficient argument
in `DKG-SUBMERSION.md` to the canonical reconstruction adds one more event for a
root with a coefficient greater than 2C. A coarse combined contribution term is
therefore `binomial(N,T)*2^-256` in that ideal fixed-input experiment. The direct
recipient input limit separately bounds every accepted honest private share by L.

This is not yet a proof of the hash-derived protocol: extracting/binding all
required preimages, adaptive oracle queries, multiple contributors, abort
selection and quantum queries require their own argument. The comparison concerns
reconstructions consisting entirely of accepting recipients; it does not assert
that a corrupted recipient followed the private checks. Transcript agreement and
availability are also not implemented by this contribution primitive.

## Privacy and distribution obligations

Represent Figure 5 sharing abstractly as a linear map L on the root and all
independent split samples W. Using the same layout gives
`V = L(R*W_x + W_y)`, where R acts separately on each input sample vector.
This identity explains why full public V potentially exposes masked information
about **every split sample**, not just the root. The original Shamir simulator
cannot simply be reused for these short, correlated shares.

A promising analysis is to condition the independent Gaussian latent samples on
their masked projections, then analyze the extra linear observations available
to corrupted recipients. The continuous Gaussian precision-matrix calculation
suggests the relevant covariance loss, but does not prove the discrete,
hash-conditioned, rejection-conditioned construction. In particular, the
reduction must handle each sample's conditional mean/covariance and their effect
on Hermine's everywhere-short sharing argument.

No confidentiality theorem is claimed here. Nor can the aggregate input be
assigned the dealer distribution merely by scaling a Gaussian width. The
[candidate rounds](DKG-ROUNDS.md) now fix public-matrix generation order and
return a separate research output. The [signing bridge](DKG-COMPOSITION.md) now
uses DKG-specific correctness bounds. Its security reduction remains pending.

## Executable evidence

`tests/dkg_contribution.rs` covers every eligible committee through seven parties,
every contributor and recipient, and all authorized private reconstructions.
Adversarial checks cover context/identity changes, wrong paths/rings/dimensions,
oversized inputs/responses, altered salts/masks/commitments, inconsistent public
shares, and consistent public changes that still fail local equations. Entropy
failures during input sampling, mask sampling, and salt generation return errors.

`scripts/dkg_contribution_reference.py` independently writes out the two 2-of-3
splits and computes all private/public coefficients, salts, leaf commitments,
context/statement identities and entropy consumption. The checked-in vector
matches the Rust implementation byte for byte at the framed hash boundaries.
These tests establish implementation/algebraic evidence, not the open privacy
or composition claims.
