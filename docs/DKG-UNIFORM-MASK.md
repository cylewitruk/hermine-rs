# Experimental uniform-mask variant

Status: implemented as an explicitly selected research variant alongside the
Gaussian candidate. Its fixed-projection privacy identity has an exact
finite-group model; its commitment/hash and quantum security arguments remain
open. This construction change is our investigation, not a theorem from the
source papers. See [DKG-ORACLES.md](DKG-ORACLES.md) for the simulation outline and
why existing Fiat–Shamir results do not automatically cover it.

## Recover shortness from local checks

Every accepting honest recipient checks that every private input coefficient is
bounded by L. Figure 5 reconstruction selects exactly T indexed shares and adds
them with coefficient +1. Consequently any reconstruction entirely from accepting
honest recipients has centered coefficients bounded by `T*L`. This is a
deterministic fact, even before establishing agreement between reconstructions.

If a separate mechanism establishes their consistency, this gives a common
short root. It suggests using the projection only for consistency and removing
its masked-response norm test. The initial `N >= 2T-1` restriction guarantees T
honest recipients when fewer than T parties are corrupted.

This option depends on everywhere-short private sharing. Uniform Shamir private
shares do not satisfy a useful local shortness bound, so this argument does not
replace the source V3S mechanism for arbitrary secret-sharing schemes. The
`T*L` root bound may also be too loose for useful Hermine parameters.
The uniform variant enforces `2*T*L < q` when validating its configuration.
This replaces the Gaussian variant's projected-response parameter restriction.

## Fixed-projection privacy identity

Let L denote the linear Figure 5 sharing map, acting separately on each scalar
coordinate of its root and split samples. Let X = L(W_x) be an honest short
sharing. Choose every root and split mask coordinate W_y uniformly and
independently over Z_q, and let Y = L(W_y). For a fixed public projection R,
independent of these choices, publish

```text
V = R X + Y = L(R W_x + W_y).
```

The variable `R W_x + W_y` is uniform for every fixed W_x. A linear map sends
uniform group input to uniform input on its image: every fiber is a coset of
the same kernel and has the same size. Thus V is uniform on `image(L)`,
independently of W_x. This works over finite abelian groups, including composite
q; it does not require inversion in a field or a Gaussian approximation.

For corrupted recipients C, their mask shares satisfy
`Y_C = V_C - R X_C`. Therefore `(V,Y_C)` can be simulated exactly from only
their already-revealed X_C and fixed R: sample V uniformly on the sharing image
and use this equation. In this experiment the full public projection leaks no
additional information about honest X beyond the corrupted private input shares.

This is stronger than a covariance estimate for Gaussian masks, but its scope
is narrower than the actual protocol: commitments, salts, and a hash-derived R
are absent. In particular, replacing R with `H(commitments(X,Y))` is not justified
by this fixed-projection calculation alone.

## Consistency and remaining work

The fixed-input consistency separation argument in `DKG-SHARING.md` does not
require short Y. For two distinct reconstructed pairs fixed before independent
R, the probability of equal projected values is at most `2^-256`. Thus the
candidate combination is uniform masking for privacy, projection separation for
consistency, and direct private-share checks for root shortness.

The construction remains unproved. Further work must address:

- A commitment/hash transcript simulator for static corrupted recipients,
  including openings, salts, and the dependency of R on all commitments.
- Soundness against adaptively selected oracle inputs and post-challenge
  openings; the classical and quantum query accounts must be distinguished.
- Honest Gaussian completeness under private coefficient rejection, adversarial
  contribution selection and abort, and the aggregate key distribution.
- Composition with Hermine's short-sharing leakage argument and signing theorem.

The variant removes the projected norm test. Its root bound is `T*L`; the
Gaussian candidate additionally has the conditional `2*C` projection bound, so
removing that predicate can loosen the available bound. This is a construction
change with separate assumptions, not the same proof with a different sampler.

## API and transcript

Select `Masking::Uniform` in `SharingConfig` together with
`ProjectionParameters::for_consistency(ring, components)`. The response and
implied-secret bound getters return `None`; shape checks still apply. Pairing
uniform masks with a bounded projection, or Gaussian masks with an unbounded
projection, is rejected. Both the root mask and every masking split are sampled
uniformly with unbiased coefficient rejection sampling.

The uniform context uses the existing framed DKG transcript with fields in this
order:

| Label | Value |
| ---- | ---- |
| `kind` | `sharing-context-v2` |
| `session` | Caller-supplied 64-byte session identifier |
| `degree`, `modulus`, `components` | Input dimensions |
| `threshold`, `parties`, `input-sigma` | Committee and input distribution |
| `masking` | `uniform-v1` |
| `private-limit` | L |

The challenge uses `kind = ternary-consistency-v1`, followed by `context`,
`contributor`, `commitment`, `degree`, `modulus`, `components`, and `rows`, in
that order. There is no `response-limit` field. SHAKE output is read directly
from this transcript, with four matrix entries per byte in low-bit-first order:
`00` and `11` encode zero, `01` encodes +1, and `10` encodes -1. There is no
intermediate seed expansion in this variant.

Leaf, commitment-root, and statement framing are otherwise unchanged. The
variant's distinct context flows into round agreement, output identity, and
signing provenance. All Gaussian version-1 encodings and fixtures are retained.

Run the complete DKG/signing/refresh simulation with OS randomness:

```sh
cargo run --features experimental-dkg --example dkg -- --uniform
```

Omitting `--uniform` runs the Gaussian comparison candidate. Neither selection
has a security guarantee.

## Reproducible model

```sh
python3 scripts/dkg_masking_model.py
```

The model explicitly writes out scalar 2-of-3 sharing and enumerates every mask
root and split over moduli 3, 5, 7, and 9. For every scalar projection and each
possible single corrupted recipient, it compares exact view distributions for
different roots with the same corrupted input shares. All 72 comparisons match.
This corroborates the algebraic identity; it does not test the commitment/hash
security argument or establish protocol security.

Independent Python fixtures additionally cover every coefficient and hash in a
uniform contribution, completed DKG rounds, and a signature under the resulting
key. Both variants exercise every eligible signing/reconstruction subset through
seven parties, including both allowed refreshes. Focused tests cover mask-mode
mismatches, the strict `2*T*L < q` boundary, cross-variant rejection, private
bounds/openings, unrestricted projected responses, and entropy failures.
