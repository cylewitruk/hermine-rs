# Experimental submersion primitive

This is the first executable component of the DKG research goal. Enable it with
`--features experimental-dkg`. It is neither a V3S protocol nor a key generator.
The dealer signing API cannot consume its output as a DKG key.

The bounded constructor below is `ProjectionParameters::new`; its bound getters
return `Some(bound)`. `for_consistency` instead returns parameters without a
response norm predicate or implied secret bound (`None`). That separately encoded
variant is specified in [DKG-UNIFORM-MASK.md](DKG-UNIFORM-MASK.md).

## Source check and selected bound

Flood and Submerse uses 256-row ternary projections with probabilities
`Pr[0]=1/2`, `Pr[1]=Pr[-1]=1/4`. Its Euclidean large-norm lemma has the condition
`B <= q/(82n)`, which is `B <= q/(41m)` for the flattened dimension m=2n.
The constant was cross-checked against Lemma 2.9 of
[Lattice-Based Zero-Knowledge Proofs and Applications](https://eprint.iacr.org/2022/284).
That paper's proof proceeds through Lemma 2.10 and then Lemma 2.8, which is
explicitly a normal-substitution heuristic. The cited thesis was not retrievable
from its host, so whether its later treatment removes that dependency is open.

The first implementation instead uses a looser infinity-norm predicate with an
elementary fixed-input probability bound. This also corresponds to the type of
bound discussed in the latter paper's Lemma 2.7. It avoids importing the
heuristic Euclidean constants into the executable check; it does not resolve
the DKG's privacy, extraction, or composition obligations.

The retrieved 84-page ePrint 2022/284 PDF has SHA-256
`8559bd4979c074b33392a3f5629a4b1613f41a46c497f2dbfa1c198f7ecc30d5`.

## Fixed-input probability argument

Let q be odd, let C be a positive integer with `4C < q-1`, and represent residues
in `[-(q-1)/2, (q-1)/2]`. Fix vectors x and y **before** sampling R. Accept the
response `v = R*x + y mod q` only when every centered coefficient has absolute
value at most C.

Suppose a coordinate x_j has centered absolute value greater than 2C. For one
row, condition on all projection entries except r_j. Write the fixed remainder
as a, including the corresponding mask coordinate. The three possible responses
are `a-x_j`, `a`, and `a+x_j`, with probabilities 1/4, 1/2, and 1/4.

The acceptance interval `[-C,C]` has circular diameter at most 2C. Its points
cannot include both a and either endpoint, since their circular distance is
`|x_j| > 2C`. If a is accepted, neither endpoint is; otherwise at most the two
endpoints are accepted. In both cases the row acceptance probability is at most
1/2. Independence of 256 rows gives a fixed-input acceptance probability at most
`2^-256` when any coefficient of x exceeds 2C.

Consequently the candidate accepted-secret bound is `||x||_infinity <= 2C`,
implying the coarse squared Euclidean bound `||x||_2^2 <= m*(2C)^2`. These are
conditional statements about the experiment, not deterministic conclusions from
one accepted response. A larger C improves honest acceptance while weakening the
secret bound; no completeness or hiding guarantee follows from the constructor.

This argument assumes independent uniform challenge entries and fixed x/y.
The hash-based protocol needs binding salted commitments, a suitable oracle
argument, and accounting for all adaptive queries and sessions. With a classical
union bound over Q fixed-input attempts, the projection term alone is at most
`Q*2^-256`; that expression excludes commitment failures and other protocol events.
It is not a quantum-oracle bound or a DKG security level.

## Primitive API and encoding

`ProjectionParameters` pins the input ring, number of polynomials, and C. Input
components are flattened in order, each by increasing polynomial degree. There
are 1–128 components and at most 16384 scalar columns, bounding matrix storage
at 4 MiB. A degree-256 polynomial over the same modulus is used as a zeroizing
container for the scalar mask and response. This is scalar linear algebra, not
negacyclic polynomial multiplication.

`Projection::derive` takes the parameters, a 64-byte common context identifier,
contributor 1–64, and a 64-byte contribution commitment. The context is an opaque
input here; the eventual DKG must construct it from the complete setup and fresh
session identity.

The seed is a 64-byte digest of the existing framed transcript in Domain 7 (DKG),
with these fields in order:

| Label | Bytes |
| ---- | ---- |
| `kind` | ASCII `ternary-submersion-v1` |
| `context` | 64-byte context identifier |
| `contributor` | u64 LE participant identifier |
| `commitment` | 64-byte commitment |
| `degree` | u64 LE input ring degree |
| `modulus` | u64 LE modulus |
| `components` | u64 LE component count |
| `rows` | u64 LE constant 256 |
| `response-limit` | u64 LE C |

Expand `SHAKE256(ASCII("hermine-rs/dkg/projection-expand/v1") || 0x00 || seed)`.
Read two-bit groups least significant first within each byte, map 0/3 to zero,
1 to +1, and 2 to -1, and fill the matrix row by row. The dimensions make the
number of groups an exact multiple of four. No published Hermine encoding is
implied by this convention.

`Projection::evaluate` checks all shapes and rings, computes `R*x+y mod q`, and
returns a zeroizing polynomial. `accepts_response` checks only its shape and
infinity norm. Neither method validates commitments or share consistency. Masks
must be independent and appropriately distributed; passing a zero mask can reveal
secret information and is only used in algebraic tests.

## Evidence and next obligations

`tests/dkg_projection.rs` compares full matrices and responses against independent
Python SHAKE/integer vectors, checks malformed inputs and exact norm boundaries,
and exhaustively checks the one-row argument for small odd moduli. It verifies
commutation with every Figure 5 reconstruction through seven parties, including
algebraic threshold boundaries outside the initial DKG threat model.

Salted share commitments and recipient checks are now implemented in
[DKG-SHARING.md](DKG-SHARING.md), with candidate rounds in
[DKG-ROUNDS.md](DKG-ROUNDS.md). A distribution/leakage analysis remains open.
The elementary norm argument does not establish that the projected public
sharing hides honest secrets or that its accepted private shares are consistent.
