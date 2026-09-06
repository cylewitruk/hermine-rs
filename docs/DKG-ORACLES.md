# Hash-derived challenges: research obligations

Status: analysis of the experimental uniform-mask candidate, not a completed
classical or quantum security proof. The fixed-projection identity in
[DKG-UNIFORM-MASK.md](DKG-UNIFORM-MASK.md) does not justify replacing an independent
challenge with a hash of commitments by itself.

## Fiat–Shamir and lattice schemes

Fiat–Shamir is compatible with lattice cryptography. ML-DSA uses the
Fiat–Shamir-with-aborts paradigm, as described in
[NIST's FIPS 204 presentation](https://csrc.nist.gov/csrc/media/Presentations/2024/fips-204/images-media/perlner-fips-204-pqc2024.pdf).
That fact does not establish applicability to this distributed proof.

[Don, Fehr, Majenz, and Schaffner (2019)](https://arxiv.org/abs/1902.07556)
provide a quantum random-oracle reduction from the transformed protocol to the
underlying public-coin three-round protocol, with conditions on its security
properties. We have not formalized this candidate as such a protocol or
established the required quantum properties of its distributed verifier.

[Don et al. (2022), Section 3.2 and Theorem 4.2](https://eprint.iacr.org/2022/270)
analyze commit-and-open protocols whose response opens a challenge-selected
subset of previously committed strings. Our challenge is a projection matrix;
our response also contains projected sharings and recipient-specific private
openings. The protocol is not directly in that class. Its theorem's bounds
cannot be imported without an embedding and proof of the required properties.

[Unruh (2017), Theorems 18 and 20](https://eprint.iacr.org/2017/398)
gives results with hypotheses including honest-verifier zero knowledge and
unpredictable commitments. Independent secret salts alone do not establish
honest-verifier zero knowledge for the full coalition view here.

These results are directions for proof work. None is a certificate for this
implementation, and a classical query argument is not a quantum query argument.

## Conditional classical simulation outline

Consider one honest contributor and a fixed set C of corrupted recipients.
Model the domain-separated leaf hashes, commitment-root hashes, and direct
challenge XOF as random oracles. The following is a proposed simulation order,
conditioned on fresh programming points and unqueried honest leaf preimages:

1. Given the corrupted input shares X_C and public context, sample an independent
   ternary R with the specified distribution.
2. Sample uniform mask root/split coordinates and apply the sharing map to obtain
   V uniformly distributed on its image. Define `Y_C = V_C - R X_C`.
3. Choose the corrupted recipients' independent salts and compute their leaf
   hashes from their full private payloads. Choose independent random digests
   for the honest recipients' leaves, whose payloads are not exposed.
4. Hash the ordered leaves into the commitment root. Program the fresh direct
   challenge-XOF input to the sampled R, using the corresponding distribution
   of packed bytes, including independent choices between the two zero codes.
5. Compute the public statement identity and deliver only the appropriate
   corrupted private openings, alongside the common public statement.

For fixed R, step 2 has the exact joint distribution of `(V,Y_C)` conditional on
X_C by the finite-group identity. This is only one component of a proof. A full
simulation must account for adversarial oracle queries before and after the
contribution, collisions, attempts to guess honest salted preimages, multiple
contributors, concurrent sessions, and conditioning on successful programming.
No complete advantage bound for those events is claimed here. Adaptive corruption
would additionally require supplying consistent previously hidden openings and
is outside the initial threat model.

Uniform masks remove the Gaussian projected-response rejection. Honest private
input rejection depends only on X, so conditioning on that event preserves the
fixed-R uniform-masking identity. It does not establish the desired distribution
of X after rejection or address adversarial selective aborts.

## Consistency and extraction

The `2^-256` calculation concerns distinct reconstructed private pairs fixed
before an independently sampled R. A hash-derived challenge permits an adversary
to choose among queried commitment roots. Post-challenge openings additionally
require commitment binding or an extraction argument. Query counts, reconstruction
choices, parties, and sessions must appear in an actual reduction; the single
fixed-input probability is not a DKG security level.

The uniform variant extracts challenge bytes directly from its framed transcript.
The Gaussian comparison variant retains its original 64-byte seed followed by
SHAKE expansion. Their encodings are intentionally distinct. The direct form
avoids an additional expansion-oracle step in a proposed proof; it does not make
the commitment or Fiat–Shamir argument automatic.

## Quantum and composition work still required

Quantum queries cannot be treated as a classical query log, and programming a
point requires a quantum argument. The above outline is therefore not a QROM
simulator. Next proof work must specify the exact distributed statement and
coalition view, select an applicable theorem, verify its hypotheses, and derive
bounds including all relevant query and session counts.

Even a completed contribution proof would leave the aggregate key distribution,
malicious contribution selection, matrix derivation, short-share leakage, and
Hermine signing/refresh composition to analyze. Executable vectors establish
implementation agreement with the written algorithm, not these properties.
