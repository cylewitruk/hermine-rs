# Contribution distribution and completeness analysis

Status: algebraic analysis and bounded numerical experiments for the research
construction. This does not establish the hardness of its final key distribution.
The [oracle analysis](DKG-ORACLES.md) and
[signing composition](DKG-COMPOSITION.md) remain separate obligations.

## Short private shares already reveal information

Uniform masks remove extra leakage from V in the fixed-independent-R experiment;
they do not make the underlying short sharing perfectly private. In the scalar
2-of-3 construction, party 2 receives `b = x-u` and an independent split sample,
where x and u are independent centered integer Gaussians of width sigma.
Before modular reduction and private-bound conditioning:

```text
Pr[x=k | b] ∝ exp(-(k² + (k-b)²)/(2*sigma²))
            ∝ exp(-(k-b/2)²/sigma²).
```

The posterior is an integer Gaussian centered at b/2 with width parameter
`sigma/sqrt(2)`. It depends on the observed share and is narrower than the prior.
This follows by completing the square, without a continuous-normal substitution.
It illustrates why uniform masking alone cannot prove Hermine DKG privacy.
For actual residues modulo q the posterior uses wrapped Gaussian masses; one
must either analyze those masses directly or bound the discarded wrap probability.

More generally, write the honest latent root/split coordinates as w, with short
shares `X = L(w)`. A coalition observes selected linear constraints on w modulo q.
Its posterior is proportional to the original product Gaussian weight on that
constraint set, additionally conditioned on private acceptance. Its covariance,
normalization, and available root uncertainty depend on the coalition and layout.
A scalar width rescaling is not a substitute for this conditional analysis.

## Summing contributions does not reproduce the dealer sampler exactly

Even without observations or rejection, independent integer Gaussian sums are
not exactly the integer Gaussian obtained by adding variance parameters. For two
equal-width samples and an integer sum z, completing the square gives:

```text
Pr[x1+x2=z] ∝ exp(-z²/(4*sigma²))
             * sum_{k in Z} exp(-(k-z/2)²/sigma²).
```

The last factor depends on the parity of z. At sigma=1, its odd/even ratio is
approximately `0.99979312865527491768`, rather than 1. Approximation can be
appropriate under explicit smoothing conditions and error accounting.
[Hermine, Lemma 2.3](https://eprint.iacr.org/2026/419) states such a convolution
lemma with a statistical-distance bound; it does not assert exact equality for
all widths. Its Lemma 6.1 uses additional conditions when bounding shared values.

In a malicious DKG, corrupt contributions may also depend on earlier public and
private observations, and the adversary may decide whether to abort after seeing
messages. The final distribution is therefore not justified by the convolution
of N independent honest roots. Even if at least one honest contributor retains
uncertainty, that fact alone does not identify an MLWE/MSIS instance distribution
or establish the desired security level.

## Conservative honest-completeness conditions

There is an elementary sufficient condition that avoids treating Gaussian sums
as exactly Gaussian. Let `d = ceil(log2(N))` and `D = d+1`. Each indexed input
share is a signed sum of at most D independent root/split samples per coordinate:
a left branch replaces the current value with a fresh sample, a right branch
subtracts one fresh sample, and recursion depth is at most d. Coefficients are
in {-1,+1}; different paths may share samples and need not be independent.
The extra 1 conservatively accounts for the nonzero sampled root.

If every input latent scalar has absolute integer value at most
`a = floor(L/D)`, then every private input share passes the coefficient limit L.
Centered reduction modulo q cannot increase that integer absolute-value bound.
This is sufficient, not necessary: cancellation often allows acceptance outside
this event.

For a centered integer Gaussian Z of width sigma and nonnegative integer a,
put `b=a+1`. Bounding successive positive-tail mass ratios by their first ratio,
and bounding the normalizer below by its mass at zero, gives:

```text
Pr[|Z| > a] <= min(1,
  2*exp(-b²/(2*sigma²)) / (1-exp(-(2*b+1)/(2*sigma²)))) =: tail(sigma,a).
```

If S is the number of root-plus-split vectors sampled for one contribution and
m is its input dimension, the probability that an all-honest session violates
this sufficient input event is at most
`min(1, N*S*m*tail(sigma_input,a))`. This union bound requires no independence
between final shares. It excludes entropy failures and finite-sampler overflow;
it is a statement about the ideal input distribution. The bound can be vacuous
for small L or large dimensions, so no automatic completeness profile is implied.

For uniform masks there is no projected-response norm rejection. Thus the input
condition suffices for honest mathematical validation, independent of how the
ternary R was selected.

For the Gaussian comparison variant, choose integer bounds a_x and a_y such that
`D*a_x <= L` and `m*a_x+a_y <= C`. If every input latent scalar is at most a_x
and each of the 256 mask-root scalars is at most a_y, then both the private test
and reconstructed response test pass for **every** ternary R. A sufficient
all-honest failure bound is consequently:

```text
min(1, N*S*m*tail(sigma_input,a_x) + N*256*tail(sigma_mask,a_y)).
```

Mask split samples cancel when reconstructing the root, so their magnitude does
not enter this response condition. The bound is deliberately conservative and
can be uninformative even when an example usually succeeds. No probability for
an independently selected R may simply be substituted when R is derived from
commitments to these same samples.

## Rejection and composition

A uniform contribution's private rejection depends only on X, so the exact
fixed-R uniform-masking identity survives conditioning on X passing. However,
that conditioning changes the input distribution itself. Gaussian response
rejection additionally conditions on the mask and hash-derived projection.
Fresh session identities and fresh entropy prevent intentional state reuse;
they do not erase statistical selection effects from retries.

The post-DKG matrix is derived from the full accepted contribution transcript.
A reduction must account for its correlation with those inputs and adversarial
oracle queries. The implemented local share bound and signing triangle bounds
prove algebraic acceptance properties for checked inputs, not the hardness or
unforgeability of this distribution. Refresh and nonce acceptance introduce
further conditioning that a complete composed proof must include.

## Reproducible evidence and remaining questions

```sh
python3 scripts/dkg_distribution_model.py
cargo nextest run --features experimental-dkg --test dkg_distribution
```

The numerical model uses 80-digit Decimal arithmetic on integer coordinates
-40 through 40. It checks 14 conditional-density identities at widths 1 and 2
and the nonconstant convolution factor. A geometric bound on omitted prior mass
is below `1e-90`; numerical comparisons use tolerance `1e-60`. It is an unreduced
scalar illustration, not a certified parameter calculator or simulation of the
committed DKG. Symbolic Rust tests check signed latent forms, the conservative
support bound, and exact root reconstruction for eligible committees through
15 parties, using no Gaussian approximations.

A complete security analysis still needs coalition-conditioned short-sharing
hardness, quantified rejection and wrapping losses for selected parameters,
adversarial contribution/abort accounting, a valid oracle reduction, and signing
composition. The experiments above make these obligations more explicit; they
do not certify any example or benchmark configuration.
