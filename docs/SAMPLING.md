# Discrete Gaussian sampling

Hermine Definition 2.2 uses probability proportional to
`exp(-x²/(2 sigma²))`. The implementation takes an explicit positive integer
standard deviation, not a variance or bit-width.

The construction follows Algorithms 1–3 in
[Canonne, Kamath, and Steinke, The Discrete Gaussian for Differential Privacy](https://papers.nips.cc/paper_files/paper/2020/file/b53b3a3d6ab90ce0268229151c9bde11-Supplemental.pdf).
The authors also provide a
[Python reference](https://github.com/IBM/discrete-gaussian-differential-privacy).

## Integer-width specialization

For integer sigma, we select Laplace scale `t = sigma`; the published general
algorithm chooses `floor(sigma)+1`. Both use the same rejection identity. Our
proposal mass and acceptance probability multiply as follows:

```text
proposal(y) ∝ exp(-|y|/sigma)
accept(y) = exp(-(|y|-sigma)²/(2 sigma²))
proposal(y) * accept(y) ∝ exp(-y²/(2 sigma²) - 1/2)
```

Thus normalization gives exactly the target discrete Gaussian distribution in
unbounded arithmetic. The acceptance rule uses only integer rational Bernoulli
trials; no exponential or floating-point approximation is evaluated. Laplace
proposals reject the negative representation of zero to avoid double-counting.

## Implementation limits

Supported integer standard deviations are `1..=2^36`. Arithmetic uses checked
finite integers, returning an error for an unrepresentable proposal, output, or
counter. Entropy errors propagate. There is no silent tail clamp, fixed iteration
cutoff, or fallback value. Because representation failures are possible, the
finite implementation must not be described as an unconditional sampler over all
integers. Failure probabilities and conditioning require review before a concrete
security profile is certified.

The algorithm has variable-time rejection, division, and GCD operations. It is a
correctness-oriented backend, not a side-channel hardened implementation.
Polynomial coefficient buffers are zeroized; this does not guarantee erasure of
every compiler-generated scalar temporary or register.

Randomness comes from a caller-provided `rand_core::TryCryptoRng`. The caller must
seed and protect it correctly. No predictable production RNG is provided.
