# Experimental signing and refresh composition

`DkgOutput::into_signing` consumes one completed candidate output and returns
`ParticipantKeys`: the public package and only that participant's secret share.
It uses a distinct DKG parameter profile. The executable composition has explicit
correctness bounds; DKG privacy, key-distribution hardness, and composed
unforgeability remain unproved. No security profile is certified by this API.

## Configuration and key binding

The supplied signing `Config` must match the DKG's ring, NTT root, committee,
and matrix dimensions. The initial input distribution and coefficient limit come
from the completed DKG. `Config.secret_sigma` controls subsequent zero-sharing
refreshes; it does not describe the sum of DKG contributions. All parties must
agree on the remaining signing settings before using the resulting key.

`Parameters::for_dkg` derives the profile from an immutable `PublicOutput`.
`KeyOrigin::ExperimentalDkg` records the DKG output identity and the private
contribution limit. Both enter the parameter encoding, long-term key identity,
signing transcripts, and pinned wire format. `dealer_keygen` rejects this profile
before requesting entropy. Dealer profiles keep their original version-1 bytes,
sampling behavior, and independent fixtures.

The bridge checks each local private pair's public image, retains the secret
components, and drops the private errors. Original DKG polynomial storage is
zeroized on drop. The consumed output cannot be imported twice through the safe
ownership API. Applications must still prevent session reuse, process rollback,
and duplicated durable states; no persistent nonce store is implemented.

## Integer correctness bounds

Let `ceil_sqrt(x)` denote exact upward integer rounding. Write n for the ring
degree, k and ell for matrix dimensions, T and N for the committee, M for the
number of preprocessing columns, omega for challenge weight, alpha for the
tail multiplier, L for the private contribution coefficient limit, and Q_rf for
the refresh allowance. Define `m = n*(k+ell)` and `d = ceil(log2(N))`.

| Bound | Derivation |
| ---- | ---- |
| `B_initial = N*L*ceil_sqrt(m)` | Every accepted local contribution coefficient is bounded by L; sum N contributions |
| `B_refresh = alpha*sigma_refresh*ceil_sqrt(m*d)` | Existing per-token refresh acceptance bound |
| `B_secret = B_initial + Q_rf*B_refresh` | Triangle inequality over all accepted lifetime updates |
| `B_nonce = alpha*sigma_nonce*ceil_sqrt(m)` | Enforced separately on every generated `(r,e)` preprocessing pair |
| `B_partial = 2*omega*B_secret + M*B_nonce + M*2^(nu_prime-1)*ceil_sqrt(n*k)` | Sparse challenge multiplication, checked nonce pairs, and preprocessing rounding |

Centered modular reduction cannot increase these norms relative to an integer
lift. Each signed monomial preserves Euclidean norm; the challenge is a sum of
omega such monomials. Hence its multiplication operator has norm at most omega.
For a local response and its verification residual, the secret/error part is
bounded by `2*omega*B_secret`. The nonce part is a sum of M checked joint pairs,
so its deterministic triangle bound is `M*B_nonce`, not the dealer profile's
Gaussian `sqrt(M)` term. This argument does not assume the hash-selected binding
factors are independent of preprocessing values.

Each private refresh token is checked jointly with its implied error before it
is installed. The existing update code preserves lifetime nonce reservations and
rejects stale epochs. Thus the accumulated refresh term is bounded for any
accepted sequence of at most Q_rf updates. This is a norm argument, not a claim
that malicious refreshes or DKG leakage preserve the dealer security proof.

The final signature bound keeps the baseline rounding analysis:

```text
scale = 2^nu_w
q_rounded = floor((q + scale/2) / scale)
q_perp_positive = max(q - scale*q_rounded, 0)
B_signature = T*B_partial
            + [3*(scale/2 + q_perp_positive) + omega*2^(nu_t-1)]*ceil_sqrt(n*k)
```

All intermediate computations use exact integers and final bounds must fit u64.
These bounds may be too loose for any useful security parameters; passing
representability and algebra checks does not establish MLWE/MSIS hardness.

## Nonce failure and refresh behavior

For DKG profiles, `preprocess` reserves its lifetime sequence number before
sampling and tests `||r||^2 + ||e||^2 <= B_nonce^2` for each column. Equality is
accepted. Excess returns `Error::NonceBound`, drops the private material, and
leaves the reservation burned. No internal retry hides this event. A caller may
request a new nonce using the next reservation; the effect of these acceptance
events on the cryptographic proof remains an explicit composition obligation.

The existing refresh implementation is dealer-assisted zero sharing, not a new
distributed refresh protocol. The refresher needs the public package, not the
old secret. Each recipient verifies the common proposal and only its own private
increment. Old signatures remain valid; old nonces cannot be used with a refreshed
share, and refresh does not reset lifetime preprocessing limits.

## Version-2 profile and local material pins

The first 23 u64 fields use the same ordering as the dealer profile, with version
2 and DKG-derived bounds. Append u64 L and the 64-byte DKG output identity.
The resulting profile is 256 bytes; the dealer profile remains 184 bytes. The
outer `HRMN` packet header stays at version 1. Decoders compare the caller's full
pinned profile and reject downgrade, origin, and bound changes.

An origin label alone cannot authenticate a matrix or key. Locally constructed
DKG profiles additionally cache two SHAKE256 material hashes derived from their
`PublicOutput`: `(A, rounded_key)` and `full_key`. Public-key decoding checks the
first; public-package decoding also checks the reconstructed full key against
the second. This rejects even consistent share changes that preserve the rounded
key but change its full-resolution value. Refreshes must preserve that same full
key. These derived caches are not separately negotiated or serialized; they are
recomputed from the locally supplied completed DKG output.

The caches use domain 7. `signing-material-v1` binds degree, modulus, matrix rows,
matrix columns, every matrix polynomial, rounded row count, and every rounded
row. `signing-full-key-v1` binds degree, modulus, vector dimension, and its rows.
Each row is framed as `row` (purpose), `length` (u64), and each `coefficient`
(u64), using purposes `matrix`, `rounded`, and `full`. These internal hashes are
not signatures or substitutes for authenticating the original DKG session.

## Evidence

```sh
cargo run --features experimental-dkg --example dkg
cargo nextest run --features experimental-dkg --test dkg_signing
python3 scripts/check_vectors.py
```

Tests cover every eligible committee and authorized subset through seven parties,
signing at epochs 0, 1, and 2, preservation of old signatures and counters,
refresh exhaustion, mismatched bridge configurations, parameter downgrades, and
substituted public material. Public-seed Gaussian cases reach exact nonce-bound
equality and excess; both successful and rejected attempts consume reservations.

The independent Python fixture continues the independently generated DKG round
output through parameter encoding, key/package identities, preprocessing,
binding factors, challenge, partial responses, and final signature. It uses
schoolbook polynomial products and Python big-integer bound calculations.
The example runs with OS randomness and routes only recipient-local private
messages. The [security ledger](DKG.md) remains open.
