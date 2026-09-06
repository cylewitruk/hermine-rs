# Direct interactive contribution candidate

Research specification, 2026-09-06. Proposed here; not implemented in Rust and
not a complete DKG security proof. The decision, source assessment, MPC
alternative, and whole-system obligations are in
[DKG-INTERACTIVE.md](DKG-INTERACTIVE.md).

## Model and notation

Use a fixed static corrupt set C, f < T, N >= 2T-1, classical confidential
authenticated pairwise channels, and consistent authenticated broadcast. Honest
endpoints store classical delivered values before any challenge. The initial
efficient-simulation construction below uses a prime q; the probability and
translation lemmas themselves work for every odd q. This is a narrower proposed
profile than the current library's general odd-modulus algebra.

Let S be the linear Figure 5 map from latent root/split coordinates to every
indexed recipient share. Let S_C select all indexed shares held by C. Input
shares X have m scalar coordinates; projection masks have r coordinates. R acts
on the scalar dimension and commutes with the sharing map. Write L for a private
input coefficient bound and use r=256 only as an illustrative row count.

Every contributor j samples one honest short sharing X_j. For each challenger
h in {1,...,N}, it independently samples all root/split mask coordinates W_jh
uniformly in Z_q and sets Y_jh=S(W_jh). Uniformity of only the mask root is
insufficient. Every mask block is independent of X and all other mask blocks.
Honest inputs must pass their local coefficient limits before delivery; the
sampling/failure distribution is an explicit separate obligation.

## Phase schedule

| Phase | Required action and transition |
| ---- | ---- |
| Setup | Agree on session, identities, T,N, q, dimensions, row count, bounds, version, and matrix-generation policy |
| Private delivery | Each j sends each i its complete X_ji and Y_jhi for every h, using canonical indexed layouts; i checks shape and the bound L and stores its first valid payload |
| Ready barrier | Each i broadcasts READY only after receiving and validating every contributor's payload. Every honest challenger waits for all N authenticated READY statements |
| Challenge | Each h broadcasts one fresh independent full ternary matrix R_h; collect all N matrices and check shape/entry encoding before any honest response |
| Response | Each j broadcasts every V_jh=R_h X_j+Y_jh, with full indexed layout. Each i checks public VandCheck and all its local equations against stored private values |
| Acceptance | Broadcast acceptance of the complete common response transcript only after every required public/private check; wait for all N acceptances before proceeding to key assembly |
| Key assembly | With a separately justified common A, form aggregate local secret/error shares, broadcast verification shares, check their public consistency and local image, and agree on the complete public output |

Own contributions/challenges are included and pinned locally. Payload keys include
version, session, phase, contributor, recipient, and challenger where applicable.
An honest endpoint never overwrites a stored input with a later one. Consistent
broadcast forbids differing public values under one sender/phase identity.

READY authenticates the fact of receipt, not a public digest of the private
values. Publishing such a digest would add a new privacy/commitment obligation.
Public transcript identifiers may hash public material for engineering purposes;
the ideal proof compares the full public transcript, so collision security of
any compact replacement must be accounted for separately.

One honest READY certifies only its own receipt. All N READY statements are
needed to establish that every honest recipient's values are fixed before any
honest challenge. An all-READY barrier is stronger than simply observing N
contribution announcements. Honest parties must not release a response early.
Corrupt challenges may depend on earlier challenge messages and previously
received private values. Honest challenges do not depend on them: each is sampled
from fresh private entropy after the barrier.

No member is assumed to know which challenger is honest. The protocol checks
every block, and the proof fixes one honest challenger for analysis. One must
not select a favorable subset of challenges after seeing their values.

## Lemma 1: conditional consistency and shortness

Fix a complete pre-challenge classical prefix, including every private value
already stored at honest endpoints. These values may have been chosen by a
quantum adversary; they are now classical records. Fix one honest challenger h
and one canonical T-member honest reconstruction U. If another honest T-member
set U' reconstructs a different input, local equations and public consistency
imply the following necessary condition for acceptance of contributor j:

```text
R_h * (x_j,U - x_j,U') + (y_j,h,U - y_j,h,U') = 0 mod q.
```

Choose a nonzero coordinate d of the input difference. Condition on all other
entries of a projection row. Multiples -d,0,d are distinct for odd q, including
composite q; their probabilities are 1/4,1/2,1/4. Therefore one row satisfies the
equation with probability at most 1/2. The r rows are independent, giving
`2^-r`. If the input difference is zero and the mask difference nonzero, the
equation cannot hold.

Union over the other honest reconstructions and contributors. A coarse bound,
valid without knowing the actual f, is:

```text
Pr[any inconsistent honest reconstruction AND honest completion]
    <= N * (binomial(N,T) - 1) * 2^-r.
```

This is an unconditional per-attempt event bound, not the probability conditioned
on completion. The response can depend arbitrarily on R_h, but acceptance still
implies one of the fixed-difference events. Correlated challenges from other
members cannot increase this upper bound, since all blocks must pass. No
commitment extraction, oracle programming, or rewinding is used in this lemma.
Its reasoning also holds against quantum computation in the stated ideal
classical-delivery model: condition on the recorded values, then sample the
honest R_h independently of the remaining adversarial quantum state.

Outside that event, all accepting honest T-member reconstructions have a common
root. They add exactly T shares with coefficient +1, so its centered infinity
norm is at most T*L. `2*T*L < q` also prevents ambiguity between these small
integer representatives. An aggregate of N contributors has local bound N*L
and root bound N*T*L by the triangle inequality. These bounds neither certify
usable signing parameters nor assert correct private behavior by corrupt members.
The lemma establishes honest reconstruction consistency, not a proof of knowledge
of a valid full private sharing for every corrupt recipient.

With r=256, the conservative one-attempt exponents are 253,250,238,189 for
2-of-3, 3-of-5, 8-of-16, 32-of-64 respectively. These concern only this failure
event. For M attempts, a conditional per-attempt bound permits an M-fold union
bound even with adaptive restarts. No accepted-only security level follows.

### Stronger field-based bound and valid extensions

There is a tighter argument for the fixed all-N acceptance policy. Over prime q,
write the honest recipients' stored input as a K_H-by-m matrix X_j,H. A valid
extension means every column lies in `image(S_H)`, where S_H is the restriction
of S to the honest recipients. If an extension does not exist, linear algebra
supplies a row vector a with `a*S_H=0` but `a*X_j,H != 0`.

Full public VandCheck accepts exactly `image(S)`: this follows by induction on
Figure 5, assigning each branch's checked root to its latent split and requiring
all decompositions to agree. Hence acceptance implies

```text
(a*X_j,H) * transpose(R_h) + a*Y_j,h,H = 0.
```

The same one-coordinate argument bounds this event by `2^-r`. Crucially, choose
the first invalid contributor and a canonical violated constraint from the
complete stored prefix, before R_h is sampled. Every contribution must pass;
success cannot select only a favorable contributor or relation afterward.
Therefore, in this field-based ideal experiment:

```text
Pr[some X_j,H has no valid extension AND honest completion] <= 2^-r.
```

There is no contributor or reconstruction union factor in this stronger bound.
If no input is invalid, the event is empty. Conditional on each fixed prefix,
the same bound holds; averaging prefixes preserves it, including quantum-chosen
classical inputs. Across at most M attempts it gives `M*2^-r`, not a claim about
the distribution of successful attempts. This refinement depends on fixing all
payloads before the honest challenge and requiring every contributor to pass.

A linear solver can then extend each X_j,H to a full sharing. With at least T
honest recipients, its root is unique because their reconstruction already fixes
it. An analysis simulator controlling honest endpoints can read the received
classical corrupt contributions and compute this root; no extraction from a
quantum commitment is involved. This strengthens the input-validity component,
but does not prove that the extracted root has a suitable hardness distribution.

## Lemma 2: no additional contribution leakage in the delivery model

Consider one honest contributor and a fixed X=S(w). A corrupt coalition first
receives X_C and, for each h, Y_h,C=S_C(W_h). Each W_h is independently uniform.
Fix all these delivered views. The still-hidden W_h is uniform on the affine
fiber with the specified S_C(W_h); it is not an unconditional independent mask
after conditioning on its delivered portion.

For any alternative w' satisfying S_C(w')=X_C, the translation

```text
W_h -> W_h + R_h * (w - w')
```

preserves that fiber, since S_C commutes with R_h and annihilates w-w'. It is a
bijection. Thus the distribution of the entire public response tuple
`(S(R_h*w + W_h))_h`, conditioned on delivered views and challenges, is unchanged
when w is replaced by w'. The proof works for arbitrary challenge matrices chosen
from the allowed preceding view, not only random matrices. Independent masks
make the joint translation valid for all challengers simultaneously.

The challenges may depend on X_C, every Y_h,C, and earlier challenge broadcasts.
There must be no earlier public commitment or response depending on still-hidden
coordinates of the same mask. Within the phase schedule, corrupt messages and
quantum state are functions of the already delivered view and auxiliary state;
the equality of the honest response kernels therefore also preserves that state.
This is a local transcript identity, not a blanket classical-to-quantum lifting
claim or a simulator for the complete DKG output.

### Efficient local simulator over a prime field

Given X_C, independently sample each uniform W_h, and deliver S_C(W_h). Retain
these masks. Obtain the challenges in the specified order. Solve the linear
system S_C(w')=X_C, separately per scalar input coordinate, and produce
`V_h=S(R_h*w' + W_h)`. The system has a solution for an honest input; Gaussian
elimination over Z_q is polynomial-time for prime q. The extension need not be
short because it is used only under uniform masking. Honest challenge generation
and public deterministic checks are reproducible from this view.

No simulator needs the honest contributor's root or its unrevealed short shares.
For composite q, the group identity still holds, but a suitable efficient module
solver or a structure-specific extension algorithm needs to be supplied. The
scalar two-of-three model supplies explicit extensions even for q=9; it does not
implement that general solver.

This lemma deliberately allows the already delivered short X_C to leak. It does
not assert perfect privacy of the short root. Global input rejection or other
public failure indicators must be included in the target experiment or bounded
separately. See [DKG-DISTRIBUTION.md](DKG-DISTRIBUTION.md).

## Fresh masks, challenge entropy, and cost

Never answer two distinct challenges with the same mask: the difference of
responses is `(R_1-R_2)*X`, exposing extra relations. A fresh R is not a sufficient
restart policy. This candidate allocates N independent mask sharings before the
ready barrier and answers once per block. Long-term shares must also be renewed
on a new DKG attempt; stale private material must not be logged or publicly opened
to prove a complaint.

The lemma samples every honest matrix entry independently. Publishing an expanded
short seed changes that assumption; it needs a quantum-secure pseudorandomness or
oracle argument and explicit expansion loss. Do not transfer the ideal `2^-r`
bound to arbitrary seed expansion. Raw ternary matrices can be packed at two bits
per entry using the existing probability mapping; there is no joint coin to bias
because every challenger's matrix is tested separately.

Let K be the total indexed recipient-share count for one contribution, and m its
input dimension. For the current u64 coefficient representation, payload-only
counts, including self-held values, are:

| Quantity | Current one-mask candidate | Proposed N-challenger candidate |
| ---- | ---- | ---- |
| Private coefficients per contributor | K*(m+r) | K*(m+N*r) |
| Public response coefficients per contributor | K*r | K*N*r |
| Projection scalar terms per contributor | K*r*m | K*N*r*m |
| Explicit challenge bytes for the whole committee | Hash-derived | N*ceil(r*m/4) |

Public counts measure each object once, before broadcast fanout, headers, ACKs,
matrix setup, or transport cryptography. Self-held values are not network sends.
With m=3584 and r=256, each explicit matrix is 224 KiB. N=64 matrices alone total
14 MiB. Private coefficient growth is 5.2 times at N=64; responses and projection
work grow 64 times. These are algebraic counts, not benchmarks or evidence that
such a committee passes the current implementation's layout/work limits.

Existing `MAX_PROJECTION_TERMS`, private-coefficient limits, codecs, and peak-memory
accounting would need to include the new factor. Processing responses one block
at a time can reduce working memory, but cannot reuse masks or release responses
before the all-challenge barrier. Computation/communication reductions require a
new proof or separately justified joint randomness; they are not free optimizations.

## Boundaries before a complete DKG theorem

1. Supply an ideal joint-output/leakage functionality for all contributions and
   their public verification material. The two lemmas alone do not realize it.
2. Establish hardness of the actual aggregate conditional distribution, including
   individual X_j,C, malicious choices, rejection, and session selection. Summing
   N Gaussian inputs does not yield the dealer distribution exactly.
3. For initial analysis, take A as independently sampled public setup. The existing
   transcript-derived matrix is a different experiment. Instantiating distributed
   A with MPC or proved coin generation is still required; choosing A early also
   exposes it before malicious inputs are fixed and changes the reduction.
4. Relate honest input consistency to public-key assembly, active-subset signing,
   public verification-share consistency, and output delivery. Account for any
   adversarially chosen public shares at corrupt recipients.
5. Prove the actual service instantiation and phase/state semantics, then compose
   with a signing theorem in the intended classical/quantum model. Erasure in a
   single process does not imply adaptive-corruption or rollback security.

An ideal-channel consistency lemma and an exact local privacy simulator are
useful progress. They are insufficient to label the resulting DKG secure.
