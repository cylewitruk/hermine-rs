# Specification decisions and open questions

Baseline: [ePrint 2026/419](https://eprint.iacr.org/2026/419), 2026-08-20 revision.
Page references are the paper's printed page numbers.

| Topic | Evidence | Implementation consequence |
| ---- | ---- | ---- |
| DKG | Section 1.2, p. 6, assumes a trusted dealer and leaves DKG analysis for future work. | Implement Keygen as specified; do not claim dealerless DKG. |
| PartialVerify predicate | Figure 7, p. 27, returns norm greater than the bound; Section 3.1 and Theorem 6.3 require true for valid shares. | Validity must use norm less than or equal to the bound. Test both sides of the boundary. |
| Refresh reconstruction indices | Figure 6 recovers indices for `[T]` but sums over `[N]`. | Sum only the selected T parties. Other indices do not exist. |
| RefreshVerifyInd indices | Figure 6 references `sk_i` although it is not an input. | Use the validated expected share layout; require exact index-set agreement. |
| Binding repetitions | Table 2 and Section 5.1 require `(2n)^(rep-1) >= 2^kappa` with beta_1 = 1; Section 7 omits the minus one. | Use the stronger requirement. For n=512, rep is 14/21/27 for kappa=128/192/256, pending upstream confirmation. |
| Rounding modulus | Section 2.2 Remark 2.5 mentions floor, but Lemma 2.7 and Table 2 define nearest-integer q_nu. | Keep integer rounding separate from commitment reduction; track the discrepancy. |
| Gaussian widths | Definition 2.2 specifies the distribution using sigma; Table 3 instead lists u_s and u_r without defining their relationship to sigma. | Do not silently treat these as validated standard deviations or interval widths. |
| Exact q | Table 3 gives only ceil(log2(q)), not the actual 30-bit/48-bit modulus. | Any selected prime is an explicit implementation choice until confirmed. |
| Norm bounds | Section 6.1 uses unconditional bounds; Section 7 uses a heuristic rounding-error bound and unspecified o(1). The final bound also differs in placement of the factor 3 multiplying q_perp. | Derive and test explicit conservative bounds before selecting a security profile. |
| Committee range | Section 7, p. 44, restricts N<=16 and T<=8; the abstract and benchmarks discuss up to 64. Theorem 6.4 states T<N. | Distinguish algorithmic support from the paper's stated concrete security scope. |
| Encoding and hashing | The paper models H_c and H_beta as random oracles; it does not specify a canonical byte encoding or complete hash instantiation. | Define a versioned local encoding and transcript; do not claim official wire compatibility. |
| Share counts | Appendix A says fewer than 4500 shares per party. Figure 5's unoptimized recurrence gives 4590 for (N,T)=(64,32), confirmed by an independent count recurrence and implementation. | Test the exact Figure 5 count; do not impose 4500 as an allocation limit. Optional Appendix B variants may change counts. |

These notes describe observed discrepancies and provisional interpretations, not
author-confirmed errata. Neither self-consistency tests nor benchmark results
resolve cryptographic parameter questions.
