//! RW-NTT: Read-Write Streaming Number-Theoretic Transform
//!
//! Implements the Split-Butterfly-Merge (SBM) algorithm from the paper.
//! Memory: O(log N) field elements.  I/O: O(N log N).  Passes: O(log N).
//!
//! API
//! ───
//! [`rw_ntt`]  – forward NTT  (evaluations over the N-th roots of unity)
//! [`rw_intt`] – inverse NTT  (back to coefficients)
//!
//! Both functions take ownership of a `Vec<F>` (the "external stream") and
//! return a new `Vec<F>`. In a production deployment these would be
//! `FileVec<F>` objects; for now we use `Vec<F>` so the streaming logic is
//! clear without page-alignment ceremony.

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

// ─────────────────────────────────────────────────────────────────────────────
// Bit-reversal permutation (O(log N) passes, O(1) RAM per pass)
// ─────────────────────────────────────────────────────────────────────────────

/// Swap bit `i` and bit `j` in every element's *position*, returning
/// the permuted stream.  Uses 2 streaming passes:
///   Pass 1 – 4-way split  (bi=0/1, bj=0/1)
///   Pass 2 – cross-merge  ((0,1)↔(1,0) swapped)
fn bit_swap<F: Clone>(data: Vec<F>, bit_i: u32, bit_j: u32) -> Vec<F> {
    let n = data.len();
    let mask_i = 1usize << bit_i;
    let mask_j = 1usize << bit_j;

    // ── Pass 1: 4-way split ──────────────────────────────────────────────────
    let mut s00: Vec<F> = Vec::new();
    let mut s01: Vec<F> = Vec::new();
    let mut s10: Vec<F> = Vec::new();
    let mut s11: Vec<F> = Vec::new();

    for (pos, elem) in data.into_iter().enumerate() {
        let bi = (pos & mask_i) != 0;
        let bj = (pos & mask_j) != 0;
        match (bi, bj) {
            (false, false) => s00.push(elem),
            (false, true) => s01.push(elem),
            (true, false) => s10.push(elem),
            (true, true) => s11.push(elem),
        }
    }

    // ── Pass 2: cross-merge ──────────────────────────────────────────────────
    // Output at position p reads from:
    //   (bi=0, bj=0) ← s00,  (bi=0, bj=1) ← s10 (cross!),
    //   (bi=1, bj=0) ← s01 (cross!),  (bi=1, bj=1) ← s11
    let mut it00 = s00.into_iter();
    let mut it01 = s01.into_iter();
    let mut it10 = s10.into_iter();
    let mut it11 = s11.into_iter();

    let mut out = Vec::with_capacity(n);
    for pos in 0..n {
        let bi = (pos & mask_i) != 0;
        let bj = (pos & mask_j) != 0;
        let elem = match (bi, bj) {
            (false, false) => it00.next().unwrap(),
            (false, true) => it10.next().unwrap(), // cross
            (true, false) => it01.next().unwrap(), // cross
            (true, true) => it11.next().unwrap(),
        };
        out.push(elem);
    }
    out
}

/// Bit-reversal permutation: output[i] = input[bit_rev(i)].
/// Decomposed into ⌊log_n/2⌋ bit-swaps → O(log N) passes total.
fn bit_reverse<F: Clone>(mut data: Vec<F>, log_n: u32) -> Vec<F> {
    for k in 0..(log_n / 2) {
        let bit_lo = k;
        let bit_hi = log_n - 1 - k;
        if bit_lo >= bit_hi {
            break;
        }
        data = bit_swap(data, bit_lo, bit_hi);
    }
    data
}

// ─────────────────────────────────────────────────────────────────────────────
// NTT butterfly stages (after bit-reversal)
// ─────────────────────────────────────────────────────────────────────────────

/// Split the data stream into two half-size streams by bit `stage`:
///   stream_a = elements at positions where bit `stage` = 0
///   stream_b = elements at positions where bit `stage` = 1
fn split_by_bit<F: Clone>(data: &[F], stage: u32) -> (Vec<F>, Vec<F>) {
    let mask = 1usize << stage;
    let mut a = Vec::with_capacity(data.len() / 2);
    let mut b = Vec::with_capacity(data.len() / 2);
    for (pos, elem) in data.iter().enumerate() {
        if (pos & mask) == 0 {
            a.push(elem.clone());
        } else {
            b.push(elem.clone());
        }
    }
    (a, b)
}

/// Apply the DIT butterfly to paired streams (stream_a, stream_b).
///
/// For each index k ∈ 0..n/2:
///   twiddle = ω^( (k & (stride-1)) * twiddle_step )
///   a'[k] = a[k] + twiddle * b[k]
///   b'[k] = a[k] − twiddle * b[k]
fn butterfly<F: FftField>(
    stream_a: Vec<F>,
    stream_b: Vec<F>,
    omega: F,   // primitive N-th root of unity
    stage: u32, // current butterfly stage (0-indexed)
    n: usize,   // total domain size N
) -> (Vec<F>, Vec<F>) {
    let stride = 1usize << stage;
    let group_size = stride * 2;
    let twiddle_step = n / group_size; // = N / (2 * stride)

    // Precompute twiddle factors for this stage: ω^0, ω^step, ω^(2·step), …
    // There are exactly `stride` distinct factors (period = stride).
    let mut twiddles = Vec::with_capacity(stride);
    let tw_base = omega.pow([twiddle_step as u64]);
    let mut tw = F::ONE;
    for _ in 0..stride {
        twiddles.push(tw);
        tw *= tw_base;
    }

    let half = stream_a.len();
    let mut out_a = Vec::with_capacity(half);
    let mut out_b = Vec::with_capacity(half);

    for (k, (a, b)) in stream_a.into_iter().zip(stream_b).enumerate() {
        let tw = twiddles[k & (stride - 1)];
        let wb = tw * b;
        out_a.push(a + wb);
        out_b.push(a - wb);
    }

    (out_a, out_b)
}

/// Merge two half-size streams back into one, restoring natural order.
/// The inverse of `split_by_bit`.
fn merge_by_bit<F>(stream_a: Vec<F>, stream_b: Vec<F>, stage: u32) -> Vec<F> {
    let n = stream_a.len() + stream_b.len();
    let mask = 1usize << stage;

    let mut it_a = stream_a.into_iter();
    let mut it_b = stream_b.into_iter();
    let mut out = Vec::with_capacity(n);

    for pos in 0..n {
        if (pos & mask) == 0 {
            out.push(it_a.next().unwrap());
        } else {
            out.push(it_b.next().unwrap());
        }
    }
    out
}

/// Run all log_n butterfly stages on bit-reversed data.
/// For each stage j:
///   • If stride ≤ DIRECT_THRESHOLD: process groups in-buffer (1 pass)
///   • Else: Split-Butterfly-Merge (3 passes)
fn ntt_stages<F: FftField>(mut data: Vec<F>, log_n: u32, omega: F) -> Vec<F> {
    let n = data.len();
    // For stages where the group fits in a small buffer we can do in-place.
    // Here we use the SBM path for all stages for simplicity and uniformity.
    for stage in 0..log_n {
        let (a, b) = split_by_bit(&data, stage);
        let (oa, ob) = butterfly(a, b, omega, stage, n);
        data = merge_by_bit(oa, ob, stage);
    }
    data
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Forward RW-NTT.
///
/// Input:  coefficient vector `[f_0, …, f_{N-1}]` (N = `data.len()` must be a power of 2).
/// Output: evaluation vector `[f(ω^0), f(ω^1), …, f(ω^{N-1})]`.
///
/// Algorithm (DIT, in-order output):
///   1. Bit-reversal permutation  (⌊log N/2⌋ bit-swaps)
///   2. log N butterfly stages    (SBM for each stage)
pub fn rw_ntt<F: FftField>(data: Vec<F>) -> Vec<F> {
    let n = data.len();
    assert!(n.is_power_of_two(), "NTT size must be a power of two");
    let log_n = n.ilog2();

    let domain =
        Radix2EvaluationDomain::<F>::new(n).expect("field does not support NTT of this size");
    let omega = domain.group_gen();

    let data = bit_reverse(data, log_n);
    ntt_stages(data, log_n, omega)
}

/// Inverse RW-NTT.
///
/// Input:  evaluation vector `[f(ω^0), …, f(ω^{N-1})]`.
/// Output: coefficient vector `[f_0, …, f_{N-1}]`.
///
/// Uses the same DIT butterfly with ω⁻¹, then divides by N.
pub fn rw_intt<F: FftField>(data: Vec<F>) -> Vec<F> {
    let n = data.len();
    assert!(n.is_power_of_two(), "NTT size must be a power of two");
    let log_n = n.ilog2();

    let domain =
        Radix2EvaluationDomain::<F>::new(n).expect("field does not support NTT of this size");
    let omega_inv = domain.group_gen_inv();
    let n_inv = domain.size_inv();

    let data = bit_reverse(data, log_n);
    let mut data = ntt_stages(data, log_n, omega_inv);

    // Divide by N
    data.iter_mut().for_each(|x| *x *= n_inv);
    data
}

// ─────────────────────────────────────────────────────────────────────────────
// Coset NTT helpers (used by the h(X) pipeline)
// ─────────────────────────────────────────────────────────────────────────────

/// Multiply coefficients by gⁱ in a single streaming pass.
/// Converts f(X) to f_g(X) = f(g·X), so NTT(f_g) gives evaluations on gH.
pub fn coset_shift<F: FftField>(mut coeffs: Vec<F>, g: F) -> Vec<F> {
    let mut gi = F::ONE;
    for c in coeffs.iter_mut() {
        *c *= gi;
        gi *= g;
    }
    coeffs
}

/// Multiply coefficients by g⁻ⁱ (inverse of `coset_shift`).
pub fn coset_unshift<F: FftField>(mut coeffs: Vec<F>, g: F) -> Vec<F> {
    let g_inv = g.inverse().expect("coset generator must be invertible");
    let mut g_inv_i = F::ONE;
    for c in coeffs.iter_mut() {
        *c *= g_inv_i;
        g_inv_i *= g_inv;
    }
    coeffs
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::{test_rng, UniformRand};

    /// Reference NTT via ark-poly evaluation.
    fn reference_ntt(coeffs: &[Fr]) -> Vec<Fr> {
        let domain = Radix2EvaluationDomain::<Fr>::new(coeffs.len()).unwrap();
        domain.fft(coeffs)
    }

    #[test]
    fn test_rw_ntt_correctness() {
        let mut rng = test_rng();
        for log_n in 1u32..=10 {
            let n = 1 << log_n;
            let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

            let got = rw_ntt(coeffs.clone());
            let want = reference_ntt(&coeffs);
            assert_eq!(got, want, "RW-NTT mismatch at N={n}");
        }
    }

    #[test]
    fn test_rw_intt_roundtrip() {
        let mut rng = test_rng();
        for log_n in 1u32..=10 {
            let n = 1 << log_n;
            let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

            let evals = rw_ntt(coeffs.clone());
            let coeffs2 = rw_intt(evals);
            assert_eq!(coeffs, coeffs2, "INTT round-trip failed at N={n}");
        }
    }

    #[test]
    fn test_bit_reverse_n8() {
        // For N=8 (3 bits), bit_rev([0,1,2,3,4,5,6,7]) = [0,4,2,6,1,5,3,7]
        let data: Vec<usize> = (0..8usize).collect();
        let result = bit_reverse(data, 3);
        assert_eq!(result, vec![0, 4, 2, 6, 1, 5, 3, 7]);
    }

    #[test]
    fn test_coset_roundtrip() {
        let mut rng = test_rng();
        let n = 16usize;
        let g = Fr::from(7u64); // arbitrary coset generator
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let shifted = coset_shift(coeffs.clone(), g);
        let unshifted = coset_unshift(shifted, g);
        assert_eq!(coeffs, unshifted);
    }
}
