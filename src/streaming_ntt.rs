//! Streaming NTT: file-backed Split-Butterfly-Merge algorithm.
//!
//! This module implements the same SBM NTT as `ntt.rs`, but replaces
//! in-memory `Vec<F>` with disk-backed `FileVec<F>`.  Peak RAM is
//! O(BUF_CAPACITY) ≈ 256 KB, independent of N.
//!
//! # Algorithm (DIT, in-order output)
//!
//! 1. **Bit-reversal** — ⌊log₂N / 2⌋ file_bit_swap passes,
//!    each = 4-way split + cross-merge = 2 sequential file passes.
//! 2. **Butterfly stages** — log₂N stages, each = Split + Butterfly + Merge
//!    = 3 sequential file passes.  Twiddle factors are computed on-the-fly
//!    (flying twiddles → O(1) RAM for twiddles).
//!
//! Total I/O: O(N log N),  passes: O(log N),  peak RAM: O(chunk_size).
//!
//! # Public API
//!
//! [`streaming_rw_ntt`]  — forward NTT  (FileVec → FileVec)
//! [`streaming_rw_intt`] — inverse NTT  (FileVec → FileVec)
//! [`streaming_coset_shift`] / [`streaming_coset_unshift`]  — coset helpers
//! [`streaming_pointwise_abc`] — ĥ = (Â·B̂ − Ĉ) / t  (used by streaming prover)

use std::io;

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

use crate::file_vec::{FileVec, FileVecReader, FileVecWriter, StreamElem};

// ── Bit-reversal permutation ──────────────────────────────────────────────────

/// Streaming bit-swap: swap bits `bit_i` and `bit_j` in every element's position.
///
/// Pass 1 — 4-way split by (bi, bj).
/// Pass 2 — cross-merge ((0,1) ↔ (1,0) swapped).
fn file_bit_swap<T: StreamElem>(
    input: FileVec<T>,
    bit_i: u32,
    bit_j: u32,
) -> io::Result<FileVec<T>> {
    let n = input.len();
    let mask_i = 1usize << bit_i;
    let mask_j = 1usize << bit_j;

    // ── Pass 1: 4-way split ──────────────────────────────────────────────────
    let mut r = FileVecReader::open(&input)?;
    let mut w00 = FileVecWriter::new()?;
    let mut w01 = FileVecWriter::new()?;
    let mut w10 = FileVecWriter::new()?;
    let mut w11 = FileVecWriter::new()?;

    for p in 0..n {
        let elem = r.next()?.expect("file_bit_swap: unexpected EOF in pass 1");
        let bi = (p & mask_i) != 0;
        let bj = (p & mask_j) != 0;
        match (bi, bj) {
            (false, false) => w00.write(&elem)?,
            (false, true) => w01.write(&elem)?,
            (true, false) => w10.write(&elem)?,
            (true, true) => w11.write(&elem)?,
        }
    }
    drop(r);
    drop(input); // delete input file

    let fv00 = w00.finish()?;
    let fv01 = w01.finish()?;
    let fv10 = w10.finish()?;
    let fv11 = w11.finish()?;

    // ── Pass 2: cross-merge ──────────────────────────────────────────────────
    // output at (bi=0,bj=1) reads from s10 (cross), and vice versa.
    let mut r00 = FileVecReader::open(&fv00)?;
    let mut r01 = FileVecReader::open(&fv01)?;
    let mut r10 = FileVecReader::open(&fv10)?;
    let mut r11 = FileVecReader::open(&fv11)?;
    let mut w = FileVecWriter::new()?;

    for p in 0..n {
        let bi = (p & mask_i) != 0;
        let bj = (p & mask_j) != 0;
        let elem = match (bi, bj) {
            (false, false) => r00.next()?.expect("file_bit_swap: EOF in s00"),
            (false, true) => r10.next()?.expect("file_bit_swap: EOF in s10"), // cross
            (true, false) => r01.next()?.expect("file_bit_swap: EOF in s01"), // cross
            (true, true) => r11.next()?.expect("file_bit_swap: EOF in s11"),
        };
        w.write(&elem)?;
    }
    // fv00..fv11 dropped here → temp files deleted.
    w.finish()
}

/// Streaming bit-reversal permutation: apply ⌊log₂N / 2⌋ bit-swaps.
fn file_bit_reverse<T: StreamElem>(mut data: FileVec<T>, log_n: u32) -> io::Result<FileVec<T>> {
    for k in 0..(log_n / 2) {
        let bit_lo = k;
        let bit_hi = log_n - 1 - k;
        if bit_lo >= bit_hi {
            break;
        }
        data = file_bit_swap(data, bit_lo, bit_hi)?;
    }
    Ok(data)
}

// ── Butterfly stage (Split-Butterfly-Merge) ───────────────────────────────────

/// Split stream at stage j: elements at positions with bit j = 0 → stream_a,
/// bit j = 1 → stream_b.
fn file_split_by_bit<T: StreamElem>(
    input: FileVec<T>,
    stage: u32,
) -> io::Result<(FileVec<T>, FileVec<T>)> {
    let n = input.len();
    let mask = 1usize << stage;

    let mut r = FileVecReader::open(&input)?;
    let mut wa = FileVecWriter::new()?;
    let mut wb = FileVecWriter::new()?;

    for p in 0..n {
        let elem = r.next()?.expect("file_split_by_bit: unexpected EOF");
        if (p & mask) == 0 {
            wa.write(&elem)?;
        } else {
            wb.write(&elem)?;
        }
    }
    drop(r);
    drop(input);

    Ok((wa.finish()?, wb.finish()?))
}

/// Butterfly with flying twiddle factors (O(1) RAM for twiddles).
///
/// For each index k ∈ 0..N/2:
///   twiddle = ω^((k mod stride) · (N / (2·stride)))
///   a'[k] = a[k] + twiddle · b[k]
///   b'[k] = a[k] − twiddle · b[k]
///
/// Flying twiddle: instead of precomputing `stride` values, multiply
/// `tw` by `tw_base` each step, reset at stride boundaries. O(1) RAM. ✓
fn file_butterfly<F: FftField + StreamElem>(
    stream_a: FileVec<F>,
    stream_b: FileVec<F>,
    omega: F,
    stage: u32,
    n: usize,
) -> io::Result<(FileVec<F>, FileVec<F>)> {
    let stride = 1usize << stage;
    let twiddle_step = n / (2 * stride); // N / (2 · stride) — the step in ω-powers

    let mut ra = FileVecReader::open(&stream_a)?;
    let mut rb = FileVecReader::open(&stream_b)?;
    let mut wa = FileVecWriter::new()?;
    let mut wb = FileVecWriter::new()?;

    // tw_base = ω^twiddle_step
    let tw_base = omega.pow([twiddle_step as u64]);
    let mut tw = F::ONE;
    let mut k_in_stride = 0usize;

    let half = n / 2;
    for _ in 0..half {
        let a = ra.next()?.expect("file_butterfly: EOF in stream_a");
        let b = rb.next()?.expect("file_butterfly: EOF in stream_b");

        let t_b = tw * b;
        wa.write(&(a + t_b))?;
        wb.write(&(a - t_b))?;

        k_in_stride += 1;
        if k_in_stride == stride {
            tw = F::ONE;
            k_in_stride = 0;
        } else {
            tw *= tw_base;
        }
    }

    drop(stream_a);
    drop(stream_b);
    Ok((wa.finish()?, wb.finish()?))
}

/// Merge two half-size streams back into natural order at stage j.
/// The inverse of `file_split_by_bit`.
fn file_merge_by_bit<T: StreamElem>(
    stream_a: FileVec<T>,
    stream_b: FileVec<T>,
    stage: u32,
) -> io::Result<FileVec<T>> {
    let n = stream_a.len() + stream_b.len();
    let mask = 1usize << stage;

    let mut ra = FileVecReader::open(&stream_a)?;
    let mut rb = FileVecReader::open(&stream_b)?;
    let mut w = FileVecWriter::new()?;

    for p in 0..n {
        let elem = if (p & mask) == 0 {
            ra.next()?.expect("file_merge_by_bit: EOF in stream_a")
        } else {
            rb.next()?.expect("file_merge_by_bit: EOF in stream_b")
        };
        w.write(&elem)?;
    }

    drop(stream_a);
    drop(stream_b);
    w.finish()
}

/// Run all `log_n` butterfly stages (Split-Butterfly-Merge each).
fn file_ntt_stages<F: FftField + StreamElem>(
    mut data: FileVec<F>,
    log_n: u32,
    omega: F,
) -> io::Result<FileVec<F>> {
    let n = data.len();
    for stage in 0..log_n {
        let (stream_a, stream_b) = file_split_by_bit(data, stage)?;
        let (out_a, out_b) = file_butterfly(stream_a, stream_b, omega, stage, n)?;
        data = file_merge_by_bit(out_a, out_b, stage)?;
    }
    Ok(data)
}

// ── Pointwise scale ───────────────────────────────────────────────────────────

/// Multiply every element by `scalar` in one streaming pass.
fn streaming_scale<F: FftField + StreamElem>(
    input: FileVec<F>,
    scalar: F,
) -> io::Result<FileVec<F>> {
    let n = input.len();
    let mut r = FileVecReader::open(&input)?;
    let mut w = FileVecWriter::new()?;
    for _ in 0..n {
        let elem = r.next()?.expect("streaming_scale: unexpected EOF") * scalar;
        w.write(&elem)?;
    }
    drop(input);
    w.finish()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Forward streaming RW-NTT.
///
/// Input:  `FileVec` of N coefficient values (N must be a power of 2).
/// Output: `FileVec` of N evaluations at ω^0, ω^1, …, ω^{N-1}.
///
/// Peak RAM: O(BUF_CAPACITY).  Total I/O: O(N log N).
pub fn streaming_rw_ntt<F: FftField + StreamElem>(input: FileVec<F>) -> io::Result<FileVec<F>> {
    let n = input.len();
    assert!(n.is_power_of_two(), "NTT size must be a power of two");
    let log_n = n.ilog2();

    let domain =
        Radix2EvaluationDomain::<F>::new(n).expect("field does not support NTT of this size");
    let omega = domain.group_gen();

    let data = file_bit_reverse(input, log_n)?;
    file_ntt_stages(data, log_n, omega)
}

/// Inverse streaming RW-NTT.
///
/// Input:  `FileVec` of N evaluation values.
/// Output: `FileVec` of N coefficient values.
pub fn streaming_rw_intt<F: FftField + StreamElem>(input: FileVec<F>) -> io::Result<FileVec<F>> {
    let n = input.len();
    assert!(n.is_power_of_two(), "NTT size must be a power of two");
    let log_n = n.ilog2();

    let domain =
        Radix2EvaluationDomain::<F>::new(n).expect("field does not support NTT of this size");
    let omega_inv = domain.group_gen_inv();
    let n_inv = domain.size_inv();

    let data = file_bit_reverse(input, log_n)?;
    let data = file_ntt_stages(data, log_n, omega_inv)?;
    streaming_scale(data, n_inv)
}

/// Coset shift: multiply coefficients[i] by g^i.
/// Converts f(X) → f_g(X) = f(g·X), so NTT(f_g) gives evaluations on gH.
pub fn streaming_coset_shift<F: FftField + StreamElem>(
    input: FileVec<F>,
    g: F,
) -> io::Result<FileVec<F>> {
    let n = input.len();
    let mut r = FileVecReader::open(&input)?;
    let mut w = FileVecWriter::new()?;
    let mut gi = F::ONE;
    for _ in 0..n {
        let mut elem = r.next()?.expect("streaming_coset_shift: unexpected EOF");
        elem *= gi;
        w.write(&elem)?;
        gi *= g;
    }
    drop(input);
    w.finish()
}

/// Coset unshift: multiply coefficients[i] by g^{-i}.
/// The inverse of `streaming_coset_shift`.
pub fn streaming_coset_unshift<F: FftField + StreamElem>(
    input: FileVec<F>,
    g: F,
) -> io::Result<FileVec<F>> {
    let g_inv = g.inverse().expect("coset generator must be invertible");
    streaming_coset_shift(input, g_inv)
}

/// Pointwise quotient: ĥ_j = (â_j · b̂_j − ĉ_j) · t_inv.
///
/// Used in the h(X) pipeline to divide by the vanishing polynomial evaluation.
/// All three inputs are consumed and their temp files deleted.
pub(crate) fn streaming_pointwise_abc<F: FftField + StreamElem>(
    a_coset: FileVec<F>,
    b_coset: FileVec<F>,
    c_coset: FileVec<F>,
    t_inv: F,
) -> io::Result<FileVec<F>> {
    let n = a_coset.len();
    let mut ra = FileVecReader::open(&a_coset)?;
    let mut rb = FileVecReader::open(&b_coset)?;
    let mut rc = FileVecReader::open(&c_coset)?;
    let mut w = FileVecWriter::new()?;

    for _ in 0..n {
        let a = ra.next()?.expect("streaming_pointwise_abc: EOF in a");
        let b = rb.next()?.expect("streaming_pointwise_abc: EOF in b");
        let c = rc.next()?.expect("streaming_pointwise_abc: EOF in c");
        let h = (a * b - c) * t_inv;
        w.write(&h)?;
    }

    drop(a_coset);
    drop(b_coset);
    drop(c_coset);
    w.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::{test_rng, UniformRand};

    use crate::ntt::{coset_shift, coset_unshift, rw_intt, rw_ntt};

    /// Reference NTT via ark-poly.
    fn ark_ntt(coeffs: &[Fr]) -> Vec<Fr> {
        Radix2EvaluationDomain::<Fr>::new(coeffs.len())
            .unwrap()
            .fft(coeffs)
    }

    #[test]
    fn test_streaming_ntt_matches_ark() {
        let mut rng = test_rng();
        for log_n in 1u32..=8 {
            let n = 1 << log_n;
            let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

            let fv = FileVec::from_vec(&coeffs).unwrap();
            let out = streaming_rw_ntt(fv).unwrap().into_vec().unwrap();

            let want = ark_ntt(&coeffs);
            assert_eq!(out, want, "streaming NTT mismatch at N={n}");
        }
    }

    #[test]
    fn test_streaming_intt_roundtrip() {
        let mut rng = test_rng();
        for log_n in 1u32..=8 {
            let n = 1 << log_n;
            let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

            let fv = FileVec::from_vec(&coeffs).unwrap();
            let evals = streaming_rw_ntt(fv).unwrap();
            let back = streaming_rw_intt(evals).unwrap().into_vec().unwrap();

            assert_eq!(back, coeffs, "INTT roundtrip failed at N={n}");
        }
    }

    #[test]
    fn test_streaming_ntt_matches_vec_ntt() {
        let mut rng = test_rng();
        for log_n in 1u32..=8 {
            let n = 1 << log_n;
            let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

            // Vec-based NTT (in-memory)
            let vec_out = rw_ntt(coeffs.clone());

            // File-based NTT
            let fv = FileVec::from_vec(&coeffs).unwrap();
            let file_out = streaming_rw_ntt(fv).unwrap().into_vec().unwrap();

            assert_eq!(file_out, vec_out, "streaming vs vec NTT mismatch at N={n}");
        }
    }

    #[test]
    fn test_streaming_coset_roundtrip() {
        let mut rng = test_rng();
        let n = 16usize;
        let g = Fr::from(7u64);
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let fv = FileVec::from_vec(&coeffs).unwrap();
        let shifted = streaming_coset_shift(fv, g).unwrap();
        let unshifted = streaming_coset_unshift(shifted, g)
            .unwrap()
            .into_vec()
            .unwrap();
        assert_eq!(unshifted, coeffs, "coset shift/unshift roundtrip failed");
    }

    /// Verify that the file-based coset NTT pipeline matches the Vec-based one.
    #[test]
    fn test_streaming_coset_ntt_matches_vec() {
        let mut rng = test_rng();
        let n = 16usize;
        let g: Fr = Fr::GENERATOR;
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // Vec-based
        let vec_out = rw_ntt(coset_shift(coeffs.clone(), g));

        // File-based
        let fv = FileVec::from_vec(&coeffs).unwrap();
        let file_out = streaming_rw_ntt(streaming_coset_shift(fv, g).unwrap())
            .unwrap()
            .into_vec()
            .unwrap();

        assert_eq!(file_out, vec_out, "streaming coset NTT vs vec mismatch");
    }

    /// Verify INTT(NTT(coset_shift)) → coset_unshift roundtrip matches vec pipeline.
    #[test]
    fn test_streaming_coset_intt_roundtrip() {
        let mut rng = test_rng();
        let n = 16usize;
        let g: Fr = Fr::GENERATOR;
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // Vec pipeline
        let evals_vec = rw_ntt(coset_shift(coeffs.clone(), g));
        let coeffs_vec = coset_unshift(rw_intt(evals_vec), g);

        // File pipeline
        let fv = FileVec::from_vec(&coeffs).unwrap();
        let shifted = streaming_coset_shift(fv, g).unwrap();
        let evals_fv = streaming_rw_ntt(shifted).unwrap();
        let back_fv = streaming_coset_unshift(streaming_rw_intt(evals_fv).unwrap(), g)
            .unwrap()
            .into_vec()
            .unwrap();

        assert_eq!(
            back_fv, coeffs_vec,
            "streaming coset INTT roundtrip mismatch"
        );
    }
}
