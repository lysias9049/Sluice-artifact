//! Streaming MSM: Chunked Pippenger
//!
//! Implements the memory-efficient multi-scalar multiplication from §4 / §5.4.
//!
//! Standard Pippenger processes all scalars in one shot with O(N) memory.
//! The *chunked* variant splits each scalar into `n_windows` windows of
//! `window_bits` bits, and processes all N (scalar, base) pairs once per
//! window using only O(2^window_bits) group elements.
//!
//! Complexity (λ = scalar bit-length):
//!   Group operations: O(λ N / window_bits)
//!   RAM:              O(2^window_bits)     ← set window_bits = O(log N) → O(N) buckets ... wait
//!
//! Paper (§5.4, Lemma 4.7): set `window_bits = ⌊log log N⌋` → O(log N) buckets,
//! O(λN/log log N) group ops.  For simplicity this implementation lets the
//! caller choose `window_bits`; the default suggested by `default_window` gives
//! roughly that trade-off.
//!
//! **Streaming property**: scalars and bases are processed one window at a
//! time by iterating over the vectors.  No more than `2^window_bits` group
//! elements are live simultaneously → O(2^window_bits) RAM.

use std::io;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::file_vec::{FileVec, FileVecReader, StreamElem};

/// Suggested window size for a given N: ⌊log₂(log₂(N))⌋ clamped to [1, 16].
pub fn default_window(n: usize) -> u32 {
    let log_n = usize::BITS - n.leading_zeros(); // ≈ log₂(N)
    let w = usize::BITS - log_n.leading_zeros(); // ≈ log₂(log₂(N))
    w.clamp(1, 16)
}

/// Chunked Pippenger MSM: compute ∑ scalars[i] · bases[i].
///
/// # Arguments
/// - `bases`:       affine group elements G₀, …, G_{n-1}
/// - `scalars`:     field scalars  s₀, …, s_{n-1}
/// - `window_bits`: window size w; at most 2^w group elements in RAM per window
///
/// # Memory
/// O(2^w) group elements + O(1) scalars at a time.
pub fn streaming_msm<G>(bases: &[G::Affine], scalars: &[G::ScalarField], window_bits: u32) -> G
where
    G: CurveGroup,
    G::ScalarField: PrimeField,
{
    assert_eq!(
        bases.len(),
        scalars.len(),
        "bases and scalars must have equal length"
    );
    if bases.is_empty() {
        return G::zero();
    }

    let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as u32;
    let n_windows = scalar_bits.div_ceil(window_bits);
    let n_buckets = 1usize << window_bits;

    // Accumulator: one partial sum per window.
    let mut window_sums: Vec<G> = vec![G::zero(); n_windows as usize];

    for (win_idx, win_sum) in window_sums.iter_mut().enumerate() {
        let shift = win_idx as u32 * window_bits;

        // ── bucket accumulation for this window ──────────────────────────────
        let mut buckets: Vec<G> = vec![G::zero(); n_buckets];

        for (scalar, base) in scalars.iter().zip(bases.iter()) {
            // Extract the window_bits-wide chunk of the scalar at position `shift`.
            let bits = extract_bits(scalar, shift, window_bits);
            if bits > 0 {
                buckets[bits as usize] += base;
            }
        }

        // ── bucket reduction (Horner / running sum) ──────────────────────────
        // ∑_{b=1}^{B-1} b · bucket[b]  =  ∑_{b=1}^{B-1} (∑_{j=b}^{B-1} bucket[j])
        let mut running = G::zero();
        let mut total = G::zero();
        for bucket in buckets.into_iter().skip(1).rev() {
            running += bucket;
            total += running;
        }

        *win_sum = total;
    }

    // ── combine windows: ∑_w window_sums[w] · 2^(w * window_bits) ──────────
    let mut result = G::zero();
    for sum in window_sums.into_iter().rev() {
        // Shift result left by window_bits positions
        for _ in 0..window_bits {
            result = result.double();
        }
        result += sum;
    }

    result
}

/// Chunk-at-a-time Pippenger MSM with bases on disk.
///
/// Reads `bases_fv` in sequential chunks of `2^window_bits` elements.
/// For each chunk, applies `streaming_msm` (Pippenger) with O(2^window_bits)
/// bucket RAM.  Total RAM: O(2^window_bits) group elements.
///
/// This implements Definition 4.1 of the paper (chunked streaming MSM).
/// Scalars are provided as a slice (still in RAM); bases come from disk.
///
/// The `convert` closure extracts a `G::Affine` from each disk element `D`.
/// This indirection is necessary because Rust's coherence rules prevent
/// implementing `StreamElem` for `G::Affine` directly (upstream blanket impl
/// conflict on `Affine<Config>`), so disk elements use newtype wrappers.
///
/// # Arguments
/// - `bases_fv`:    disk-backed elements (FileVec of disk newtype D)
/// - `scalars`:     scalar field elements (in RAM, same length as bases_fv)
/// - `convert`:     closure mapping disk element D → G::Affine
/// - `window_bits`: chunk size = 2^window_bits; bucket RAM = 2^window_bits group elements
pub fn file_chunk_msm<G, D, F>(
    bases_fv: &FileVec<D>,
    scalars: &[G::ScalarField],
    convert: F,
    window_bits: u32,
) -> io::Result<G>
where
    G: CurveGroup,
    G::ScalarField: PrimeField,
    D: StreamElem,
    F: Fn(D) -> G::Affine,
{
    let n = bases_fv.len();
    assert_eq!(
        n,
        scalars.len(),
        "file_chunk_msm: bases and scalars length mismatch"
    );

    if n == 0 {
        return Ok(G::zero());
    }

    let chunk_size = 1usize << window_bits;
    let mut reader = FileVecReader::open(bases_fv)?;
    let mut ans = G::zero();
    let mut pos = 0usize;

    while pos < n {
        let m = chunk_size.min(n - pos);

        // Read one chunk of m base points from disk → O(chunk_size × 64 B) RAM
        let mut chunk_bases: Vec<G::Affine> = Vec::with_capacity(m);
        for _ in 0..m {
            let disk_elem = reader
                .next()?
                .expect("file_chunk_msm: unexpected EOF in bases_fv");
            chunk_bases.push(convert(disk_elem));
        }

        // Pippenger on m pairs; bucket RAM = O(2^window_bits)
        let partial = streaming_msm::<G>(&chunk_bases, &scalars[pos..pos + m], window_bits);
        ans += partial;
        pos += m;
    }

    Ok(ans)
}

/// Chunk-at-a-time Pippenger MSM where BOTH bases and scalars come from disk.
///
/// Reads `bases_fv` and `scalars_fv` together in sequential chunks of `2^window_bits` elements.
/// For each chunk, applies `streaming_msm` (Pippenger) with O(2^window_bits) bucket RAM.
/// Total RAM: O(2^window_bits) group elements per iteration.
///
/// This is the fully-streaming MSM variant where neither the CRS (bases) nor
/// the witness (scalars) need to reside in RAM simultaneously.
///
/// # Arguments
/// - `bases_fv`:    disk-backed CRS elements (FileVec of disk newtype D)
/// - `scalars_fv`:  disk-backed scalar elements (FileVec<G::ScalarField>)
/// - `cvt_base`:    closure mapping disk element D → G::Affine
/// - `window_bits`: chunk size = 2^window_bits; bucket RAM = 2^window_bits group elements
pub fn file_chunk_msm_fv<G, D, Fb>(
    bases_fv: &FileVec<D>,
    scalars_fv: &FileVec<G::ScalarField>,
    cvt_base: Fb,
    window_bits: u32,
) -> io::Result<G>
where
    G: CurveGroup,
    G::ScalarField: PrimeField + StreamElem,
    D: StreamElem,
    Fb: Fn(D) -> G::Affine,
{
    let n = bases_fv.len();
    assert_eq!(
        n,
        scalars_fv.len(),
        "file_chunk_msm_fv: bases and scalars length mismatch"
    );

    if n == 0 {
        return Ok(G::zero());
    }

    let chunk_size = 1usize << window_bits;
    let mut base_reader = FileVecReader::open(bases_fv)?;
    let mut scalar_reader = FileVecReader::open(scalars_fv)?;
    let mut acc = G::zero();
    let mut i = 0usize;

    while i < n {
        let cnt = chunk_size.min(n - i);
        let mut chunk_bases: Vec<G::Affine> = Vec::with_capacity(cnt);
        let mut chunk_scalars: Vec<G::ScalarField> = Vec::with_capacity(cnt);

        for _ in 0..cnt {
            let d = base_reader
                .next()?
                .expect("file_chunk_msm_fv: EOF in bases");
            let s = scalar_reader
                .next()?
                .expect("file_chunk_msm_fv: EOF in scalars");
            chunk_bases.push(cvt_base(d));
            chunk_scalars.push(s);
        }

        let partial = streaming_msm::<G>(&chunk_bases, &chunk_scalars, window_bits);
        acc += partial;
        i += cnt;
    }

    Ok(acc)
}

/// Extract `width` bits of `scalar` starting at bit position `shift`.
fn extract_bits<F: PrimeField>(scalar: &F, shift: u32, width: u32) -> u64 {
    let bits = scalar.into_bigint();
    // `into_bigint()` gives little-endian limbs of 64 bits each.
    let limb_idx = (shift / 64) as usize;
    let bit_shift = shift % 64;

    if limb_idx >= bits.as_ref().len() {
        return 0;
    }
    let limbs = bits.as_ref();
    let lo = limbs[limb_idx] >> bit_shift;

    // May span two limbs
    let hi = if bit_shift + width > 64 && limb_idx + 1 < limbs.len() {
        limbs[limb_idx + 1] << (64 - bit_shift)
    } else {
        0
    };

    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    (lo | hi) & mask
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Affine, G1Projective};
    use ark_ec::CurveGroup;
    use ark_std::{test_rng, UniformRand, Zero};

    /// Naive MSM for comparison.
    fn naive_msm(bases: &[G1Affine], scalars: &[Fr]) -> G1Projective {
        bases.iter().zip(scalars).map(|(b, s)| *b * s).sum()
    }

    #[test]
    fn test_streaming_msm_correctness() {
        let mut rng = test_rng();
        for n in [1, 2, 4, 16, 64, 256] {
            let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let bases: Vec<G1Affine> = (0..n)
                .map(|_| G1Projective::rand(&mut rng).into_affine())
                .collect();

            let want = naive_msm(&bases, &scalars);
            let w = default_window(n.max(2));
            let got = streaming_msm::<G1Projective>(&bases, &scalars, w);

            assert_eq!(got, want, "MSM mismatch at n={n}, w={w}");
        }
    }

    #[test]
    fn test_streaming_msm_zero_scalars() {
        let n = 8;
        let mut rng = test_rng();
        let scalars = vec![Fr::from(0u64); n];
        let bases: Vec<G1Affine> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();
        let got = streaming_msm::<G1Projective>(&bases, &scalars, 4);
        assert!(got.is_zero());
    }

    #[test]
    fn test_streaming_msm_single() {
        let mut rng = test_rng();
        let s = Fr::rand(&mut rng);
        let b = G1Projective::rand(&mut rng).into_affine();
        let got = streaming_msm::<G1Projective>(&[b], &[s], 4);
        let want = G1Projective::from(b) * s;
        assert_eq!(got, want);
    }
}
