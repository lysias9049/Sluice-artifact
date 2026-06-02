//! Streaming R1CS evaluation
//!
//! Implements the streaming sparse matrix-vector product from §5.2 of the paper.
//! The computation has three phases:
//!
//! 1. **Multiply** – stream through (column-sorted) matrix and witness simultaneously;
//!    emit `(constraint_idx, aᵢ · M_{q,i})` pairs  (1 pass, O(1) RAM).
//! 2. **Sort** – LSD radix sort on the `constraint_idx` key using ⌈log d⌉ bit-passes
//!    (O(S log N) I/O, O(log N) RAM).
//! 3. **Reduce** – scan the sorted stream, accumulate partial sums per constraint
//!    (1 pass, O(1) RAM).
//!
//! All three phases together: O(log N) RAM, O(S log N) I/O.
//!
//! The in-memory helpers (`multiply`, `radix_sort`, `reduce`, `streaming_matvec`)
//! are kept for the standard prover.  The file-backed version
//! [`streaming_matvec_to_file`] is used by the streaming prover to avoid
//! materialising any O(N) vector in RAM.

use std::io::{self, Read, Write};

use crate::file_vec::{FileVec, FileVecReader, FileVecWriter, StreamElem};
use crate::types::R1csMatrix;
use ark_ff::Field;

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1 – Multiply
// ─────────────────────────────────────────────────────────────────────────────

/// Multiply: produce `(constraint_idx, value)` pairs.
///
/// `matrix` must be sorted by `wire_idx` (column index).
/// `witness[i]` = aᵢ.
fn multiply<F: Field + Copy>(matrix: &R1csMatrix<F>, witness: &[F]) -> Vec<(usize, F)> {
    matrix
        .iter()
        .map(|&(row, col, val)| (row, witness[col] * val))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 – LSD Radix sort
// ─────────────────────────────────────────────────────────────────────────────

/// Stable binary partition into (bit=0) | (bit=1) using bit `b` of the key.
/// This is one pass of the LSD radix sort.
fn radix_pass<V: Copy>(data: Vec<(usize, V)>, key_bit: u32) -> Vec<(usize, V)> {
    let mask = 1usize << key_bit;
    let mut zeros: Vec<(usize, V)> = Vec::new();
    let mut ones: Vec<(usize, V)> = Vec::new();
    for item in data {
        if item.0 & mask == 0 {
            zeros.push(item);
        } else {
            ones.push(item);
        }
    }
    zeros.extend(ones);
    zeros
}

/// Sort `(key, value)` pairs by `key` using LSD radix sort with `key_bits` passes.
/// Stable sort → correct result.  I/O: O(S · key_bits), RAM: O(S) per pass.
fn radix_sort<V: Copy>(mut data: Vec<(usize, V)>, key_bits: u32) -> Vec<(usize, V)> {
    for b in 0..key_bits {
        data = radix_pass(data, b);
    }
    data
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 – Reduce
// ─────────────────────────────────────────────────────────────────────────────

/// Reduce: sum all values sharing the same `constraint_idx` → output vector.
///
/// Input must be sorted by `constraint_idx`.
/// `n_constraints`: number of constraints (= domain size after padding).
fn reduce<F: Field>(sorted: Vec<(usize, F)>, n_constraints: usize) -> Vec<F> {
    let mut out = vec![F::ZERO; n_constraints];
    for (row, val) in sorted {
        out[row] += val;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Streaming sparse matrix-vector product: compute M · a for one R1CS matrix.
///
/// - `matrix`: nonzero entries `(constraint_idx, wire_idx, value)` sorted by `wire_idx`.
/// - `witness`: full assignment vector `a = [a_0, a_1, …, a_m]`.
/// - `n_constraints`: number of constraints (rows), used to size the output.
///
/// Returns a vector of length `n_constraints` containing `(M · a)[q]` for each q.
pub fn streaming_matvec<F: Field + Copy>(
    matrix: &R1csMatrix<F>,
    witness: &[F],
    n_constraints: usize,
) -> Vec<F> {
    let key_bits = usize::BITS - n_constraints.leading_zeros();

    let pairs = multiply(matrix, witness);
    let sorted = radix_sort(pairs, key_bits);
    reduce(sorted, n_constraints)
}

// ─────────────────────────────────────────────────────────────────────────────
// Disk-backed streaming matvec (O(BUF_CAPACITY) peak RAM)
// ─────────────────────────────────────────────────────────────────────────────

/// Serialisable `(row_index, field_value)` pair stored in a `FileVec`.
///
/// `row` is stored as a little-endian `u64` so the LSD radix sort can
/// inspect individual bits with a simple mask.
#[derive(Clone, Copy)]
struct IndexedScalar<F: StreamElem + Copy> {
    row: u64,
    val: F,
}

impl<F: StreamElem + Copy> StreamElem for IndexedScalar<F> {
    // u64 (8 bytes) + F::BYTE_LEN
    const BYTE_LEN: usize = 8 + F::BYTE_LEN;

    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.row.to_le_bytes())?;
        self.val.write_to(w)
    }

    fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf)?;
        let row = u64::from_le_bytes(buf);
        let val = F::read_from(r)?;
        Ok(IndexedScalar { row, val })
    }
}

/// Phase 1 (disk): stream matrix entries, write (row, witness[col]*val) to disk.
///
/// `witness_fv` must have length ≥ max(col) + 1 and the matrix must be sorted
/// by `col` (wire index) in non-decreasing order.  Both streams are read
/// sequentially in lockstep — O(BUF_CAPACITY) RAM, no random access.
fn file_multiply<F: Field + Copy + StreamElem>(
    matrix: &R1csMatrix<F>,
    witness_fv: &FileVec<F>,
) -> io::Result<FileVec<IndexedScalar<F>>> {
    let mut out = FileVecWriter::new()?;
    let mut wits = FileVecReader::open(witness_fv)?;
    let mut cur_col = 0usize;
    // Load the first witness value; default to zero if witness is empty.
    let mut cur_wit = wits.next()?.unwrap_or(F::ZERO);

    for &(row, col, val) in matrix {
        // Matrix is column-sorted: col is non-decreasing.
        // Advance the witness reader until we reach this column.
        while cur_col < col {
            cur_wit = wits.next()?.unwrap_or(F::ZERO);
            cur_col += 1;
        }
        out.write(&IndexedScalar {
            row: row as u64,
            val: cur_wit * val,
        })?;
    }
    out.finish()
}

/// One LSD radix-sort pass on bit `bit` of the row key.
///
/// Partitions input into bit=0 and bit=1 halves (each in its own temp file),
/// then concatenates them — stable, O(S) I/O, O(BUF_CAPACITY) RAM.
fn file_radix_pass<F: StreamElem + Copy>(
    input: FileVec<IndexedScalar<F>>,
    bit: u32,
) -> io::Result<FileVec<IndexedScalar<F>>> {
    let mask = 1u64 << bit;
    let mut w0 = FileVecWriter::new()?;
    let mut w1 = FileVecWriter::new()?;

    {
        let mut r = FileVecReader::open(&input)?;
        while let Some(p) = r.next()? {
            if p.row & mask == 0 {
                w0.write(&p)?;
            } else {
                w1.write(&p)?;
            }
        }
        // r dropped here — file handle released before input is deleted
    }
    drop(input);

    let fv0 = w0.finish()?;
    let fv1 = w1.finish()?;

    // Concatenate: all zeros-bucket, then ones-bucket
    let mut out = FileVecWriter::new()?;
    {
        let mut r0 = FileVecReader::open(&fv0)?;
        while let Some(p) = r0.next()? {
            out.write(&p)?;
        }
    }
    {
        let mut r1 = FileVecReader::open(&fv1)?;
        while let Some(p) = r1.next()? {
            out.write(&p)?;
        }
    }
    out.finish()
}

/// Phase 2 (disk): LSD radix sort on `key_bits` bits.
/// RAM: O(BUF_CAPACITY). I/O: O(S · key_bits).
fn file_radix_sort<F: StreamElem + Copy>(
    mut data: FileVec<IndexedScalar<F>>,
    key_bits: u32,
) -> io::Result<FileVec<IndexedScalar<F>>> {
    for b in 0..key_bits {
        data = file_radix_pass(data, b)?;
    }
    Ok(data)
}

/// Phase 3 (disk): scan sorted stream, accumulate per-row sums, pad to `n`,
/// and write directly into a `FileVec<F>`.  No O(N) output Vec in RAM.
fn file_reduce<F: Field + Copy + StreamElem>(
    sorted: FileVec<IndexedScalar<F>>,
    n_constraints: usize,
    n: usize,
) -> io::Result<FileVec<F>> {
    let mut writer = FileVecWriter::<F>::new()?;
    let mut reader = FileVecReader::open(&sorted)?;
    // One-element lookahead buffer — avoids re-reading from disk.
    let mut peeked: Option<IndexedScalar<F>> = reader.next()?;

    for row in 0..n_constraints {
        let mut acc = F::ZERO;
        loop {
            let matches = peeked.as_ref().map_or(false, |p| p.row as usize == row);
            if !matches {
                break;
            }
            let p = peeked.take().unwrap(); // F is Copy; no heap movement
            acc += p.val;
            peeked = reader.next()?;
        }
        writer.write(&acc)?;
    }

    // Drop reader before sorted so the backing file can be deleted (Windows).
    drop(reader);
    drop(sorted);

    // Zero-pad from n_constraints to n
    for _ in n_constraints..n {
        writer.write(&F::ZERO)?;
    }
    writer.finish()
}

/// File-backed streaming sparse matrix-vector product.
///
/// Identical result to [`streaming_matvec`] but writes output directly into a
/// `FileVec<F>` (zero-padded to length `n`) without ever holding an O(N) vector
/// in RAM.  All three internal phases (multiply → sort → reduce) keep only
/// O(BUF_CAPACITY) bytes in RAM at any time.
///
/// `witness_fv` must be a `FileVec<F>` of length `n_vars`, sorted so that
/// `witness_fv[i]` = aᵢ.  The matrix must be sorted by wire index (column).
/// Both are read sequentially; no random access and no O(N) RAM allocation.
pub fn streaming_matvec_to_file<F: Field + Copy + StreamElem>(
    matrix: &R1csMatrix<F>,
    witness_fv: &FileVec<F>,
    n_constraints: usize,
    n: usize,
) -> io::Result<FileVec<F>> {
    let key_bits = (usize::BITS - n_constraints.leading_zeros()).max(1);
    let pairs = file_multiply(matrix, witness_fv)?;
    let sorted = file_radix_sort(pairs, key_bits)?;
    file_reduce(sorted, n_constraints, n)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fully disk-backed streaming matvec (matrix on disk, witness on disk)
// ─────────────────────────────────────────────────────────────────────────────

use crate::file_vec::MatrixEntry;

/// Phase 1 (disk→disk, fully streaming): col-sorted matrix entries from
/// FileVec; witness from FileVec.  Both read sequentially in lockstep.
/// O(BUF_CAPACITY) working RAM, zero heap allocation proportional to N.
fn file_multiply_fv<F: Field + Copy + StreamElem>(
    matrix_fv: &FileVec<MatrixEntry<F>>,
    witness_fv: &FileVec<F>,
) -> io::Result<FileVec<IndexedScalar<F>>> {
    let mut out = FileVecWriter::new()?;
    let mut wits = FileVecReader::open(witness_fv)?;
    let mut mat_r = FileVecReader::open(matrix_fv)?;
    let mut cur_col = 0u32;
    let mut cur_wit = wits.next()?.unwrap_or(F::ZERO);

    while let Some(entry) = mat_r.next()? {
        // Matrix is col-sorted; advance the witness stream to match.
        while cur_col < entry.col {
            cur_wit = wits.next()?.unwrap_or(F::ZERO);
            cur_col += 1;
        }
        out.write(&IndexedScalar {
            row: entry.row as u64,
            val: cur_wit * entry.val,
        })?;
    }
    out.finish()
}

/// Fully disk-backed streaming sparse matrix-vector product.
///
/// Both `matrix_fv` (col-sorted `MatrixEntry` stream) and `witness_fv` live
/// on disk.  Output is written to a new `FileVec<F>` (zero-padded to `n`).
/// Working RAM: O(BUF_CAPACITY).  No O(N) allocation at any point.
pub fn streaming_matvec_fv_to_file<F: Field + Copy + StreamElem>(
    matrix_fv: &FileVec<MatrixEntry<F>>,
    witness_fv: &FileVec<F>,
    n_constraints: usize,
    n: usize,
) -> io::Result<FileVec<F>> {
    let key_bits = (usize::BITS - n_constraints.leading_zeros()).max(1);
    let pairs = file_multiply_fv(matrix_fv, witness_fv)?;
    let sorted = file_radix_sort(pairs, key_bits)?;
    file_reduce(sorted, n_constraints, n)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::Zero;

    /// Dense matrix-vector product (reference).
    fn dense_matvec(mat: &[Vec<Fr>], v: &[Fr]) -> Vec<Fr> {
        mat.iter()
            .map(|row| row.iter().zip(v).map(|(a, b)| *a * *b).sum())
            .collect()
    }

    /// Convert a dense 2-D matrix to column-sorted sparse form.
    fn to_sparse(mat: &[Vec<Fr>]) -> R1csMatrix<Fr> {
        let mut entries = Vec::new();
        for (row, r) in mat.iter().enumerate() {
            for (col, &v) in r.iter().enumerate() {
                if !v.is_zero() {
                    entries.push((row, col, v));
                }
            }
        }
        // sort by column (wire index) for streaming multiply
        entries.sort_by_key(|&(_, col, _)| col);
        entries
    }

    #[test]
    fn test_matvec_small() {
        // 4×4 sparse matrix, 4-element witness
        let mat = vec![
            vec![
                Fr::from(1u64),
                Fr::from(0u64),
                Fr::from(2u64),
                Fr::from(0u64),
            ],
            vec![
                Fr::from(0u64),
                Fr::from(3u64),
                Fr::from(0u64),
                Fr::from(1u64),
            ],
            vec![
                Fr::from(1u64),
                Fr::from(1u64),
                Fr::from(1u64),
                Fr::from(1u64),
            ],
            vec![
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(5u64),
            ],
        ];
        let witness = vec![
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        ];

        let expected = dense_matvec(&mat, &witness);
        let sparse = to_sparse(&mat);
        let got = streaming_matvec(&sparse, &witness, 4);

        assert_eq!(got, expected);
    }

    #[test]
    fn test_matvec_random() {
        use ark_std::{test_rng, UniformRand};
        let mut rng = test_rng();
        let n = 16usize;
        let m = 12usize;

        // Random sparse matrix with ~25% fill
        let mut mat = vec![vec![Fr::zero(); m]; n];
        let mut entries: R1csMatrix<Fr> = Vec::new();
        for row in 0..n {
            for col in 0..m {
                if u32::rand(&mut rng) % 4 == 0 {
                    let v = Fr::rand(&mut rng);
                    mat[row][col] = v;
                    entries.push((row, col, v));
                }
            }
        }
        entries.sort_by_key(|&(_, col, _)| col);

        let witness: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut rng)).collect();
        let expected = dense_matvec(&mat, &witness);
        let got = streaming_matvec(&entries, &witness, n);
        assert_eq!(got, expected);
    }

    /// Verify that `streaming_matvec_to_file` produces the same result as
    /// `streaming_matvec` (plus zero-padding) for a small random instance.
    #[test]
    fn test_file_matvec_matches_vec() {
        use ark_std::{test_rng, UniformRand};
        let mut rng = test_rng();
        let n_constraints = 8usize;
        let n_pad = 16usize; // next power of two
        let m = 6usize;

        let mut mat = vec![vec![Fr::zero(); m]; n_constraints];
        let mut entries: R1csMatrix<Fr> = Vec::new();
        for row in 0..n_constraints {
            for col in 0..m {
                if u32::rand(&mut rng) % 3 == 0 {
                    let v = Fr::rand(&mut rng);
                    mat[row][col] = v;
                    entries.push((row, col, v));
                }
            }
        }
        entries.sort_by_key(|&(_, col, _)| col);

        let witness: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut rng)).collect();

        // Reference: in-memory version padded to n_pad
        let mut expected = streaming_matvec(&entries, &witness, n_constraints);
        expected.resize(n_pad, Fr::zero());

        // File-backed version: witness on disk, no O(N) RAM
        let witness_fv = FileVec::from_vec(&witness).unwrap();
        let got_fv = streaming_matvec_to_file(&entries, &witness_fv, n_constraints, n_pad).unwrap();
        let got = got_fv.into_vec().unwrap();

        assert_eq!(got, expected, "file matvec mismatch");
    }
}
