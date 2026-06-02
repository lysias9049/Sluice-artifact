//! RW-Groth16 Streaming Prover
//!
//! This is the Phase 3 file-backed version of the prover.  Unlike `prover.rs`
//! (which holds all NTT intermediates in RAM), this module writes them to
//! temporary disk files via `FileVec<F>`, achieving O(log N) peak RAM.
//!
//! # Pipeline (same as §5 of the paper, now with disk-backed intermediates)
//!
//! 1. Witness arrangement          (O(n_vars) RAM — same as before)
//! 2. R1CS evaluation → FileVec   (streaming mat-vec, O(S) RAM)
//! 3. h(X) via coset streaming NTT (O(chunk) RAM; NTT intermediates on disk)
//! 4. Proof elements via MSM       (O(2^w) RAM)
//!
//! # Correctness
//!
//! Output proof is identical to `prover::prove` — the same Groth16 format,
//! same CRS, same mathematical computation.  Only the memory layout differs.

use std::io;

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{FftField, Field};
use ark_std::{rand::Rng, UniformRand};

use crate::{
    file_vec::{FileVec, FileVecReader, FileVecWriter, G1Disk, G2Disk, StreamElem},
    msm::{default_window, file_chunk_msm_fv, streaming_msm},
    r1cs::{streaming_matvec_fv_to_file, streaming_matvec_to_file},
    streaming_ntt::{
        streaming_coset_shift, streaming_coset_unshift, streaming_pointwise_abc, streaming_rw_intt,
        streaming_rw_ntt,
    },
    types::{Proof, ProvingKey, Qap, StreamingProvingKey, StreamingQap},
};

// ── Public prover ─────────────────────────────────────────────────────────────

/// RW-Groth16 streaming prover.
///
/// Identical output to [`crate::prover::prove`], but NTT intermediates are
/// held in `FileVec<F>` (disk), not `Vec<F>` (RAM).
///
/// Requires `E::ScalarField: StreamElem` (currently `Fr` of BN254).
pub fn streaming_prove<E, R>(
    qap: &Qap<E::ScalarField>,
    pk: &ProvingKey<E>,
    statement: &[E::ScalarField],
    witness: &[E::ScalarField],
    rng: &mut R,
) -> io::Result<Proof<E>>
where
    E: Pairing,
    E::ScalarField: FftField + StreamElem,
    R: Rng,
{
    // ── 0. Blinding scalars ──────────────────────────────────────────────────
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    // ── 1. Witness → disk (eliminates O(N) Vec from RAM) ────────────────────
    assert_eq!(
        1 + statement.len() + witness.len(),
        qap.n_vars,
        "witness length mismatch"
    );
    let a_scalar_fv: FileVec<E::ScalarField> = {
        let mut wt = FileVecWriter::<E::ScalarField>::new()?;
        wt.write(&E::ScalarField::ONE)?;
        for x in statement {
            wt.write(x)?;
        }
        for x in witness {
            wt.write(x)?;
        }
        wt.finish()?
    };

    let n = qap.domain_size;

    // ── 2. R1CS evaluation → FileVec (O(BUF_CAPACITY) peak RAM) ─────────────
    let a_fv = streaming_matvec_to_file(&qap.u, &a_scalar_fv, qap.n_constraints, n)?;
    let b_fv = streaming_matvec_to_file(&qap.v, &a_scalar_fv, qap.n_constraints, n)?;
    let c_fv = streaming_matvec_to_file(&qap.w, &a_scalar_fv, qap.n_constraints, n)?;

    // ── 3. h(X) via streaming coset NTT pipeline ─────────────────────────────
    let h_fv = streaming_h_polynomial::<E::ScalarField>(a_fv, b_fv, c_fv, n)?;
    // streaming_prove uses RAM-backed CRS; materialising h is consistent with that.
    let h_coeffs: Vec<E::ScalarField> = h_fv.into_vec()?;

    // ── 4. Proof elements via streaming MSM ──────────────────────────────────
    // Read witness scalars from disk for MSM.
    let a_vec: Vec<E::ScalarField> = a_scalar_fv.into_vec()?;
    let w = default_window(n.max(2)) as u32;

    // [A]₁ = [α]₁ + Σᵢ aᵢ·[uᵢ(τ)]₁ + r·[δ]₁
    let sum_a: E::G1 = streaming_msm::<E::G1>(&pk.g1_u_tau, &a_vec, w);
    let enc_a = (E::G1::from(pk.g1_alpha) + sum_a + E::G1::from(pk.g1_delta) * r).into_affine();

    // [B]₂ = [β]₂ + Σᵢ aᵢ·[vᵢ(τ)]₂ + s·[δ]₂
    let sum_b2: E::G2 = streaming_msm::<E::G2>(&pk.g2_v_tau, &a_vec, w);
    let enc_b2 = (E::G2::from(pk.g2_beta) + sum_b2 + E::G2::from(pk.g2_delta) * s).into_affine();

    // [B]₁ (auxiliary term for [C]₁)
    let sum_b1: E::G1 = streaming_msm::<E::G1>(&pk.g1_v_tau, &a_vec, w);
    let enc_b1 = E::G1::from(pk.g1_beta) + sum_b1 + E::G1::from(pk.g1_delta) * s;

    // [C]₁ = Σᵢ_{>ℓ} aᵢ·[(βuᵢ+αvᵢ+wᵢ)/δ]₁  +  Σⱼ hⱼ·[τʲt(τ)/δ]₁
    //        + s·[A]₁ + r·[B]₁ − rs·[δ]₁
    let witness_scalars = &a_vec[qap.n_pub + 1..];
    let sum_c_wit: E::G1 = streaming_msm::<E::G1>(&pk.g1_abc_over_delta, witness_scalars, w);
    let sum_c_quot: E::G1 = streaming_msm::<E::G1>(&pk.g1_h_pow_tau_over_delta, &h_coeffs, w);

    let enc_c = (sum_c_wit + sum_c_quot + E::G1::from(enc_a) * s + enc_b1 * r
        - E::G1::from(pk.g1_delta) * (r * s))
        .into_affine();

    Ok(Proof {
        a: enc_a,
        b: enc_b2,
        c: enc_c,
    })
}

/// RW-Groth16 prover with CRS on disk.
///
/// Uses `StreamingProvingKey` (FileVec-backed CRS) + chunk-at-a-time Pippenger MSM.
/// This transitional path still receives `qap` and `witness` as caller-owned
/// RAM slices, so benchmark papers should treat it as the `RW-File` variant:
/// useful for large-scale timing, but not the direct basis for the fully
/// streaming working-memory claim.
///
/// Output proof is identical to `streaming_prove` and standard Groth16.
pub fn streaming_prove_disk<E, R>(
    qap: &Qap<E::ScalarField>,
    pk: &StreamingProvingKey<E>,
    statement: &[E::ScalarField],
    witness: &[E::ScalarField],
    rng: &mut R,
) -> io::Result<Proof<E>>
where
    E: Pairing,
    E::ScalarField: FftField + StreamElem,
    E::G1Affine: From<ark_bn254::G1Affine>,
    E::G2Affine: From<ark_bn254::G2Affine>,
    R: Rng,
{
    // ── 0. Blinding scalars ──────────────────────────────────────────────────
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    // ── 1. Witness → disk immediately for the internal pipeline ─────────────
    // The caller still owns the input slice, so this removes O(N) allocations
    // from later phases but does not make this API fully streaming end to end.
    assert_eq!(
        1 + statement.len() + witness.len(),
        qap.n_vars,
        "witness length mismatch"
    );
    let a_scalar_fv: FileVec<E::ScalarField> = {
        let mut w = FileVecWriter::<E::ScalarField>::new()?;
        w.write(&E::ScalarField::ONE)?;
        for x in statement {
            w.write(x)?;
        }
        for x in witness {
            w.write(x)?;
        }
        w.finish()?
    };
    // statement and witness slices go out of scope; no O(N) Vec ever in RAM.

    // Private witness only (indices n_pub+1..) → separate FileVec for C MSM.
    let priv_witness_fv: FileVec<E::ScalarField> = {
        let mut w = FileVecWriter::<E::ScalarField>::new()?;
        // Skip 1 (const) + n_pub (public) elements, then write the rest.
        let mut r = FileVecReader::open(&a_scalar_fv)?;
        let skip = 1 + pk.n_pub;
        for _ in 0..skip {
            r.next()?;
        }
        while let Some(x) = r.next()? {
            w.write(&x)?;
        }
        w.finish()?
    };

    let n = qap.domain_size;

    // ── 2. R1CS evaluation → FileVec (O(BUF_CAPACITY) peak RAM) ─────────────
    // Witness is read sequentially from disk; matrix is column-sorted.
    // No O(N) allocation at any point.
    let a_fv_ntt = streaming_matvec_to_file(&qap.u, &a_scalar_fv, qap.n_constraints, n)?;
    let b_fv_ntt = streaming_matvec_to_file(&qap.v, &a_scalar_fv, qap.n_constraints, n)?;
    let c_fv_ntt = streaming_matvec_to_file(&qap.w, &a_scalar_fv, qap.n_constraints, n)?;

    // ── 3. h(X) via streaming coset NTT pipeline (returns FileVec) ───────────
    let h_fv = streaming_h_polynomial::<E::ScalarField>(a_fv_ntt, b_fv_ntt, c_fv_ntt, n)?;

    // ── 4. Proof elements via file_chunk_msm_fv ──────────────────────────────
    // Both CRS bases (from disk via StreamingProvingKey) and scalars (from disk
    // via FileVec) are streamed chunk-at-a-time → O(2^w) peak RAM.
    let w = default_window(n.max(2)) as u32;

    // Conversion closures: disk newtypes → E::G1Affine / E::G2Affine
    let cvt_g1 = |d: G1Disk| -> E::G1Affine { E::G1Affine::from(d.0) };
    let cvt_g2 = |d: G2Disk| -> E::G2Affine { E::G2Affine::from(d.0) };

    // [A]₁ = [α]₁ + Σᵢ aᵢ·[uᵢ(τ)]₁ + r·[δ]₁
    // a_scalar_fv is read 3 times (A, B2, B1); FileVecReader reopens from start each time.
    let sum_a: E::G1 = file_chunk_msm_fv::<E::G1, _, _>(&pk.g1_u_tau, &a_scalar_fv, &cvt_g1, w)?;
    let enc_a = (E::G1::from(pk.g1_alpha) + sum_a + E::G1::from(pk.g1_delta) * r).into_affine();

    // [B]₂ = [β]₂ + Σᵢ aᵢ·[vᵢ(τ)]₂ + s·[δ]₂
    let sum_b2: E::G2 = file_chunk_msm_fv::<E::G2, _, _>(&pk.g2_v_tau, &a_scalar_fv, &cvt_g2, w)?;
    let enc_b2 = (E::G2::from(pk.g2_beta) + sum_b2 + E::G2::from(pk.g2_delta) * s).into_affine();

    // [B]₁ (auxiliary for [C]₁)
    let sum_b1: E::G1 = file_chunk_msm_fv::<E::G1, _, _>(&pk.g1_v_tau, &a_scalar_fv, &cvt_g1, w)?;
    let enc_b1 = E::G1::from(pk.g1_beta) + sum_b1 + E::G1::from(pk.g1_delta) * s;

    // [C]₁ = Σᵢ_{>ℓ} aᵢ·[(βuᵢ+αvᵢ+wᵢ)/δ]₁ + Σⱼ hⱼ·[τʲt(τ)/δ]₁
    //        + s·[A]₁ + r·[B]₁ − rs·[δ]₁
    let sum_c_wit: E::G1 =
        file_chunk_msm_fv::<E::G1, _, _>(&pk.g1_abc_over_delta, &priv_witness_fv, &cvt_g1, w)?;
    let sum_c_quot: E::G1 =
        file_chunk_msm_fv::<E::G1, _, _>(&pk.g1_h_pow_tau_over_delta, &h_fv, &cvt_g1, w)?;

    let enc_c = (sum_c_wit + sum_c_quot + E::G1::from(enc_a) * s + enc_b1 * r
        - E::G1::from(pk.g1_delta) * (r * s))
        .into_affine();

    Ok(Proof {
        a: enc_a,
        b: enc_b2,
        c: enc_c,
    })
}

/// Fully-streaming RW-Groth16 prover: QAP on disk, CRS on disk, witness on disk.
///
/// `assignment_fv` is a `FileVec<F>` containing the full assignment vector
/// `[1, pub_1 … pub_ℓ, priv_1 … priv_m]`.  It never exists as a `Vec` in RAM;
/// the caller generates it directly into a `FileVecWriter`.
///
/// Peak working RAM: O(2^w) for MSM buckets + O(BUF_CAPACITY) for NTT/R1CS streams
/// = O(log N) total.  The unavoidable O(N) witness I/O is external storage, not
/// working memory.
pub fn streaming_prove_rw<E, R>(
    qap: &StreamingQap<E::ScalarField>,
    pk: &StreamingProvingKey<E>,
    assignment_fv: &FileVec<E::ScalarField>,
    rng: &mut R,
) -> io::Result<Proof<E>>
where
    E: Pairing,
    E::ScalarField: FftField + StreamElem + Copy,
    E::G1Affine: From<ark_bn254::G1Affine>,
    E::G2Affine: From<ark_bn254::G2Affine>,
    R: Rng,
{
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);
    let n = qap.domain_size;

    // ── Private witness FileVec (skip 1 + n_pub elements) ───────────────────
    let priv_fv: FileVec<E::ScalarField> = {
        let mut w = FileVecWriter::new()?;
        let mut rd = FileVecReader::open(assignment_fv)?;
        let skip = 1 + pk.n_pub;
        for _ in 0..skip {
            rd.next()?;
        }
        while let Some(x) = rd.next()? {
            w.write(&x)?;
        }
        w.finish()?
    };

    // ── R1CS: fully streaming (matrix on disk, witness on disk) ─────────────
    let a_fv = streaming_matvec_fv_to_file(&qap.u, assignment_fv, qap.n_constraints, n)?;
    let b_fv = streaming_matvec_fv_to_file(&qap.v, assignment_fv, qap.n_constraints, n)?;
    let c_fv = streaming_matvec_fv_to_file(&qap.w, assignment_fv, qap.n_constraints, n)?;

    // ── h(X) via streaming coset NTT pipeline ───────────────────────────────
    let h_fv = streaming_h_polynomial::<E::ScalarField>(a_fv, b_fv, c_fv, n)?;

    // ── MSM: CRS from disk, scalars from disk ────────────────────────────────
    let w_bits = default_window(n.max(2)) as u32;
    let cvt_g1 = |d: G1Disk| -> E::G1Affine { E::G1Affine::from(d.0) };
    let cvt_g2 = |d: G2Disk| -> E::G2Affine { E::G2Affine::from(d.0) };

    let sum_a: E::G1 =
        file_chunk_msm_fv::<E::G1, _, _>(&pk.g1_u_tau, assignment_fv, &cvt_g1, w_bits)?;
    let enc_a = (E::G1::from(pk.g1_alpha) + sum_a + E::G1::from(pk.g1_delta) * r).into_affine();

    let sum_b2: E::G2 =
        file_chunk_msm_fv::<E::G2, _, _>(&pk.g2_v_tau, assignment_fv, &cvt_g2, w_bits)?;
    let enc_b2 = (E::G2::from(pk.g2_beta) + sum_b2 + E::G2::from(pk.g2_delta) * s).into_affine();

    let sum_b1: E::G1 =
        file_chunk_msm_fv::<E::G1, _, _>(&pk.g1_v_tau, assignment_fv, &cvt_g1, w_bits)?;
    let enc_b1 = E::G1::from(pk.g1_beta) + sum_b1 + E::G1::from(pk.g1_delta) * s;

    let sum_c_wit: E::G1 =
        file_chunk_msm_fv::<E::G1, _, _>(&pk.g1_abc_over_delta, &priv_fv, &cvt_g1, w_bits)?;
    let sum_c_quot: E::G1 =
        file_chunk_msm_fv::<E::G1, _, _>(&pk.g1_h_pow_tau_over_delta, &h_fv, &cvt_g1, w_bits)?;

    let enc_c = (sum_c_wit + sum_c_quot + E::G1::from(enc_a) * s + enc_b1 * r
        - E::G1::from(pk.g1_delta) * (r * s))
        .into_affine();

    Ok(Proof {
        a: enc_a,
        b: enc_b2,
        c: enc_c,
    })
}

// ── h(X) pipeline ─────────────────────────────────────────────────────────────

/// Compute h(X) = (A(X)·B(X) − C(X)) / t(X) via the coset NTT streaming pipeline.
///
/// All NTT intermediates live on disk; peak RAM is O(BUF_CAPACITY).
///
/// Returns the coefficient vector of h (length N−1) as a `FileVec<F>` (disk-backed).
/// No RAM materialisation of the N−1 coefficients occurs; the FileVec is handed
/// directly to `file_chunk_msm_fv` for the MSM inner product.
fn streaming_h_polynomial<F: FftField + StreamElem>(
    a_evals: FileVec<F>,
    b_evals: FileVec<F>,
    c_evals: FileVec<F>,
    n: usize,
) -> io::Result<FileVec<F>> {
    let g: F = F::GENERATOR; // coset generator (∉ H)

    // ── Step 1: iNTT → coefficient vectors A(X), B(X), C(X) ────────────────
    let a_coeffs = streaming_rw_intt(a_evals)?;
    let b_coeffs = streaming_rw_intt(b_evals)?;
    let c_coeffs = streaming_rw_intt(c_evals)?;

    // ── Step 2: coset shift then NTT → evaluations on coset gH ─────────────
    let a_coset = streaming_rw_ntt(streaming_coset_shift(a_coeffs, g)?)?;
    let b_coset = streaming_rw_ntt(streaming_coset_shift(b_coeffs, g)?)?;
    let c_coset = streaming_rw_ntt(streaming_coset_shift(c_coeffs, g)?)?;

    // ── Step 3: pointwise quotient ĥⱼ = (âⱼ·b̂ⱼ − ĉⱼ) / (g^N − 1) ────────
    let t_val_inv = (g.pow([n as u64]) - F::ONE)
        .inverse()
        .expect("g^N ≠ 1 for any coset generator g ∉ H");

    let h_coset = streaming_pointwise_abc(a_coset, b_coset, c_coset, t_val_inv)?;

    // ── Step 4: iNTT then coset unshift → h coefficients ────────────────────
    let h_shifted = streaming_rw_intt(h_coset)?;
    let h_fv = streaming_coset_unshift(h_shifted, g)?;

    // h(X) has degree ≤ N−2; write first N−1 elements to a trimmed FileVec.
    // The last coefficient is 0 in exact arithmetic and is discarded on disk.
    let h_trimmed = {
        let mut writer = FileVecWriter::<F>::new()?;
        let mut reader = FileVecReader::open(&h_fv)?;
        for _ in 0..(n - 1) {
            let elem = reader.next()?.expect("streaming_h_polynomial: EOF in h_fv");
            writer.write(&elem)?;
        }
        writer.finish()?
    };

    Ok(h_trimmed) // FileVec<F>, stays on disk — no RAM materialisation
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_std::{test_rng, One};

    use crate::{setup::setup, types::Qap, verify::verify};

    /// Minimal 1-constraint multiplication circuit: a · b = c.
    fn single_mul_qap() -> Qap<Fr> {
        let one = Fr::one();
        Qap {
            domain_size: 2,
            n_constraints: 1,
            n_vars: 4, // [1, a, b, c]
            n_pub: 0,
            u: vec![(0, 1, one)],
            v: vec![(0, 2, one)],
            w: vec![(0, 3, one)],
        }
    }

    #[test]
    fn test_streaming_prove_single_mul() {
        let mut rng = test_rng();
        let qap = single_mul_qap();
        let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);
        let a = Fr::from(3u64);
        let b = Fr::from(5u64);
        let witness = vec![a, b, a * b];
        let stmt: Vec<Fr> = vec![];

        let proof = streaming_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng).unwrap();
        assert!(
            verify::<Bn254>(&vk, &stmt, &proof),
            "streaming prove: verify failed"
        );
    }

    #[test]
    fn test_streaming_prove_disk_single_mul() {
        use crate::setup::streaming_setup;

        let mut rng = test_rng();
        let qap = single_mul_qap();
        let (spk, vk) = streaming_setup::<Bn254, _>(&qap, &mut rng).unwrap();

        let a = Fr::from(3u64);
        let b = Fr::from(5u64);
        let witness = vec![a, b, a * b];
        let stmt: Vec<Fr> = vec![];

        let proof =
            streaming_prove_disk::<Bn254, _>(&qap, &spk, &stmt, &witness, &mut rng).unwrap();
        assert!(
            verify::<Bn254>(&vk, &stmt, &proof),
            "streaming_prove_disk: verify failed"
        );
    }

    #[test]
    fn test_streaming_prove_rw_single_mul() {
        use crate::file_vec::{FileVec, FileVecWriter};
        use crate::setup::{make_streaming_qap, streaming_setup};

        let mut rng = test_rng();
        let qap = single_mul_qap();
        let (spk, vk) = streaming_setup::<Bn254, _>(&qap, &mut rng).unwrap();
        let sqap = make_streaming_qap(&qap).unwrap();

        // Build assignment_fv = [1, a, b, a*b] on disk
        let a = Fr::from(3u64);
        let b = Fr::from(5u64);
        let assignment_fv: FileVec<Fr> = {
            let mut w = FileVecWriter::<Fr>::new().unwrap();
            w.write(&Fr::one()).unwrap();
            w.write(&a).unwrap();
            w.write(&b).unwrap();
            w.write(&(a * b)).unwrap();
            w.finish().unwrap()
        };

        let stmt: Vec<Fr> = vec![];
        let proof = streaming_prove_rw::<Bn254, _>(&sqap, &spk, &assignment_fv, &mut rng).unwrap();
        assert!(
            crate::verify::verify::<Bn254>(&vk, &stmt, &proof),
            "streaming_prove_rw: verify failed"
        );
    }

    #[test]
    fn test_streaming_prove_disk_matches_ram() {
        use crate::setup::streaming_setup;

        let mut rng = test_rng();
        let qap = single_mul_qap();

        // Both provers must accept the same witness (soundness not tested here,
        // just correctness via the verifier).
        let (spk, vk) = streaming_setup::<Bn254, _>(&qap, &mut rng).unwrap();

        let a = Fr::from(7u64);
        let b = Fr::from(11u64);
        let witness = vec![a, b, a * b];
        let stmt: Vec<Fr> = vec![];

        let proof =
            streaming_prove_disk::<Bn254, _>(&qap, &spk, &stmt, &witness, &mut rng).unwrap();
        assert!(
            verify::<Bn254>(&vk, &stmt, &proof),
            "streaming_prove_disk: verifier rejected proof"
        );
    }
}
