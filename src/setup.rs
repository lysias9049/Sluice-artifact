//! RW-Groth16 Trusted Setup
//!
//! Generates the Common Reference String (CRS) for a given QAP instance.
//! This is a one-time operation; in a real deployment it uses a multi-party
//! computation ceremony.  Here we expose the trapdoor explicitly for testing.
//!
//! The setup samples trapdoor (τ, α, β, γ, δ) ← F* and computes:
//!
//! Proving key:
//!   G₁: [uᵢ(τ)]₁, [vᵢ(τ)]₁, [(βuᵢ+αvᵢ+wᵢ)/δ]₁ (i>ℓ), [τʲt(τ)/δ]₁, [α]₁, [β]₁, [δ]₁
//!   G₂: [vᵢ(τ)]₂, [β]₂, [δ]₂
//!
//! Verifying key:
//!   [α]₁, [β]₂, [γ]₂, [δ]₂, [(βuᵢ+αvᵢ+wᵢ)/γ]₁ (i≤ℓ)

use std::io;

use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
use ark_ff::{FftField, Field};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{rand::Rng, UniformRand};

use crate::file_vec::{FileVec, FileVecWriter, G1Disk, G2Disk, MatrixEntry, StreamElem};
use crate::types::{ProvingKey, Qap, R1csMatrix, StreamingProvingKey, StreamingQap, VerifyingKey};

/// Generate the CRS for `qap`.
///
/// Returns `(ProvingKey, VerifyingKey)`.  The trapdoor is discarded after
/// this function returns; it is never exposed to the caller.
pub fn setup<E, R>(qap: &Qap<E::ScalarField>, rng: &mut R) -> (ProvingKey<E>, VerifyingKey<E>)
where
    E: Pairing,
    E::ScalarField: FftField,
    R: Rng,
{
    // ── Sample trapdoor ──────────────────────────────────────────────────────
    let tau = E::ScalarField::rand(rng);
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);
    let delta = E::ScalarField::rand(rng);

    let delta_inv = delta.inverse().expect("delta must be nonzero");
    let gamma_inv = gamma.inverse().expect("gamma must be nonzero");

    // Generators
    let g1 = E::G1::generator();
    let g2 = E::G2::generator();

    let n = qap.domain_size;
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n)
        .expect("field does not support NTT of this size");

    // ── Evaluate wire polynomials at τ ───────────────────────────────────────
    // uᵢ(τ), vᵢ(τ), wᵢ(τ): computed by evaluating the Lagrange basis at τ.
    // Lagrange basisᵢ₍ₖ₎(τ) = product_{j≠k} (τ - ωʲ)/(ωᵏ - ωʲ)
    //
    // We compute the N Lagrange evaluations at τ in one shot:
    //   L_k(τ)  for k = 0..N-1
    // Then for each wire i, uᵢ(τ) = Σ_k U[k,i] · L_k(τ)
    let lagrange_at_tau = lagrange_evals_at_tau(&domain, tau);

    let n_vars = qap.n_vars;
    let n_pub = qap.n_pub;

    let u_tau: Vec<E::ScalarField> = wire_evals_at_tau(&qap.u, &lagrange_at_tau, n_vars);
    let v_tau: Vec<E::ScalarField> = wire_evals_at_tau(&qap.v, &lagrange_at_tau, n_vars);
    let w_tau: Vec<E::ScalarField> = wire_evals_at_tau(&qap.w, &lagrange_at_tau, n_vars);

    // ── t(τ) = τ^N − 1  (vanishing polynomial) ──────────────────────────────
    let t_tau = tau.pow([n as u64]) - E::ScalarField::ONE;

    // ── Build ABC combined: βuᵢ + αvᵢ + wᵢ for each i ──────────────────────
    let abc: Vec<E::ScalarField> = (0..n_vars)
        .map(|i| beta * u_tau[i] + alpha * v_tau[i] + w_tau[i])
        .collect();

    // ── G₁ proving key elements ──────────────────────────────────────────────
    let g1_u_tau: Vec<E::G1Affine> = u_tau.iter().map(|&x| (g1 * x).into_affine()).collect();

    let g1_v_tau: Vec<E::G1Affine> = v_tau.iter().map(|&x| (g1 * x).into_affine()).collect();

    // [(βuᵢ+αvᵢ+wᵢ)/δ]₁  for i = n_pub+1 .. n_vars-1  (private wires)
    let g1_abc_over_delta: Vec<E::G1Affine> = abc[n_pub + 1..]
        .iter()
        .map(|&x| (g1 * (x * delta_inv)).into_affine())
        .collect();

    // [τʲ·t(τ)/δ]₁  for j = 0..N-2
    // h(X) has degree ≤ N-2 so we need N-1 powers.
    let tau_t_over_delta: Vec<E::G1Affine> = {
        let factor = t_tau * delta_inv;
        let mut tau_pow = E::ScalarField::ONE;
        (0..n - 1)
            .map(|_| {
                let elem = (g1 * (factor * tau_pow)).into_affine();
                tau_pow *= tau;
                elem
            })
            .collect()
    };

    let g1_alpha = (g1 * alpha).into_affine();
    let g1_beta = (g1 * beta).into_affine();
    let g1_delta = (g1 * delta).into_affine();

    // ── G₂ proving key elements ──────────────────────────────────────────────
    let g2_v_tau: Vec<E::G2Affine> = v_tau.iter().map(|&x| (g2 * x).into_affine()).collect();

    let g2_beta = (g2 * beta).into_affine();
    let g2_delta = (g2 * delta).into_affine();

    // ── Verifying key ─────────────────────────────────────────────────────────
    let alpha_g1 = g1_alpha;
    let beta_g2 = g2_beta;
    let gamma_g2 = (g2 * gamma).into_affine();
    let delta_g2 = g2_delta;

    // [(βuᵢ+αvᵢ+wᵢ)/γ]₁  for i = 0..=n_pub  (public wires: 0 is constant)
    let gamma_abc_g1: Vec<E::G1Affine> = abc[..=n_pub]
        .iter()
        .map(|&x| (g1 * (x * gamma_inv)).into_affine())
        .collect();

    let pk = ProvingKey {
        g1_u_tau,
        g1_v_tau,
        g1_abc_over_delta,
        g1_h_pow_tau_over_delta: tau_t_over_delta,
        g1_alpha,
        g1_beta,
        g1_delta,
        g2_v_tau,
        g2_beta,
        g2_delta,
    };

    let vk = VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };

    (pk, vk)
}

/// Generate the CRS and write large arrays directly to disk (FileVec).
///
/// Returns `(StreamingProvingKey, VerifyingKey)`.
/// The proving key's G₁/G₂ arrays are stored as temp files; peak RAM during
/// setup is O(N) for the field-element intermediates (u_tau, v_tau, w_tau),
/// which are freed before writing curve points.
pub fn streaming_setup<E, R>(
    qap: &Qap<E::ScalarField>,
    rng: &mut R,
) -> io::Result<(StreamingProvingKey<E>, VerifyingKey<E>)>
where
    E: Pairing,
    E::ScalarField: FftField,
    E::G1Affine: Into<ark_bn254::G1Affine>,
    E::G2Affine: Into<ark_bn254::G2Affine>,
    R: Rng,
{
    // ── Sample trapdoor (same as setup) ─────────────────────────────────────
    let tau = E::ScalarField::rand(rng);
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);
    let delta = E::ScalarField::rand(rng);

    let delta_inv = delta.inverse().expect("delta must be nonzero");
    let gamma_inv = gamma.inverse().expect("gamma must be nonzero");

    let g1 = E::G1::generator();
    let g2 = E::G2::generator();

    let n = qap.domain_size;
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n)
        .expect("field does not support NTT of this size");

    // ── Evaluate wire polynomials at τ ───────────────────────────────────────
    let lagrange_at_tau = lagrange_evals_at_tau(&domain, tau);
    let n_vars = qap.n_vars;
    let n_pub = qap.n_pub;

    let u_tau = wire_evals_at_tau(&qap.u, &lagrange_at_tau, n_vars);
    let v_tau = wire_evals_at_tau(&qap.v, &lagrange_at_tau, n_vars);
    let w_tau = wire_evals_at_tau(&qap.w, &lagrange_at_tau, n_vars);

    let t_tau = tau.pow([n as u64]) - E::ScalarField::ONE;

    // abc[i] = β·u_i(τ) + α·v_i(τ) + w_i(τ)
    let abc: Vec<E::ScalarField> = (0..n_vars)
        .map(|i| beta * u_tau[i] + alpha * v_tau[i] + w_tau[i])
        .collect();

    // ── Write G₁ streams to disk ─────────────────────────────────────────────
    // g1_u_tau
    let mut w_g1u: FileVecWriter<G1Disk> = FileVecWriter::new()?;
    for &x in &u_tau {
        w_g1u.write(&G1Disk((g1 * x).into_affine().into()))?;
    }
    let g1_u_tau: FileVec<G1Disk> = w_g1u.finish()?;

    // g1_v_tau
    let mut w_g1v: FileVecWriter<G1Disk> = FileVecWriter::new()?;
    for &x in &v_tau {
        w_g1v.write(&G1Disk((g1 * x).into_affine().into()))?;
    }
    let g1_v_tau: FileVec<G1Disk> = w_g1v.finish()?;

    // g1_abc_over_delta (private wires only: indices n_pub+1..n_vars)
    let mut w_abc: FileVecWriter<G1Disk> = FileVecWriter::new()?;
    for &x in &abc[n_pub + 1..] {
        w_abc.write(&G1Disk((g1 * (x * delta_inv)).into_affine().into()))?;
    }
    let g1_abc_over_delta: FileVec<G1Disk> = w_abc.finish()?;

    // g1_h_pow_tau_over_delta: [τʲ·t(τ)/δ]₁ for j = 0..N-2
    let mut w_h: FileVecWriter<G1Disk> = FileVecWriter::new()?;
    {
        let factor = t_tau * delta_inv;
        let mut tau_pow = E::ScalarField::ONE;
        for _ in 0..n - 1 {
            w_h.write(&G1Disk((g1 * (factor * tau_pow)).into_affine().into()))?;
            tau_pow *= tau;
        }
    }
    let g1_h_pow_tau_over_delta: FileVec<G1Disk> = w_h.finish()?;

    // ── Write G₂ streams to disk ─────────────────────────────────────────────
    let mut w_g2v: FileVecWriter<G2Disk> = FileVecWriter::new()?;
    for &x in &v_tau {
        w_g2v.write(&G2Disk((g2 * x).into_affine().into()))?;
    }
    let g2_v_tau: FileVec<G2Disk> = w_g2v.finish()?;

    // ── Small constants (RAM) ─────────────────────────────────────────────────
    let g1_alpha = (g1 * alpha).into_affine();
    let g1_beta = (g1 * beta).into_affine();
    let g1_delta = (g1 * delta).into_affine();
    let g2_beta = (g2 * beta).into_affine();
    let g2_delta = (g2 * delta).into_affine();

    // ── Verifying key ─────────────────────────────────────────────────────────
    let gamma_g2 = (g2 * gamma).into_affine();
    let gamma_abc_g1: Vec<E::G1Affine> = abc[..=n_pub]
        .iter()
        .map(|&x| (g1 * (x * gamma_inv)).into_affine())
        .collect();

    let spk = StreamingProvingKey {
        g1_u_tau,
        g1_v_tau,
        g1_abc_over_delta,
        g1_h_pow_tau_over_delta,
        g2_v_tau,
        g1_alpha,
        g1_beta,
        g1_delta,
        g2_beta,
        g2_delta,
        n_pub,
    };

    let vk = VerifyingKey {
        alpha_g1: g1_alpha,
        beta_g2: g2_beta,
        gamma_g2,
        delta_g2: g2_delta,
        gamma_abc_g1,
    };

    Ok((spk, vk))
}

/// Write all three R1CS matrices of `qap` to disk as col-sorted
/// `FileVec<MatrixEntry<F>>` streams, returning a `StreamingQap`.
///
/// After this call the caller may `drop(qap)` to free O(N) RAM.
/// Peak RAM during this call: O(max(|U|, |V|, |W|) × entry_size) ≈ O(N).
pub fn make_streaming_qap<F>(qap: &Qap<F>) -> io::Result<StreamingQap<F>>
where
    F: ark_ff::FftField + StreamElem + Copy,
{
    fn write_mat<F: StreamElem + Copy>(
        mat: &[(usize, usize, F)],
    ) -> io::Result<FileVec<MatrixEntry<F>>> {
        let mut w = FileVecWriter::new()?;
        for &(row, col, val) in mat {
            w.write(&MatrixEntry {
                row: row as u32,
                col: col as u32,
                val,
            })?;
        }
        w.finish()
    }
    Ok(StreamingQap {
        domain_size: qap.domain_size,
        n_constraints: qap.n_constraints,
        n_vars: qap.n_vars,
        n_pub: qap.n_pub,
        u: write_mat(&qap.u)?,
        v: write_mat(&qap.v)?,
        w: write_mat(&qap.w)?,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute L_k(τ) for k = 0..N-1 using the formula:
///   L_k(τ) = ω^k · (τ^N - 1) / (N · (τ - ω^k))   when τ ∉ H
///   L_k(τ) = [k == index of τ in H]                 when τ ∈ H (unlikely with random τ)
fn lagrange_evals_at_tau<F: FftField>(domain: &Radix2EvaluationDomain<F>, tau: F) -> Vec<F> {
    let n = domain.size();
    let n_inv = domain.size_inv();
    let omega = domain.group_gen();

    // t(τ) = τ^N - 1
    let t_tau = tau.pow([n as u64]) - F::ONE;

    if t_tau.is_zero() {
        // τ is an N-th root of unity — extremely unlikely for random τ
        // Fall back to indicator vector
        let mut evals = vec![F::ZERO; n];
        let mut om_k = F::ONE;
        for k in 0..n {
            if om_k == tau {
                evals[k] = F::ONE;
                break;
            }
            om_k *= omega;
        }
        return evals;
    }

    // L_k(τ) = ω^k · t(τ) · n_inv · (τ - ω^k)^{-1}
    //
    // Derivation: t(X) = ∏_j (X - ω^j), t'(X) = N·X^{N-1}.
    // t'(ω^k) = N·ω^{k(N-1)} = N·ω^{-k}  (since ω^N = 1).
    // L_k(X) = t(X) / ((X - ω^k)·t'(ω^k))
    //        = (X^N-1) / ((X-ω^k)·N·ω^{-k})
    //        = ω^k · (X^N-1) / (N·(X-ω^k))
    //
    // Sanity check: ∑_k L_k(τ) = (τ^N-1)/N · ∑_k ω^k/(τ-ω^k)
    //   and ∑_k ω^k/(τ-ω^k) = N/(τ^N-1),  so the sum equals 1 ✓
    let mut om_k = F::ONE;
    let prefix = t_tau * n_inv;
    (0..n)
        .map(|_k| {
            let denom = tau - om_k;
            let lk = om_k * prefix * denom.inverse().expect("τ ∉ H so τ - ω^k ≠ 0");
            om_k *= omega;
            lk
        })
        .collect()
}

/// Evaluate wire polynomial i at τ:  fᵢ(τ) = Σ_k M[k,i] · L_k(τ)
///
/// `matrix` is column-sorted (wire index = column).
fn wire_evals_at_tau<F: Field + Copy>(
    matrix: &R1csMatrix<F>,
    lagrange: &[F],
    n_vars: usize,
) -> Vec<F> {
    let mut evals = vec![F::ZERO; n_vars];
    for &(row, col, val) in matrix {
        evals[col] += lagrange[row] * val;
    }
    evals
}
