//! Standard (non-streaming) Groth16 prover — reference baseline.
//!
//! Uses the **same CRS** (ProvingKey) as `prover::prove` but replaces every
//! streaming primitive with a simple in-memory equivalent:
//!
//! | Phase         | RW-Groth16             | Standard baseline          |
//! |---------------|------------------------|----------------------------|
//! | R1CS eval     | 3-phase streaming      | Dense accumulate (O(N) RAM)|
//! | NTT / iNTT    | SBM (O(log N) RAM)     | ark-poly in-memory FFT     |
//! | MSM           | Chunked Pippenger      | same (identical)           |
//!
//! The proof produced is mathematically identical to `prover::prove`
//! (both implement the same Groth16 equations); the difference is purely
//! in the RAM working set of the prove step.

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{FftField, Field};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{rand::Rng, UniformRand, Zero};

use crate::{
    msm::{default_window, streaming_msm},
    types::{Proof, ProvingKey, Qap},
};

/// Prove using in-memory (non-streaming) operations.
///
/// Memory usage of the prove step: O(N) field elements — dominated by the
/// six length-N vectors allocated during the FFT pipeline.
pub fn standard_prove<E, R>(
    qap: &Qap<E::ScalarField>,
    pk: &ProvingKey<E>,
    statement: &[E::ScalarField],
    witness: &[E::ScalarField],
    rng: &mut R,
) -> Proof<E>
where
    E: Pairing,
    E::ScalarField: FftField,
    R: Rng,
{
    // ── Blinding scalars ─────────────────────────────────────────────────────
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    // ── Assemble full assignment ─────────────────────────────────────────────
    let mut a: Vec<E::ScalarField> = Vec::with_capacity(qap.n_vars);
    a.push(E::ScalarField::ONE);
    a.extend_from_slice(statement);
    a.extend_from_slice(witness);
    assert_eq!(a.len(), qap.n_vars);

    let n = qap.domain_size;
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n)
        .expect("field does not support FFT of this size");

    // ── Dense R1CS evaluation — O(N) memory ──────────────────────────────────
    // Allocates three length-N vectors in RAM simultaneously.
    let mut a_hat = vec![E::ScalarField::zero(); n];
    let mut b_hat = vec![E::ScalarField::zero(); n];
    let mut c_hat = vec![E::ScalarField::zero(); n];

    for &(row, col, val) in &qap.u {
        if row < n {
            a_hat[row] += a[col] * val;
        }
    }
    for &(row, col, val) in &qap.v {
        if row < n {
            b_hat[row] += a[col] * val;
        }
    }
    for &(row, col, val) in &qap.w {
        if row < n {
            c_hat[row] += a[col] * val;
        }
    }

    // ── h(X) via ark-poly in-memory FFT — O(N) memory ────────────────────────
    // Peak: ≈ 9 × N field elements live simultaneously inside the pipeline.
    let h_coeffs = compute_h_in_memory::<E::ScalarField>(a_hat, b_hat, c_hat, n, &domain);

    // ── Proof elements (same MSM as the streaming prover) ────────────────────
    let w = default_window(n.max(2)) as u32;

    let sum_a: E::G1 = streaming_msm::<E::G1>(&pk.g1_u_tau, &a, w);
    let enc_a = (E::G1::from(pk.g1_alpha) + sum_a + E::G1::from(pk.g1_delta) * r).into_affine();

    let sum_b2: E::G2 = streaming_msm::<E::G2>(&pk.g2_v_tau, &a, w);
    let enc_b2 = (E::G2::from(pk.g2_beta) + sum_b2 + E::G2::from(pk.g2_delta) * s).into_affine();

    let sum_b1: E::G1 = streaming_msm::<E::G1>(&pk.g1_v_tau, &a, w);
    let enc_b1 = E::G1::from(pk.g1_beta) + sum_b1 + E::G1::from(pk.g1_delta) * s;

    let witness_scalars = &a[qap.n_pub + 1..];
    let sum_c_wit: E::G1 = streaming_msm::<E::G1>(&pk.g1_abc_over_delta, witness_scalars, w);
    let sum_c_quot: E::G1 = streaming_msm::<E::G1>(&pk.g1_h_pow_tau_over_delta, &h_coeffs, w);

    let enc_c = (sum_c_wit + sum_c_quot + E::G1::from(enc_a) * s + enc_b1 * r
        - E::G1::from(pk.g1_delta) * (r * s))
        .into_affine();

    Proof {
        a: enc_a,
        b: enc_b2,
        c: enc_c,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// h(X) via ark-poly in-memory FFT
// ─────────────────────────────────────────────────────────────────────────────

/// Compute h(X) = (A·B − C) / t(X) using in-memory FFT (O(N) working set).
///
/// Allocates ≈ 9 × N field elements across three iFFT + three coset-FFT passes.
fn compute_h_in_memory<F: FftField>(
    a_evals: Vec<F>,
    b_evals: Vec<F>,
    c_evals: Vec<F>,
    n: usize,
    domain: &Radix2EvaluationDomain<F>,
) -> Vec<F> {
    // iFFT: evaluations → coefficients (each allocates N elements)
    let a_coeffs = domain.ifft(&a_evals);
    let b_coeffs = domain.ifft(&b_evals);
    let c_coeffs = domain.ifft(&c_evals);

    // Coset shift + FFT on gH
    let g = F::GENERATOR;
    let coset_fft = |mut v: Vec<F>| -> Vec<F> {
        let mut gi = F::ONE;
        for c in v.iter_mut() {
            *c *= gi;
            gi *= g;
        }
        domain.fft(&v)
    };

    let a_coset = coset_fft(a_coeffs);
    let b_coset = coset_fft(b_coeffs);
    let c_coset = coset_fft(c_coeffs);

    // Pointwise quotient  ĥⱼ = (Âⱼ·B̂ⱼ − Ĉⱼ) / (g^N − 1)
    let t_inv = (g.pow([n as u64]) - F::ONE)
        .inverse()
        .expect("coset generator g^N ≠ 1");

    let h_coset: Vec<F> = a_coset
        .into_iter()
        .zip(b_coset)
        .zip(c_coset)
        .map(|((a, b), c)| (a * b - c) * t_inv)
        .collect();

    // iFFT + coset unshift
    let h_shifted = domain.ifft(&h_coset);
    let g_inv = g.inverse().unwrap();
    let mut h = h_shifted;
    let mut g_inv_i = F::ONE;
    for c in h.iter_mut() {
        *c *= g_inv_i;
        g_inv_i *= g_inv;
    }

    // h(X) has degree ≤ N−2; trim last coefficient (should be ≈ 0)
    h.truncate(n - 1);
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_std::test_rng;

    use crate::{setup::setup, types::Qap, verify::verify};

    fn mul_qap() -> Qap<Fr> {
        // Same 1-constraint circuit as the e2e test: a × b = c
        // Wire: [1, c(pub), a(priv), b(priv)]
        Qap {
            domain_size: 2,
            n_constraints: 1,
            n_vars: 4,
            n_pub: 1,
            u: vec![(0, 2, Fr::from(1u64))],
            v: vec![(0, 3, Fr::from(1u64))],
            w: vec![(0, 1, Fr::from(1u64))],
        }
    }

    #[test]
    fn test_standard_prove_verifies() {
        let mut rng = test_rng();
        let qap = mul_qap();
        let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);

        let statement = vec![Fr::from(6u64)];
        let witness = vec![Fr::from(2u64), Fr::from(3u64)];

        let proof = standard_prove::<Bn254, _>(&qap, &pk, &statement, &witness, &mut rng);
        assert!(
            verify::<Bn254>(&vk, &statement, &proof),
            "standard prove must verify"
        );
    }
}
