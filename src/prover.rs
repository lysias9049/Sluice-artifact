//! RW-Groth16 Prover
//!
//! Implements Definition 5.1 of the paper (the streaming Prove algorithm).
//!
//! Pipeline
//! ────────
//! 1. **Witness arrangement** – assemble [a_0=1 | φ | w]          (1 pass, O(1) RAM)
//! 2. **R1CS evaluation** – compute â, b̂, ĉ = U·a, V·a, W·a      (O(log N) RAM)
//! 3. **h(X) computation** – 7 RW-NTTs + 5 streaming passes       (O(log N) RAM)
//! 4. **Proof elements** – 5 streaming MSMs                        (O(log N) RAM)
//!
//! Output: π = ([A]₁, [B]₂, [C]₁) identical to standard Groth16.

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{FftField, Field};
use ark_std::{rand::Rng, UniformRand};

use crate::{
    msm::{default_window, streaming_msm},
    ntt::{coset_shift, coset_unshift, rw_intt, rw_ntt},
    r1cs::streaming_matvec,
    types::{Proof, ProvingKey, Qap},
};

/// RW-Groth16 prover.
///
/// # Arguments
/// - `qap`:       the QAP instance (R1CS matrices + domain)
/// - `pk`:        the proving key (CRS in streaming layout)
/// - `statement`: public inputs  φ = (a_1, …, a_ℓ)
/// - `witness`:   private inputs w = (a_{ℓ+1}, …, a_m)
/// - `rng`:       randomness source for the blinding factors r, s
///
/// # Returns
/// A Groth16 proof π = ([A]₁, [B]₂, [C]₁).
pub fn prove<E, R>(
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
    // ── 0. Blinding scalars ──────────────────────────────────────────────────
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    // ── 1. Witness arrangement ───────────────────────────────────────────────
    // Assemble full assignment:  a = [1, a_1, …, a_ℓ, a_{ℓ+1}, …, a_m]
    let mut a: Vec<E::ScalarField> = Vec::with_capacity(qap.n_vars);
    a.push(E::ScalarField::ONE);
    a.extend_from_slice(statement);
    a.extend_from_slice(witness);
    assert_eq!(a.len(), qap.n_vars);

    // ── 2. R1CS evaluation: â, b̂, ĉ ────────────────────────────────────────
    // These are the evaluations of A(X), B(X), C(X) at the N roots of unity.
    let a_hat = streaming_matvec(&qap.u, &a, qap.n_constraints);
    let b_hat = streaming_matvec(&qap.v, &a, qap.n_constraints);
    let c_hat = streaming_matvec(&qap.w, &a, qap.n_constraints);

    // Pad to domain_size (power of two) with zeros.
    let n = qap.domain_size;
    let a_hat = pad_to(a_hat, n);
    let b_hat = pad_to(b_hat, n);
    let c_hat = pad_to(c_hat, n);

    // ── 3. Quotient polynomial h(X) via coset NTT ──────────────────────────
    // Use coset gH to avoid dividing by zero (t(X) = X^N - 1 vanishes on H).
    let h_coeffs = compute_h_polynomial::<E::ScalarField>(a_hat, b_hat, c_hat, n);

    // ── 4. Proof elements via streaming MSM ──────────────────────────────────
    let w = default_window(n.max(2)) as u32;

    // [A]₁ = [α]₁ + Σᵢ aᵢ·[uᵢ(τ)]₁ + r·[δ]₁
    let sum_a: E::G1 = streaming_msm::<E::G1>(&pk.g1_u_tau, &a, w);
    let enc_a = (E::G1::from(pk.g1_alpha) + sum_a + E::G1::from(pk.g1_delta) * r).into_affine();

    // [B]₂ = [β]₂ + Σᵢ aᵢ·[vᵢ(τ)]₂ + s·[δ]₂
    let sum_b2: E::G2 = streaming_msm::<E::G2>(&pk.g2_v_tau, &a, w);
    let enc_b2 = (E::G2::from(pk.g2_beta) + sum_b2 + E::G2::from(pk.g2_delta) * s).into_affine();

    // [B]₁ (auxiliary, needed for [C]₁)
    let sum_b1: E::G1 = streaming_msm::<E::G1>(&pk.g1_v_tau, &a, w);
    let enc_b1 = E::G1::from(pk.g1_beta) + sum_b1 + E::G1::from(pk.g1_delta) * s;

    // [C]₁ = Σᵢ_{>ℓ} aᵢ·[(βuᵢ+αvᵢ+wᵢ)/δ]₁ + Σⱼ hⱼ·[τʲt(τ)/δ]₁
    //        + s·[A]₁ + r·[B]₁ − rs·[δ]₁
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
// h(X) pipeline  (§5.3 of the paper)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute coefficients of h(X) = (A(X)·B(X) − C(X)) / t(X).
///
/// Uses a coset gH to evaluate t(X) = X^N − 1 as the constant g^N − 1.
/// Pipeline: 3 iNTTs → 3 coset-NTTs → pointwise quotient → 1 iNTT → unshift.
fn compute_h_polynomial<F: FftField>(
    a_evals: Vec<F>,
    b_evals: Vec<F>,
    c_evals: Vec<F>,
    n: usize,
) -> Vec<F> {
    // Step 1: iNTT  →  coefficient vectors A(X), B(X), C(X)
    let a_coeffs = rw_intt(a_evals);
    let b_coeffs = rw_intt(b_evals);
    let c_coeffs = rw_intt(c_evals);

    // Step 2: coset shift  then  NTT  (evaluations on gH)
    // g must not be an N-th root of unity.
    let g = coset_generator::<F>(n);
    let a_coset = rw_ntt(coset_shift(a_coeffs, g));
    let b_coset = rw_ntt(coset_shift(b_coeffs, g));
    let c_coset = rw_ntt(coset_shift(c_coeffs, g));

    // Step 3: pointwise quotient  ĥⱼ = (Â_j · B̂_j − Ĉ_j) / (g^N − 1)
    let t_val_inv = {
        let g_n = g.pow([n as u64]);
        (g_n - F::ONE)
            .inverse()
            .expect("coset generator must satisfy g^N ≠ 1")
    };
    let h_coset: Vec<F> = a_coset
        .into_iter()
        .zip(b_coset)
        .zip(c_coset)
        .map(|((a, b), c)| (a * b - c) * t_val_inv)
        .collect();

    // Step 4: iNTT then coset unshift  →  coefficients of h(X)
    let h_shifted = rw_intt(h_coset);
    let h_coeffs = coset_unshift(h_shifted, g);

    // h(X) has degree ≤ N-2; the last coefficient should be zero.
    // Trim to N-1 terms (indices 0..N-2).
    let mut h = h_coeffs;
    h.truncate(n - 1);
    h
}

/// Return a coset generator g ∉ H (not an N-th root of unity).
///
/// We use the multiplicative generator of F* if available, or fall back
/// to F::GENERATOR (the standard arkworks constant for each field).
fn coset_generator<F: FftField>(_n: usize) -> F {
    F::GENERATOR
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn pad_to<F: ark_ff::Zero + Clone>(mut v: Vec<F>, n: usize) -> Vec<F> {
    v.resize(n, F::zero());
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::Zero;

    /// Verify h(X) by checking A(X)·B(X) − C(X) = h(X)·t(X) over a random point.
    #[test]
    fn test_h_polynomial_identity() {
        use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
        use ark_std::{test_rng, UniformRand};

        let mut rng = test_rng();
        let n = 8usize;
        let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();

        // Random degree ≤ n-1 polynomials A, B, C with A·B = C at H
        let a_coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b_coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let a_evals = domain.fft(&a_coeffs);
        let b_evals = domain.fft(&b_coeffs);
        // Force A·B = C on H (so h divides cleanly)
        let c_evals: Vec<Fr> = a_evals.iter().zip(&b_evals).map(|(a, b)| *a * *b).collect();

        let h = compute_h_polynomial::<Fr>(a_evals, b_evals, c_evals, n);

        // Verify: A(ζ)·B(ζ) − C(ζ) = h(ζ)·t(ζ) for random ζ
        let zeta = Fr::rand(&mut rng);
        let eval_poly = |coeffs: &[Fr]| -> Fr {
            coeffs
                .iter()
                .rev()
                .fold(Fr::zero(), |acc, &c| acc * zeta + c)
        };
        let t_zeta = zeta.pow([n as u64]) - Fr::from(1u64);

        let a_z = eval_poly(&a_coeffs);
        let b_z = eval_poly(&b_coeffs);
        // c is constructed so A·B = C on H; just re-derive c(ζ)
        // In the real prover c_coeffs = iNTT(c_evals); here we approximate.
        let c_coeffs = domain.ifft(&{
            let a_e = domain.fft(&a_coeffs);
            let b_e = domain.fft(&b_coeffs);
            a_e.into_iter()
                .zip(b_e)
                .map(|(a, b)| a * b)
                .collect::<Vec<_>>()
        });
        let c_z = eval_poly(&c_coeffs);
        let h_z = eval_poly(&h);

        // Should satisfy: a_z * b_z - c_z = h_z * t_zeta
        let lhs = a_z * b_z - c_z;
        let rhs = h_z * t_zeta;
        assert_eq!(lhs, rhs, "h(X)·t(X) = A(X)·B(X) − C(X) identity failed");
    }
}
