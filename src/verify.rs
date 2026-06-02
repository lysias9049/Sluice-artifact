//! RW-Groth16 Verifier
//!
//! Groth16 verification equation (standard, O(1) operations):
//!
//!   e([A]₁, [B]₂) = e([α]₁, [β]₂)
//!                 · e(Σᵢ₌₀^ℓ aᵢ·[(βuᵢ+αvᵢ+wᵢ)/γ]₁, [γ]₂)
//!                 · e([C]₁, [δ]₂)
//!
//! Memory: O(ℓ) for the public-input MSM; all pairings are O(1).

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_std::Zero;

use crate::types::{Proof, VerifyingKey};

/// Verify a Groth16 proof against public inputs `statement = [a₁, …, aℓ]`.
///
/// Returns `true` iff the proof is valid.
pub fn verify<E: Pairing>(
    vk: &VerifyingKey<E>,
    statement: &[E::ScalarField],
    proof: &Proof<E>,
) -> bool {
    // ── Public-input accumulator ──────────────────────────────────────────────
    // Σᵢ₌₀^ℓ aᵢ·[(βuᵢ+αvᵢ+wᵢ)/γ]₁
    // vk.gamma_abc_g1[0] corresponds to the constant wire a₀ = 1.
    // vk.gamma_abc_g1[1..] correspond to a₁ … aℓ.
    assert_eq!(
        vk.gamma_abc_g1.len(),
        statement.len() + 1,
        "gamma_abc_g1 must have length n_pub + 1"
    );

    let mut acc = E::G1::from(vk.gamma_abc_g1[0]); // a₀ = 1 · gamma_abc[0]
    for (ai, &gi) in statement.iter().zip(&vk.gamma_abc_g1[1..]) {
        acc += E::G1::from(gi) * ai;
    }
    let acc = acc.into_affine();

    // ── Pairing check ─────────────────────────────────────────────────────────
    // e([A]₁,[B]₂) == e([α]₁,[β]₂) · e(acc,[γ]₂) · e([C]₁,[δ]₂)
    //
    // Equivalently (move RHS to left as negatives):
    //   e([A]₁,[B]₂) · e(-[α]₁,[β]₂) · e(-acc,[γ]₂) · e(-[C]₁,[δ]₂) == 1

    let neg_alpha = (-E::G1::from(vk.alpha_g1)).into_affine();
    let neg_acc = (-E::G1::from(acc)).into_affine();
    let neg_c = (-E::G1::from(proof.c)).into_affine();

    let lhs = E::multi_pairing(
        [proof.a, neg_alpha, neg_acc, neg_c],
        [proof.b, vk.beta_g2, vk.gamma_g2, vk.delta_g2],
    );

    lhs.is_zero()
}
