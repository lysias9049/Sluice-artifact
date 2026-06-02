//! End-to-end integration test: prove and verify `a × b = c`
//!
//! Circuit: one multiplication gate with public output c = a × b.
//!   Wire layout:  a₀=1 (constant), a₁=c (public), a₂=a (private), a₃=b (private)
//!   n_vars = 4,  n_pub = 1
//!
//! R1CS constraint (1 row):
//!   (a₂) · (a₃) = (a₁)
//!   i.e. U·a = [a₂], V·a = [a₃], W·a = [a₁]
//!
//! Concrete assignment: a=2, b=3, c=6.

use ark_bn254::{Bn254, Fr};
use ark_std::test_rng;

use rw_groth16::{prover::prove, setup::setup, types::Qap, verify::verify};

fn mul_circuit_qap() -> Qap<Fr> {
    // 1 constraint; domain_size must be a power of two ≥ 1.
    // We use domain_size = 1 (N=1), which means all iNTT/NTT operate on size-1
    // vectors — that's valid (the single Lagrange basis is L_0(X) = 1).
    // However for coset NTT the degree of h is ≤ N-2 = -1, meaning h = 0.
    // That's correct: a₂·a₃ − a₁ = 0 on H, so h is identically zero.
    //
    // We use domain_size = 2 to keep the NTT non-trivial (log₂ = 1 bit).
    // The second row of U/V/W is all-zero (unused constraint).
    let domain_size = 2;
    let n_constraints = 1; // only 1 real constraint; 1 phantom zero-row
    let n_vars = 4; // a₀=1, a₁=c, a₂=a, a₃=b
    let n_pub = 1; // a₁ is public

    // Matrix entries (constraint_idx, wire_idx, value) sorted by wire_idx.
    // U: a₂ (wire 2) contributes to constraint 0
    let u = vec![(0usize, 2usize, Fr::from(1u64))];
    // V: a₃ (wire 3)
    let v = vec![(0usize, 3usize, Fr::from(1u64))];
    // W: a₁ (wire 1)
    let w = vec![(0usize, 1usize, Fr::from(1u64))];

    Qap {
        domain_size,
        n_constraints,
        n_vars,
        n_pub,
        u,
        v,
        w,
    }
}

#[test]
fn test_mul_circuit_valid_proof() {
    let mut rng = test_rng();
    let qap = mul_circuit_qap();

    // Trusted setup
    let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);

    // Assignment: a=2, b=3, c=6
    let statement = vec![Fr::from(6u64)]; // public:  [c]
    let witness = vec![Fr::from(2u64), Fr::from(3u64)]; // private: [a, b]

    // Prove
    let proof = prove::<Bn254, _>(&qap, &pk, &statement, &witness, &mut rng);

    // Verify
    assert!(
        verify::<Bn254>(&vk, &statement, &proof),
        "valid proof must verify"
    );
}

#[test]
fn test_mul_circuit_wrong_statement_fails() {
    let mut rng = test_rng();
    let qap = mul_circuit_qap();
    let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);

    // Correct proof for a=2, b=3, c=6
    let statement = vec![Fr::from(6u64)];
    let witness = vec![Fr::from(2u64), Fr::from(3u64)];
    let proof = prove::<Bn254, _>(&qap, &pk, &statement, &witness, &mut rng);

    // Claim c=7 (wrong)
    let wrong_statement = vec![Fr::from(7u64)];
    assert!(
        !verify::<Bn254>(&vk, &wrong_statement, &proof),
        "proof with wrong public input must not verify"
    );
}
