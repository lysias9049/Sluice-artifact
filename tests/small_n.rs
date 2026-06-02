//! Phase 2-2: 소규모 N 정확성 테스트
//!
//! N개의 독립 곱셈 게이트 회로 (aᵢ · bᵢ = cᵢ) 를
//! N = 2, 4, 8, 16, 64, 256 에 대해 검증.
//!
//! 검증 항목:
//! 1. RW-Groth16 prover → verify 통과
//! 2. Standard prover  → verify 통과
//! 3. 두 prover의 proof byte size 동일 (128 bytes on BN254)

use ark_bn254::{Bn254, Fr};
use ark_std::{One, UniformRand};

use rw_groth16::{
    prover::prove as rw_prove, setup::setup, standard_prover::standard_prove, types::Qap,
    verify::verify,
};

// ── 회로 구성 ─────────────────────────────────────────────────────────────────

/// N개 곱셈 게이트 QAP (모두 private, n_pub = 0).
/// Wire layout: [const(0), a₁(1), b₁(2), c₁(3), a₂(4), …]
fn make_mul_qap(n: usize) -> Qap<Fr> {
    let one = Fr::one();
    let u: Vec<_> = (0..n).map(|i| (i, 3 * i + 1, one)).collect();
    let v: Vec<_> = (0..n).map(|i| (i, 3 * i + 2, one)).collect();
    let w: Vec<_> = (0..n).map(|i| (i, 3 * i + 3, one)).collect();
    Qap {
        domain_size: n,
        n_constraints: n,
        n_vars: 1 + 3 * n,
        n_pub: 0,
        u,
        v,
        w,
    }
}

/// witness = [a₁, b₁, c₁=a₁b₁, a₂, b₂, c₂, …] (길이 3N)
fn make_witness(n: usize, rng: &mut impl ark_std::rand::Rng) -> Vec<Fr> {
    let mut w = Vec::with_capacity(3 * n);
    for _ in 0..n {
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        w.extend_from_slice(&[a, b, a * b]);
    }
    w
}

// ── 공통 검증 헬퍼 ────────────────────────────────────────────────────────────

fn run_both_provers(n: usize) {
    let mut rng = ark_std::test_rng();
    let qap = make_mul_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);

    // RW-Groth16
    let rw_proof = rw_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng);
    assert!(
        verify::<Bn254>(&vk, &stmt, &rw_proof),
        "RW-Groth16 verify failed at N={n}"
    );

    // Standard Groth16
    let st_proof = standard_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng);
    assert!(
        verify::<Bn254>(&vk, &stmt, &st_proof),
        "Standard Groth16 verify failed at N={n}"
    );

    // 증명 크기 일치
    use ark_serialize::CanonicalSerialize;
    let proof_size = |p: &rw_groth16::types::Proof<Bn254>| -> usize {
        let mut buf = Vec::new();
        p.a.serialize_compressed(&mut buf).unwrap();
        p.b.serialize_compressed(&mut buf).unwrap();
        p.c.serialize_compressed(&mut buf).unwrap();
        buf.len()
    };
    assert_eq!(
        proof_size(&rw_proof),
        proof_size(&st_proof),
        "proof size mismatch at N={n}"
    );
    assert_eq!(
        proof_size(&rw_proof),
        128,
        "expected 128-byte proof at N={n}"
    );
}

// ── 테스트 케이스 ─────────────────────────────────────────────────────────────

#[test]
fn test_n2() {
    run_both_provers(2);
}

#[test]
fn test_n4() {
    run_both_provers(4);
}

#[test]
fn test_n8() {
    run_both_provers(8);
}

#[test]
fn test_n16() {
    run_both_provers(16);
}

#[test]
fn test_n64() {
    run_both_provers(64);
}

// N=256은 시간이 걸릴 수 있어 ignored로 표시 (로컬 실험용)
#[test]
#[ignore = "large N — run locally with: cargo test -- --ignored"]
fn test_n256() {
    run_both_provers(256);
}
