//! Phase 3: Streaming prover end-to-end correctness tests.
//!
//! Verifies that `streaming_prove` produces a valid proof for the same
//! circuits used in the vec-based tests (N = 2, 4, 8, 16, 64).
//!
//! Each test also checks:
//! 1. streaming_prove → verify ✓
//! 2. fixed-randomness streaming_prove and standard_prove are byte-identical
//! 3. streaming NTT output matches vec NTT output for the same input.

use ark_bn254::{Bn254, Fr};
use ark_std::{rand::SeedableRng, One, UniformRand};

use rw_groth16::{
    file_vec::FileVec, ntt::rw_ntt, setup::setup, standard_prover::standard_prove,
    streaming_ntt::streaming_rw_ntt, streaming_prover::streaming_prove, types::Qap, verify::verify,
};

// ── Circuit helpers ───────────────────────────────────────────────────────────

/// N independent multiplication gates: aᵢ · bᵢ = cᵢ (all private).
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

/// witness = [a₁, b₁, a₁b₁, a₂, b₂, a₂b₂, …] (length 3N).
fn make_witness(n: usize, rng: &mut impl ark_std::rand::Rng) -> Vec<Fr> {
    let mut w = Vec::with_capacity(3 * n);
    for _ in 0..n {
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        w.extend_from_slice(&[a, b, a * b]);
    }
    w
}

// ── Core test helper ──────────────────────────────────────────────────────────

fn run_streaming_prover(n: usize) {
    let mut rng = ark_std::test_rng();
    let qap = make_mul_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);

    let seed = 0x5257_4752_4f54_4800 + n as u64;
    let mut st_rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    let mut std_rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);

    // ── Streaming prover ─────────────────────────────────────────────────────
    let st_proof = streaming_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut st_rng).unwrap();
    assert!(
        verify::<Bn254>(&vk, &stmt, &st_proof),
        "streaming_prove: verify failed at N={n}"
    );

    // ── Standard prover baseline ─────────────────────────────────────────────
    let std_proof = standard_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut std_rng);
    assert!(
        verify::<Bn254>(&vk, &stmt, &std_proof),
        "standard_prove: verify failed at N={n}"
    );

    // ── Fixed-randomness proofs must be byte-identical and 128 bytes ─────────
    let proof_bytes = |p: &rw_groth16::types::Proof<Bn254>| -> Vec<u8> {
        use ark_serialize::CanonicalSerialize;
        let mut buf = Vec::new();
        p.a.serialize_compressed(&mut buf).unwrap();
        p.b.serialize_compressed(&mut buf).unwrap();
        p.c.serialize_compressed(&mut buf).unwrap();
        buf
    };
    let st_bytes = proof_bytes(&st_proof);
    let std_bytes = proof_bytes(&std_proof);
    assert_eq!(
        st_bytes.len(),
        128,
        "streaming proof size ≠ 128 bytes at N={n}"
    );
    assert_eq!(
        st_bytes, std_bytes,
        "fixed-randomness streaming and standard proofs differ at N={n}"
    );
}

// ── Streaming NTT correctness ─────────────────────────────────────────────────

fn run_streaming_ntt_correctness(log_n: u32) {
    let mut rng = ark_std::test_rng();
    let n = 1 << log_n;
    let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

    // Vec-based reference
    let vec_out = rw_ntt(coeffs.clone());

    // File-based streaming
    let fv = FileVec::from_vec(&coeffs).unwrap();
    let file_out = streaming_rw_ntt(fv).unwrap().into_vec().unwrap();

    assert_eq!(file_out, vec_out, "streaming NTT ≠ vec NTT at N={n}");
}

// ── Test cases ────────────────────────────────────────────────────────────────

// Streaming NTT matches vec NTT for small N
#[test]
fn test_streaming_ntt_n2() {
    run_streaming_ntt_correctness(1);
}
#[test]
fn test_streaming_ntt_n4() {
    run_streaming_ntt_correctness(2);
}
#[test]
fn test_streaming_ntt_n8() {
    run_streaming_ntt_correctness(3);
}
#[test]
fn test_streaming_ntt_n16() {
    run_streaming_ntt_correctness(4);
}
#[test]
fn test_streaming_ntt_n64() {
    run_streaming_ntt_correctness(6);
}

// Streaming prover produces valid proofs
#[test]
fn test_streaming_prove_n2() {
    run_streaming_prover(2);
}
#[test]
fn test_streaming_prove_n4() {
    run_streaming_prover(4);
}
#[test]
fn test_streaming_prove_n8() {
    run_streaming_prover(8);
}
#[test]
fn test_streaming_prove_n16() {
    run_streaming_prover(16);
}

// N=64 is a bit slower but still reasonable for CI
#[test]
fn test_streaming_prove_n64() {
    run_streaming_prover(64);
}

// N=256: run locally with `cargo test -- --ignored`
#[test]
#[ignore = "large N — run locally with: cargo test -- --ignored"]
fn test_streaming_prove_n256() {
    run_streaming_prover(256);
}
