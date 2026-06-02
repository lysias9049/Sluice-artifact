//! Phase 2-3: MSM window size tradeoff 측정
//!
//! window size w = 1, 2, 4, 6, 8, 12, 16 별로 prove 시간과
//! peak RSS를 측정해서 memory/time tradeoff curve를 출력함.
//!
//! 사용법:
//!   cargo run --bin msm_tradeoff --release            # N = 16 (기본)
//!   cargo run --bin msm_tradeoff --release -- 64      # N = 64
//!   cargo run --bin msm_tradeoff --release -- 1024    # 대규모 (로컬용)

use ark_bn254::{Bn254, Fr};
use ark_ec::CurveGroup;
use ark_ff::{FftField, Field};
use ark_std::{One, UniformRand, Zero};

use rw_groth16::{
    harness::{measure, peak_rss_mb},
    msm::streaming_msm,
    ntt::{coset_shift, coset_unshift, rw_intt, rw_ntt},
    r1cs::streaming_matvec,
    setup::setup,
    types::{Proof, ProvingKey, Qap},
    verify::verify,
};

// ── 회로 구성 ─────────────────────────────────────────────────────────────────

fn make_qap(n: usize) -> Qap<Fr> {
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

fn make_witness(n: usize, rng: &mut impl ark_std::rand::Rng) -> Vec<Fr> {
    let mut w = Vec::with_capacity(3 * n);
    for _ in 0..n {
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        w.extend_from_slice(&[a, b, a * b]);
    }
    w
}

// ── window-size 지정 prover ───────────────────────────────────────────────────

/// 지정된 window_bits로 MSM을 수행하는 prover.
/// prover.rs의 prove()와 동일한 로직이지만 w를 외부에서 주입.
fn prove_with_window(
    qap: &Qap<Fr>,
    pk: &ProvingKey<Bn254>,
    witness: &[Fr],
    window_bits: u32,
    rng: &mut impl ark_std::rand::Rng,
) -> Proof<Bn254> {
    use ark_std::UniformRand;
    type F = Fr;

    let r = F::rand(rng);
    let s = F::rand(rng);

    let mut a: Vec<F> = Vec::with_capacity(qap.n_vars);
    a.push(F::ONE);
    // n_pub = 0, so no statement
    a.extend_from_slice(witness);

    let n = qap.domain_size;

    let a_hat = streaming_matvec(&qap.u, &a, qap.n_constraints);
    let b_hat = streaming_matvec(&qap.v, &a, qap.n_constraints);
    let c_hat = streaming_matvec(&qap.w, &a, qap.n_constraints);

    let pad = |mut v: Vec<F>| {
        v.resize(n, F::zero());
        v
    };
    let a_hat = pad(a_hat);
    let b_hat = pad(b_hat);
    let c_hat = pad(c_hat);

    // h(X) via coset NTT
    let g = F::GENERATOR;
    let t_inv = (g.pow([n as u64]) - F::ONE).inverse().unwrap();

    let a_coset = rw_ntt(coset_shift(rw_intt(a_hat), g));
    let b_coset = rw_ntt(coset_shift(rw_intt(b_hat), g));
    let c_coset = rw_ntt(coset_shift(rw_intt(c_hat), g));

    let h_coset: Vec<F> = a_coset
        .into_iter()
        .zip(b_coset)
        .zip(c_coset)
        .map(|((a, b), c)| (a * b - c) * t_inv)
        .collect();

    let mut h = coset_unshift(rw_intt(h_coset), g);
    h.truncate(n - 1);

    // MSMs with specified window size
    let w = window_bits;
    let sum_a = streaming_msm::<ark_bn254::G1Projective>(&pk.g1_u_tau, &a, w);
    let enc_a = (<ark_bn254::G1Projective as From<_>>::from(pk.g1_alpha)
        + sum_a
        + <ark_bn254::G1Projective as From<_>>::from(pk.g1_delta) * r)
        .into_affine();

    let sum_b2 = streaming_msm::<ark_bn254::G2Projective>(&pk.g2_v_tau, &a, w);
    let enc_b2 = (<ark_bn254::G2Projective as From<_>>::from(pk.g2_beta)
        + sum_b2
        + <ark_bn254::G2Projective as From<_>>::from(pk.g2_delta) * s)
        .into_affine();

    let sum_b1 = streaming_msm::<ark_bn254::G1Projective>(&pk.g1_v_tau, &a, w);
    let enc_b1 = <ark_bn254::G1Projective as From<_>>::from(pk.g1_beta)
        + sum_b1
        + <ark_bn254::G1Projective as From<_>>::from(pk.g1_delta) * s;

    let witness_scalars = &a[1..]; // n_pub = 0
    let sum_c_wit =
        streaming_msm::<ark_bn254::G1Projective>(&pk.g1_abc_over_delta, witness_scalars, w);
    let sum_c_quot = streaming_msm::<ark_bn254::G1Projective>(&pk.g1_h_pow_tau_over_delta, &h, w);

    let enc_c = (sum_c_wit
        + sum_c_quot
        + <ark_bn254::G1Projective as From<_>>::from(enc_a) * s
        + enc_b1 * r
        - <ark_bn254::G1Projective as From<_>>::from(pk.g1_delta) * (r * s))
        .into_affine();

    Proof {
        a: enc_a,
        b: enc_b2,
        c: enc_c,
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(16); // 기본값: 작은 N

    assert!(
        n >= 2 && n.is_power_of_two(),
        "N must be a power of two ≥ 2"
    );

    let mut rng = ark_std::test_rng();
    let qap = make_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);

    println!("=== MSM Window Size Tradeoff ===");
    println!("N = {n}  (n_vars = {})", 1 + 3 * n);
    println!();
    println!(
        "{:<8} {:>12} {:>14} {:>8}",
        "window_w", "prove(ms)", "peak_RSS(MB)", "valid"
    );
    println!("{}", "─".repeat(46));

    // 출력용 CSV 헤더
    eprintln!("window_w,prove_ms,peak_rss_mb,valid");

    for &w in &[1u32, 2, 4, 6, 8, 12, 16] {
        let rss0 = peak_rss_mb();
        let (proof, t) =
            measure(|| prove_with_window(&qap, &pk, &witness, w, &mut ark_std::test_rng()));
        let rss1 = peak_rss_mb();
        let valid = verify::<Bn254>(&vk, &stmt, &proof);

        println!(
            "{:<8} {:>11.1} {:>13.1} {:>8}",
            w,
            t.as_secs_f64() * 1000.0,
            rss1 - rss0,
            valid
        );

        // CSV to stderr (redirect: cargo run ... 2> msm_tradeoff.csv)
        eprintln!(
            "{},{:.1},{:.1},{}",
            w,
            t.as_secs_f64() * 1000.0,
            rss1 - rss0,
            valid
        );
    }

    println!();
    println!("CSV: cargo run --bin msm_tradeoff --release -- {n} 2> msm_tradeoff.csv");
}
