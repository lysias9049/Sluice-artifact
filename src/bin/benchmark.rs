//! RW-Groth16 3-way comparison benchmark
//!
//! 3가지 prover를 비교:
//!   1. Standard Groth16    — in-memory ark-poly FFT (O(N) RAM)
//!   2. RW-Groth16 Vec      — Vec 기반 SBM NTT (O(N) RAM)
//!   3. RW-Groth16 Disk     — streaming_prove_disk (CRS on disk, caller QAP/witness in RAM)
//!
//! [3]은 streaming_setup으로 CRS를 디스크에 쓴 뒤 streaming_prove_disk를 실행.
//! prove time은 setup 제외, prove 호출만 측정.
//!
//! 사용법:
//!   cargo run --bin benchmark --release -- 64 256 1024 4096 2> Experiments/benchmark_small.csv
//!
//! 주의: Standard/Vec prover는 N ≥ 2^18 에서 OOM 가능.
//!   대규모 N(2^18 이상) 전용 → streaming_bench.rs 사용.
//!
//! 회로: N개 곱셈 게이트 (aᵢ · bᵢ = cᵢ, 모두 private).
//! Wire layout: [const(0), a₁(1), b₁(2), c₁(3), a₂(4), …]

use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use ark_std::{One, UniformRand};

use rw_groth16::{
    harness::{measure, peak_rss_mb},
    prover::prove as rw_prove,
    setup::{setup, streaming_setup},
    standard_prover::standard_prove,
    streaming_prover::streaming_prove_disk,
    types::Qap,
    verify::verify,
};

// ── 회로 구성 ─────────────────────────────────────────────────────────────────

fn make_qap(n: usize) -> Qap<Fr> {
    let one = Fr::one();
    let mut u = Vec::with_capacity(n);
    let mut v = Vec::with_capacity(n);
    let mut w = Vec::with_capacity(n);
    for i in 0..n {
        u.push((i, 3 * i + 1, one));
        v.push((i, 3 * i + 2, one));
        w.push((i, 3 * i + 3, one));
    }
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

// ── 유틸리티 ──────────────────────────────────────────────────────────────────

fn proof_bytes(p: &rw_groth16::types::Proof<Bn254>) -> usize {
    let mut buf = Vec::new();
    p.a.serialize_compressed(&mut buf).unwrap();
    p.b.serialize_compressed(&mut buf).unwrap();
    p.c.serialize_compressed(&mut buf).unwrap();
    buf.len()
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

// ── 단일 N 실험 ───────────────────────────────────────────────────────────────

fn run(n: usize) {
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!(
        "║  N = {n:<8}  n_vars = {:<8}  log₂N = {}",
        1 + 3 * n,
        n.ilog2()
    );
    println!("╚══════════════════════════════════════════════════════╝");

    let mut rng = ark_std::test_rng();
    let qap = make_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    // ── 공유 CRS ──────────────────────────────────────────────────────────────
    let rss0 = peak_rss_mb();
    let ((pk, vk), t_setup) = measure(|| setup::<Bn254, _>(&qap, &mut rng));
    let rss1 = peak_rss_mb();
    println!("  [Setup — 공유 CRS]");
    println!("    time      : {:.1} ms", ms(t_setup));
    println!(
        "    peak RSS  : +{:.1} MB  (total {:.1} MB)",
        rss1 - rss0,
        rss1
    );

    // ── 1. Standard Groth16 (in-memory, O(N) RAM) ─────────────────────────────
    let r0 = peak_rss_mb();
    let (st_proof, t_st) =
        measure(|| standard_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng));
    let r1 = peak_rss_mb();
    let st_rss_delta = r1 - r0;
    let (st_ok, t_st_v) = measure(|| verify::<Bn254>(&vk, &stmt, &st_proof));
    println!();
    println!("  [1] Standard Groth16  (in-memory ark-poly FFT, O(N) RAM)");
    println!(
        "    prove     : {:>10.1} ms  │  RSS delta: +{:.1} MB",
        ms(t_st),
        st_rss_delta
    );
    println!("    verify    : {:>10.3} ms  │  valid: {st_ok}", ms(t_st_v));
    println!("    proof     : {} bytes", proof_bytes(&st_proof));

    // ── 2. RW-Groth16 Vec (SBM NTT, O(N) RAM) ────────────────────────────────
    let r0 = peak_rss_mb();
    let (rw_proof, t_rw) = measure(|| rw_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng));
    let r1 = peak_rss_mb();
    let rw_rss_delta = r1 - r0;
    let (rw_ok, t_rw_v) = measure(|| verify::<Bn254>(&vk, &stmt, &rw_proof));
    println!();
    println!("  [2] RW-Groth16 Vec    (SBM NTT, Vec<F>, O(N) RAM)");
    println!(
        "    prove     : {:>10.1} ms  │  RSS delta: +{:.1} MB",
        ms(t_rw),
        rw_rss_delta
    );
    println!("    verify    : {:>10.3} ms  │  valid: {rw_ok}", ms(t_rw_v));
    println!("    proof     : {} bytes", proof_bytes(&rw_proof));

    // ── 3. RW-Groth16 Disk (RW-File: CRS on disk, caller QAP/witness in RAM) ──
    // streaming_setup으로 CRS를 FileVec(disk)에 기록 (prove time에서 제외)
    let mut rng_disk = ark_std::test_rng();
    let (spk, vk_disk) =
        streaming_setup::<Bn254, _>(&qap, &mut rng_disk).expect("streaming_setup failed");

    let r0 = peak_rss_mb();
    let (disk_proof, t_disk) = measure(|| {
        streaming_prove_disk::<Bn254, _>(&qap, &spk, &stmt, &witness, &mut rng_disk)
            .expect("streaming_prove_disk error")
    });
    let r1 = peak_rss_mb();
    let (disk_ok, t_disk_v) = measure(|| verify::<Bn254>(&vk_disk, &stmt, &disk_proof));
    println!();
    println!("  [3] RW-Groth16 Disk  (RW-File: CRS on disk, caller QAP/witness in RAM)");
    println!(
        "    prove     : {:>10.1} ms  │  RSS delta: +{:.1} MB",
        ms(t_disk),
        r1 - r0
    );
    println!(
        "    verify    : {:>10.3} ms  │  valid: {disk_ok}",
        ms(t_disk_v)
    );
    println!("    proof     : {} bytes", proof_bytes(&disk_proof));

    // ── 요약 ─────────────────────────────────────────────────────────────────
    println!();
    println!("  ── 요약 (Disk / Standard) ───────────────────────────────");
    println!("    prove time ratio  : {:.2}×", ms(t_disk) / ms(t_st));
    println!(
        "    proof size        : 동일 ({} bytes)",
        proof_bytes(&disk_proof)
    );

    // CSV to stderr: log_n, n, st_ms, rw_ms, disk_ms, rss_st, rss_rw, rss_disk, ok×3
    let rss_disk_delta = r1 - r0;
    eprintln!(
        "{},{},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1},{},{},{}",
        n.ilog2(),
        n,
        ms(t_st),
        ms(t_rw),
        ms(t_disk),
        st_rss_delta,
        rw_rss_delta,
        rss_disk_delta,
        st_ok,
        rw_ok,
        disk_ok
    );

    assert!(st_ok, "Standard proof invalid at N={n}");
    assert!(rw_ok, "RW Vec proof invalid at N={n}");
    assert!(disk_ok, "RW Disk proof invalid at N={n}");
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let sizes: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|s| s.parse::<usize>().ok())
        .collect();

    let sizes = if sizes.is_empty() { vec![1024] } else { sizes };

    // CSV 헤더 to stderr
    eprintln!("log_n,n,standard_ms,rw_vec_ms,rw_file_ms,rss1,rss2,rss3,st_ok,rw_ok,sv_ok");

    for &n in &sizes {
        assert!(
            n >= 2 && n.is_power_of_two(),
            "N must be a power of two ≥ 2, got {n}"
        );
        run(n);
    }

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("대규모 N (2^18 이상) 전용:  cargo run --bin streaming_bench --release -- 18 28");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
