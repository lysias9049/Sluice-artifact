//! Memory benchmark: peak RAM of streaming_prove_disk vs standard_prove.
//!
//! For each N in [2^LOG_MIN, 2^LOG_MAX] this binary runs both provers and
//! reports the peak working-set growth during the prove call.
//!
//! Usage:
//!   cargo run --bin mem_bench --release
//!   cargo run --bin mem_bench --release -- 4 10        # custom range
//!   cargo run --bin mem_bench --release -- 4 14 2> mem.csv
//!
//! The stdout table is human-readable; stderr is CSV for plotting.

use ark_bn254::{Bn254, Fr};
use ark_std::{One, UniformRand};

use rw_groth16::{
    harness::{current_rss_mb, peak_rss_mb},
    setup::{setup, streaming_setup},
    streaming_prover::{streaming_prove, streaming_prove_disk},
    types::Qap,
    verify::verify,
};

// ── circuit ───────────────────────────────────────────────────────────────────

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

// ── memory sampler ────────────────────────────────────────────────────────────

/// Measure peak working-set growth while running `f`.
///
/// Returns `(result, peak_delta_mb, current_after_mb)` where:
/// - `peak_delta_mb`   = how much the lifetime peak grew during `f`
/// - `current_after_mb` = current working set after `f` completes
fn measure_ram<T, F: FnOnce() -> T>(f: F) -> (T, f64, f64) {
    let peak_before = peak_rss_mb();
    let v = f();
    let peak_after = peak_rss_mb();
    let current = current_rss_mb();
    (v, peak_after - peak_before, current)
}

// ── standard_prove (baseline O(N) RAM) ───────────────────────────────────────

fn run_standard(log_n: u32) -> (f64, f64) {
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let qap = make_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    let (pk, _vk) = setup::<Bn254, _>(&qap, &mut rng);

    let (proof, peak_delta, current) = measure_ram(|| {
        streaming_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng)
            .expect("streaming_prove failed")
    });
    let _ = proof;
    (peak_delta, current)
}

// ── streaming_prove_disk (O(log N) RAM) ──────────────────────────────────────

fn run_disk(log_n: u32) -> (f64, f64) {
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let qap = make_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    let (spk, vk) = streaming_setup::<Bn254, _>(&qap, &mut rng).expect("streaming_setup failed");

    let (proof, peak_delta, current) = measure_ram(|| {
        streaming_prove_disk::<Bn254, _>(&qap, &spk, &stmt, &witness, &mut rng)
            .expect("streaming_prove_disk failed")
    });

    let ok = verify::<Bn254>(&vk, &stmt, &proof);
    assert!(ok, "proof verification failed at N=2^{log_n}");

    (peak_delta, current)
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let log_min: u32 = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(4);
    let log_max: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);

    println!("=== RW-Groth16 Memory Benchmark ===");
    println!("peak_delta = lifetime-peak growth during prove call");
    println!("current    = working-set size right after prove returns");
    println!();
    println!(
        "{:<6} {:>8}  {:>14}  {:>12}  {:>14}  {:>12}",
        "log N", "N", "std peak_Δ(MB)", "std cur(MB)", "disk peak_Δ(MB)", "disk cur(MB)"
    );
    println!("{}", "─".repeat(72));

    // CSV header to stderr
    eprintln!("log_n,n,std_peak_delta_mb,std_current_mb,disk_peak_delta_mb,disk_current_mb");

    for log_n in log_min..=log_max {
        let n = 1usize << log_n;

        let (std_delta, std_cur) = run_standard(log_n);
        let (disk_delta, disk_cur) = run_disk(log_n);

        println!(
            "{:<6} {:>8}  {:>14.2}  {:>12.2}  {:>14.2}  {:>12.2}",
            log_n, n, std_delta, std_cur, disk_delta, disk_cur
        );
        eprintln!(
            "{},{},{:.2},{:.2},{:.2},{:.2}",
            log_n, n, std_delta, std_cur, disk_delta, disk_cur
        );
    }

    println!();
    println!("기대값: disk peak_Δ ≈ 일정 (O(log N)); std peak_Δ ∝ N (O(N))");
    println!(
        "CSV: cargo run --bin mem_bench --release -- {} {} 2> mem.csv",
        log_min, log_max
    );
}
