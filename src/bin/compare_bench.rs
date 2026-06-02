//! Standard Groth16 vs RW-Groth16 comparison benchmark.
//!
//! Measures for each N ∈ {2^LOG_MIN … 2^LOG_MAX} (default 4–10), REPS times each:
//!   • Proving time   (ms, mean ± std)
//!   • Proof size     (bytes, constant)
//!   • Verification time (ms, mean ± std)
//!   • Peak RAM       (MB) during the prove call
//!
//! Usage:
//!   cargo run --bin compare_bench --release                       # default 4–10, 5 reps
//!   cargo run --bin compare_bench --release -- 4 10 5             # explicit args
//!   cargo run --bin compare_bench --release -- 4 10 5 2> cmp.csv  # CSV to file
//!
//! Stdout: human-readable table.   Stderr: CSV rows for plotting.

use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use ark_std::{One, UniformRand};

use rw_groth16::{
    harness::{current_rss_mb, peak_rss_mb},
    setup::{setup, streaming_setup},
    standard_prover::standard_prove,
    streaming_prover::streaming_prove_disk,
    types::Qap,
    verify::verify,
};

// ── circuit factory ───────────────────────────────────────────────────────────

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

fn make_witness(n: usize, seed: u64) -> Vec<Fr> {
    use ark_std::rand::SeedableRng;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    let mut w = Vec::with_capacity(3 * n);
    for _ in 0..n {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        w.extend_from_slice(&[a, b, a * b]);
    }
    w
}

fn proof_bytes<E: ark_ec::pairing::Pairing>(p: &rw_groth16::types::Proof<E>) -> usize {
    let mut buf = Vec::new();
    p.a.serialize_compressed(&mut buf).unwrap();
    p.b.serialize_compressed(&mut buf).unwrap();
    p.c.serialize_compressed(&mut buf).unwrap();
    buf.len()
}

// ── per-run result ────────────────────────────────────────────────────────────

struct RunResult {
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    peak_delta_mb: f64, // peak_rss growth during prove
    current_mb: f64,    // working-set size right after prove
}

// ── Standard Groth16 ─────────────────────────────────────────────────────────

fn bench_standard(log_n: u32, reps: usize) -> Vec<RunResult> {
    let n = 1usize << log_n;
    let qap = make_qap(n);
    let mut rng = ark_std::test_rng();
    let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);
    let stmt: Vec<Fr> = vec![];

    (0..reps)
        .map(|rep| {
            let witness = make_witness(n, rep as u64 + 1);

            let peak0 = peak_rss_mb();
            let t0 = Instant::now();
            let proof = standard_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng);
            let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let peak1 = peak_rss_mb();
            let current = current_rss_mb();

            let t1 = Instant::now();
            let ok = verify::<Bn254>(&vk, &stmt, &proof);
            let verify_ms = t1.elapsed().as_secs_f64() * 1000.0;
            assert!(ok, "standard_prove: verify failed at N=2^{log_n} rep={rep}");

            RunResult {
                prove_ms,
                verify_ms,
                proof_bytes: proof_bytes(&proof),
                peak_delta_mb: peak1 - peak0,
                current_mb: current,
            }
        })
        .collect()
}

// ── RW-Groth16 (streaming, disk CRS) ─────────────────────────────────────────

fn bench_rw_disk(log_n: u32, reps: usize) -> Vec<RunResult> {
    let n = 1usize << log_n;
    let qap = make_qap(n);
    let mut rng = ark_std::test_rng();
    let (spk, vk) = streaming_setup::<Bn254, _>(&qap, &mut rng).expect("streaming_setup failed");
    let stmt: Vec<Fr> = vec![];

    (0..reps)
        .map(|rep| {
            let witness = make_witness(n, rep as u64 + 1);

            let peak0 = peak_rss_mb();
            let t0 = Instant::now();
            let proof = streaming_prove_disk::<Bn254, _>(&qap, &spk, &stmt, &witness, &mut rng)
                .expect("streaming_prove_disk failed");
            let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let peak1 = peak_rss_mb();
            let current = current_rss_mb();

            let t1 = Instant::now();
            let ok = verify::<Bn254>(&vk, &stmt, &proof);
            let verify_ms = t1.elapsed().as_secs_f64() * 1000.0;
            assert!(
                ok,
                "streaming_prove_disk: verify failed at N=2^{log_n} rep={rep}"
            );

            RunResult {
                prove_ms,
                verify_ms,
                proof_bytes: proof_bytes(&proof),
                peak_delta_mb: peak1 - peak0,
                current_mb: current,
            }
        })
        .collect()
}

// ── statistics helpers ────────────────────────────────────────────────────────

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn std_dev(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let m = mean(v);
    let var = v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
    var.sqrt()
}

fn max_f(v: &[f64]) -> f64 {
    v.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
}

struct Stats {
    prove_mean: f64,
    prove_std: f64,
    verify_mean: f64,
    verify_std: f64,
    proof_bytes: usize,
    peak_delta_mb: f64, // max across reps (worst case)
    current_mb: f64,    // mean after-prove working set
}

fn summarise(runs: &[RunResult]) -> Stats {
    let prove_v: Vec<f64> = runs.iter().map(|r| r.prove_ms).collect();
    let verify_v: Vec<f64> = runs.iter().map(|r| r.verify_ms).collect();
    let delta_v: Vec<f64> = runs.iter().map(|r| r.peak_delta_mb).collect();
    let current_v: Vec<f64> = runs.iter().map(|r| r.current_mb).collect();
    Stats {
        prove_mean: mean(&prove_v),
        prove_std: std_dev(&prove_v),
        verify_mean: mean(&verify_v),
        verify_std: std_dev(&verify_v),
        proof_bytes: runs[0].proof_bytes,
        peak_delta_mb: max_f(&delta_v),
        current_mb: mean(&current_v),
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let log_min: u32 = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(4);
    let log_max: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let reps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);

    println!("=== Standard Groth16 vs RW-Groth16 Comparison ===");
    println!("Circuit: N multiplications (aᵢ·bᵢ=cᵢ)  Curve: BN254");
    println!("Repetitions per N: {reps}  (mean ± std reported for time)");
    println!("RAM: peak_delta = max growth of lifetime peak during prove;");
    println!("     current    = working-set size right after prove returns");
    println!();

    // ── Standard Groth16 table ────────────────────────────────────────────────
    println!("── Standard Groth16 (in-memory, ark-poly FFT, O(N) RAM) ──────────");
    println!(
        "{:<6} {:>8}  {:>16}  {:>14}  {:>10}  {:>12}  {:>12}",
        "log N",
        "N",
        "prove ms (mean±std)",
        "verify ms (±std)",
        "proof (B)",
        "peak_Δ RAM",
        "cur RAM"
    );
    println!("{}", "─".repeat(92));
    eprintln!("scheme,log_n,n,prove_mean_ms,prove_std_ms,verify_mean_ms,verify_std_ms,proof_bytes,peak_delta_mb,current_mb");

    let mut std_stats: Vec<(u32, Stats)> = Vec::new();
    for log_n in log_min..=log_max {
        let n = 1usize << log_n;
        let runs = bench_standard(log_n, reps);
        let s = summarise(&runs);
        println!(
            "{:<6} {:>8}  {:>9.1} ± {:>5.1}   {:>7.3} ± {:>5.3}   {:>10}  {:>8.2} MB  {:>8.2} MB",
            log_n,
            n,
            s.prove_mean,
            s.prove_std,
            s.verify_mean,
            s.verify_std,
            s.proof_bytes,
            s.peak_delta_mb,
            s.current_mb
        );
        eprintln!(
            "standard,{},{},{:.3},{:.3},{:.4},{:.4},{},{:.3},{:.3}",
            log_n,
            n,
            s.prove_mean,
            s.prove_std,
            s.verify_mean,
            s.verify_std,
            s.proof_bytes,
            s.peak_delta_mb,
            s.current_mb
        );
        std_stats.push((log_n, s));
    }

    println!();

    // ── RW-Groth16 table ──────────────────────────────────────────────────────
    println!("── RW-Groth16 (streaming, disk CRS, O(log N) RAM) ────────────────");
    println!(
        "{:<6} {:>8}  {:>16}  {:>14}  {:>10}  {:>12}  {:>12}",
        "log N",
        "N",
        "prove ms (mean±std)",
        "verify ms (±std)",
        "proof (B)",
        "peak_Δ RAM",
        "cur RAM"
    );
    println!("{}", "─".repeat(92));

    let mut rw_stats: Vec<(u32, Stats)> = Vec::new();
    for log_n in log_min..=log_max {
        let n = 1usize << log_n;
        let runs = bench_rw_disk(log_n, reps);
        let s = summarise(&runs);
        println!(
            "{:<6} {:>8}  {:>9.1} ± {:>5.1}   {:>7.3} ± {:>5.3}   {:>10}  {:>8.2} MB  {:>8.2} MB",
            log_n,
            n,
            s.prove_mean,
            s.prove_std,
            s.verify_mean,
            s.verify_std,
            s.proof_bytes,
            s.peak_delta_mb,
            s.current_mb
        );
        eprintln!(
            "rw_disk,{},{},{:.3},{:.3},{:.4},{:.4},{},{:.3},{:.3}",
            log_n,
            n,
            s.prove_mean,
            s.prove_std,
            s.verify_mean,
            s.verify_std,
            s.proof_bytes,
            s.peak_delta_mb,
            s.current_mb
        );
        rw_stats.push((log_n, s));
    }

    println!();

    // ── ratio summary ─────────────────────────────────────────────────────────
    println!("── Overhead ratio: RW-Groth16 / Standard Groth16 ────────────────");
    println!(
        "{:<6} {:>8}  {:>14}  {:>14}  {:>12}",
        "log N", "N", "prove ratio", "verify ratio", "proof size"
    );
    println!("{}", "─".repeat(58));
    for ((log_n, st), (_, rw)) in std_stats.iter().zip(rw_stats.iter()) {
        let n = 1usize << log_n;
        let prove_r = rw.prove_mean / st.prove_mean;
        let verify_r = rw.verify_mean / st.verify_mean;
        let size_eq = if rw.proof_bytes == st.proof_bytes {
            "identical"
        } else {
            "different"
        };
        println!(
            "{:<6} {:>8}  {:>13.2}×  {:>13.2}×  {:>12}",
            log_n, n, prove_r, verify_r, size_eq
        );
    }

    println!();
    println!("Notes:");
    println!("  prove ratio > 1 → RW-Groth16 is slower (expected: disk I/O overhead)");
    println!("  verify ratio ≈ 1 → verification is identical (same VK, same pairing)");
    println!("  peak_delta ≈ 0 MB for RW-Groth16 → O(log N) working RAM confirmed");
    println!();
    println!(
        "CSV: cargo run --bin compare_bench --release -- {} {} {} 2> cmp.csv",
        log_min, log_max, reps
    );
}
