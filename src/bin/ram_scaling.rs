//! RAM scaling benchmark: fresh-process peak RSS per (prover, N).
//!
//! Each (prover, N, rep) runs in its own subprocess to avoid lifetime-peak
//! accumulation from prior runs.  The worker exits after one prove call and
//! reports its peak RSS to stdout.
//!
//! Modes
//! ─────
//!   driver (default)
//!       Spawns worker subprocesses for each (prover, log_n, rep), collects
//!       peak RSS values, and prints the comparison table.
//!
//!   worker  --worker <prover> <log_n> <seed>
//!       Runs ONE prove call, then prints "peak_mb,current_mb" to stdout.
//!       <prover> = "std" | "rw"
//!
//! Usage
//! ─────
//!   cargo run --bin ram_scaling --release -- 10 22 3
//!     → N = 2^10 … 2^22,  3 reps each
//!
//!   cargo run --bin ram_scaling --release -- 10 22 3 2> ram_scale.csv
//!     → same, CSV rows to stderr for plotting

use std::process::Command;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_std::{One, UniformRand};

use rw_groth16::{
    harness::{current_rss_mb, peak_rss_mb},
    setup::{setup, streaming_setup},
    standard_prover::standard_prove,
    streaming_prover::streaming_prove_disk,
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

// ── worker mode ───────────────────────────────────────────────────────────────

fn worker_std(log_n: u32, seed: u64) {
    let n = 1usize << log_n;
    let qap = make_qap(n);
    let mut rng = {
        use ark_std::rand::SeedableRng;
        ark_std::rand::rngs::StdRng::seed_from_u64(seed ^ 0xdeadbeef)
    };
    let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);
    let witness = make_witness(n, seed);
    let stmt: Vec<Fr> = vec![];

    // ── record baseline before prove ─────────────────────────────────────────
    let peak0 = peak_rss_mb();
    let cur0 = current_rss_mb();
    let _t0 = Instant::now();

    let proof = standard_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng);

    let peak1 = peak_rss_mb();
    let cur1 = current_rss_mb();

    let ok = verify::<Bn254>(&vk, &stmt, &proof);
    assert!(ok, "std verify failed");

    // peak during prove = max(peak_rss right after prove, current right after prove)
    // peak_delta = growth since baseline
    let peak_delta = peak1 - peak0;
    let cur_max = cur0.max(cur1);

    // Print to stdout for driver to parse
    println!("{:.3},{:.3},{:.3},{:.3}", peak_delta, cur_max, peak1, cur1);
}

fn worker_rw(log_n: u32, seed: u64) {
    let n = 1usize << log_n;
    let qap = make_qap(n);
    let mut rng = {
        use ark_std::rand::SeedableRng;
        ark_std::rand::rngs::StdRng::seed_from_u64(seed ^ 0xcafebabe)
    };
    let (spk, vk) = streaming_setup::<Bn254, _>(&qap, &mut rng).expect("streaming_setup failed");
    let witness = make_witness(n, seed);
    let stmt: Vec<Fr> = vec![];

    let peak0 = peak_rss_mb();
    let cur0 = current_rss_mb();

    let proof = streaming_prove_disk::<Bn254, _>(&qap, &spk, &stmt, &witness, &mut rng)
        .expect("streaming_prove_disk failed");

    let peak1 = peak_rss_mb();
    let cur1 = current_rss_mb();

    let ok = verify::<Bn254>(&vk, &stmt, &proof);
    assert!(ok, "rw verify failed");

    let peak_delta = peak1 - peak0;
    let cur_max = cur0.max(cur1);

    println!("{:.3},{:.3},{:.3},{:.3}", peak_delta, cur_max, peak1, cur1);
}

// ── driver mode ───────────────────────────────────────────────────────────────

fn spawn_worker(exe: &str, prover: &str, log_n: u32, seed: u64) -> Option<(f64, f64, f64, f64)> {
    let out = Command::new(exe)
        .args(["--worker", prover, &log_n.to_string(), &seed.to_string()])
        .output()
        .ok()?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("  worker {prover} log_n={log_n} seed={seed} FAILED: {stderr}");
        return None;
    }

    let s = String::from_utf8_lossy(&out.stdout);
    let s = s.trim();
    let parts: Vec<f64> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    if parts.len() >= 4 {
        Some((parts[0], parts[1], parts[2], parts[3]))
    } else {
        eprintln!("  worker {prover} log_n={log_n} bad output: {s:?}");
        None
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = v.len() / 2;
    if v.len() % 2 == 0 {
        (v[mid - 1] + v[mid]) / 2.0
    } else {
        v[mid]
    }
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn driver(log_min: u32, log_max: u32, reps: usize) {
    // Path to this executable (workers re-use same binary)
    let exe = std::env::current_exe()
        .expect("cannot determine own path")
        .to_string_lossy()
        .into_owned();

    println!("=== RAM Scaling: Standard Groth16 vs RW-Groth16 ===");
    println!("Each data point = separate process (no lifetime-peak contamination)");
    println!("Reps per (prover, N): {reps}   Metric: peak_rss during prove call");
    println!();

    // Theoretical predictions
    println!("Theoretical RAM (field elements only, 32 bytes each):");
    println!("  Standard NTT vectors : ~6 × N × 32 bytes");
    println!("  Streaming I/O buffers: ~256 KB × const  (independent of N)");
    println!("  Crossover N          : ~2^17 (where 6N×32 > const×256KB)");
    println!();

    println!(
        "{:<6} {:>10}  {:>18}  {:>18}  {:>10}",
        "log N", "N", "Std  peak (MB) med", "RW   peak (MB) med", "ratio RW/Std"
    );
    println!("{}", "─".repeat(68));

    // CSV header to stderr
    eprintln!(
        "log_n,n,\
               std_peak_delta_med,std_peak_delta_mean,\
               std_cur_med,std_cur_mean,\
               rw_peak_delta_med,rw_peak_delta_mean,\
               rw_cur_med,rw_cur_mean"
    );

    for log_n in log_min..=log_max {
        let n = 1usize << log_n;

        eprint!("  N=2^{log_n}={n:>7}  std ");
        let mut std_deltas = Vec::new();
        let mut std_peaks = Vec::new();
        for rep in 0..reps {
            eprint!(".");
            if let Some((delta, _cur_max, peak, _cur1)) =
                spawn_worker(&exe, "std", log_n, rep as u64 + 1)
            {
                std_deltas.push(delta);
                std_peaks.push(peak);
            }
        }

        eprint!("  rw ");
        let mut rw_deltas = Vec::new();
        let mut rw_peaks = Vec::new();
        for rep in 0..reps {
            eprint!(".");
            if let Some((delta, _cur_max, peak, _cur1)) =
                spawn_worker(&exe, "rw", log_n, rep as u64 + 1)
            {
                rw_deltas.push(delta);
                rw_peaks.push(peak);
            }
        }
        eprintln!();

        if std_deltas.is_empty() || rw_deltas.is_empty() {
            println!("{:<6} {:>10}  (worker failed)", log_n, n);
            continue;
        }

        let std_d_med = median(std_deltas.clone());
        let std_d_mean = mean(&std_deltas);
        let std_p_med = median(std_peaks.clone());
        let std_p_mean = mean(&std_peaks);

        let rw_d_med = median(rw_deltas.clone());
        let rw_d_mean = mean(&rw_deltas);
        let rw_p_med = median(rw_peaks.clone());
        let rw_p_mean = mean(&rw_peaks);

        // For the table, show peak_delta (RAM growth during prove) as primary metric
        let ratio_delta = if std_d_med > 0.01 {
            rw_d_med / std_d_med
        } else {
            f64::NAN
        };

        println!(
            "{:<6} {:>10}  {:>8.2} MB (Δ{:.2})  {:>8.2} MB (Δ{:.2})  {:>10}",
            log_n,
            n,
            std_p_med,
            std_d_med,
            rw_p_med,
            rw_d_med,
            if ratio_delta.is_nan() {
                "n/a".to_string()
            } else {
                format!("{ratio_delta:.2}×")
            }
        );

        eprintln!(
            "{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
            log_n,
            n,
            std_d_med,
            std_d_mean,
            std_p_med,
            std_p_mean,
            rw_d_med,
            rw_d_mean,
            rw_p_med,
            rw_p_mean
        );
    }

    println!();
    println!("Columns: 'peak (MB)' = total process peak RSS during prove");
    println!("         'Δ...'      = growth vs baseline (before prove)");
    println!("Expected: Std total peak ∝ N for large N;  RW total peak ≈ const");
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Worker mode: --worker <prover> <log_n> <seed>
    if args.first().map(|s| s.as_str()) == Some("--worker") {
        let prover = args.get(1).map(|s| s.as_str()).unwrap_or("std");
        let log_n: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
        let seed: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
        match prover {
            "std" => worker_std(log_n, seed),
            "rw" => worker_rw(log_n, seed),
            other => {
                eprintln!("unknown prover: {other}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Driver mode: [log_min] [log_max] [reps]
    let log_min: u32 = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(10);
    let log_max: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(22);
    let reps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);

    assert!(log_min >= 1 && log_max >= log_min && log_max <= 28);
    driver(log_min, log_max, reps);
}
