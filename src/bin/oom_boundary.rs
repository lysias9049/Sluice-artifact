//! OOM boundary experiment: which N causes OOM at a given memory limit?
//!
//! For each (prover, memory_limit_MB, N), spawns a worker subprocess with
//! RLIMIT_AS set to `limit_mb` MB.  If the worker exits with a non-zero code
//! the prover ran out of memory (OOM) for that N.
//!
//! Usage (macOS / Linux only — setrlimit not available on Windows):
//!
//!   # sweep N=2^10..2^20 with limits [64, 128, 256, 512] MB
//!   cargo run --bin oom_boundary --release
//!
//!   # custom range and limits
//!   cargo run --bin oom_boundary --release -- 10 20 64,128,256,512
//!
//!   # CSV to file
//!   cargo run --bin oom_boundary --release -- 10 20 64,256 2> oom.csv
//!
//! Worker mode (internal, spawned by the driver):
//!   oom_boundary --worker <prover> <log_n> <seed> <limit_mb>

use std::process::Command;

use ark_bn254::{Bn254, Fr};
use ark_std::{One, UniformRand};

use rw_groth16::{
    harness::set_address_space_limit,
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

// ── worker ────────────────────────────────────────────────────────────────────

fn worker(prover: &str, log_n: u32, seed: u64, limit_mb: u64) {
    // Apply memory limit BEFORE any large allocations.
    if limit_mb > 0 {
        let ok = set_address_space_limit(limit_mb * 1024 * 1024);
        if !ok {
            eprintln!("set_address_space_limit failed (platform not supported?)");
        }
    }

    let n = 1usize << log_n;
    let qap = make_qap(n);
    let mut rng = {
        use ark_std::rand::SeedableRng;
        ark_std::rand::rngs::StdRng::seed_from_u64(seed ^ 0xdead)
    };
    let witness = make_witness(n, seed);
    let stmt: Vec<Fr> = vec![];

    match prover {
        "std" => {
            let (pk, vk) = setup::<Bn254, _>(&qap, &mut rng);
            let proof = standard_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng);
            assert!(verify::<Bn254>(&vk, &stmt, &proof));
            println!("ok");
        }
        "rw" => {
            let (spk, vk) =
                streaming_setup::<Bn254, _>(&qap, &mut rng).expect("streaming_setup failed");
            let proof = streaming_prove_disk::<Bn254, _>(&qap, &spk, &stmt, &witness, &mut rng)
                .expect("streaming_prove_disk failed");
            assert!(verify::<Bn254>(&vk, &stmt, &proof));
            println!("ok");
        }
        _ => {
            eprintln!("unknown prover: {prover}");
            std::process::exit(1);
        }
    }
}

// ── driver ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Oom,
    Error,
}

impl Outcome {
    fn symbol(self) -> &'static str {
        match self {
            Outcome::Ok => "✓ OK",
            Outcome::Oom => "✗ OOM",
            Outcome::Error => "? ERR",
        }
    }
    fn csv(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Oom => "oom",
            Outcome::Error => "err",
        }
    }
}

fn run_worker(exe: &str, prover: &str, log_n: u32, seed: u64, limit_mb: u64) -> Outcome {
    match Command::new(exe)
        .args([
            "--worker",
            prover,
            &log_n.to_string(),
            &seed.to_string(),
            &limit_mb.to_string(),
        ])
        .output()
    {
        Err(_) => Outcome::Error,
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if out.status.success() && stdout.trim() == "ok" {
                Outcome::Ok
            } else {
                // Non-zero exit = OOM (Rust allocator abort) or other crash
                Outcome::Oom
            }
        }
    }
}

fn driver(log_min: u32, log_max: u32, limits_mb: Vec<u64>) {
    let exe = std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    println!("=== OOM Boundary: Standard Groth16 vs RW-Groth16 ===");
    println!("Memory limits tested: {:?} MB", limits_mb);
    println!("✓ OK = proof succeeded   ✗ OOM = allocation failed");
    println!();

    // CSV header
    eprintln!("prover,log_n,n,limit_mb,outcome");

    for &limit_mb in &limits_mb {
        println!(
            "── Memory limit: {} MB ────────────────────────────────",
            limit_mb
        );
        println!(
            "{:<6} {:>8}  {:>14}  {:>14}",
            "log N", "N", "Standard", "RW-Groth16"
        );
        println!("{}", "─".repeat(48));

        for log_n in log_min..=log_max {
            let n = 1usize << log_n;

            let std_out = run_worker(&exe, "std", log_n, 1, limit_mb);
            let rw_out = run_worker(&exe, "rw", log_n, 1, limit_mb);

            let marker = if std_out == Outcome::Oom && rw_out == Outcome::Ok {
                " ← RW wins"
            } else if std_out == Outcome::Ok && rw_out == Outcome::Oom {
                " ← std wins(?)"
            } else {
                ""
            };

            println!(
                "{:<6} {:>8}  {:>14}  {:>14}{}",
                log_n,
                n,
                std_out.symbol(),
                rw_out.symbol(),
                marker
            );

            eprintln!("standard,{},{},{},{}", log_n, n, limit_mb, std_out.csv());
            eprintln!("rw,{},{},{},{}", log_n, n, limit_mb, rw_out.csv());
        }
        println!();
    }

    println!("Notes:");
    println!("  OOM boundary = smallest N where the prover fails.");
    println!("  RW-Groth16 should survive at larger N than Standard Groth16.");
    println!("  Both need ~10-15 MB baseline (Rust runtime + crypto libs).");
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Worker mode
    if args.first().map(|s| s.as_str()) == Some("--worker") {
        let prover = args.get(1).map(|s| s.as_str()).unwrap_or("std");
        let log_n: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
        let seed: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
        let limit: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
        worker(prover, log_n, seed, limit);
        return;
    }

    // Driver mode
    let log_min: u32 = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(10);
    let log_max: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let limits_mb: Vec<u64> = args
        .get(2)
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![64, 128, 256, 512]);

    driver(log_min, log_max, limits_mb);
}
