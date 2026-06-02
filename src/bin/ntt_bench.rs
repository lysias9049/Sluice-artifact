//! SBM NTT 마이크로벤치마크
//!
//! 각 N에 대해:
//! - RW-NTT vs ark-poly FFT 결과 일치 확인 (correctness)
//! - 5회 반복 측정 → 중앙값(median) 시간 기록
//! - 이론적 pass count = log₂(N) 출력
//! - 이론적 I/O bytes = N × log N × 32 bytes 출력
//!
//! 사용법:
//!   cargo run --bin ntt_bench --release              # N = 2^4 ~ 2^12 (기본)
//!   cargo run --bin ntt_bench --release -- 20        # N = 2^4 ~ 2^20
//!   cargo run --bin ntt_bench --release -- 20 7      # log_n_max=20, repeats=7
//!   cargo run --bin ntt_bench --release -- 20 5 2> ntt_bench.csv

use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::UniformRand;

use rw_groth16::{harness::measure_n, ntt::rw_ntt};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let log_n_max: u32 = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(12);
    let repeats: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let log_n_min: u32 = 4;

    println!("=== SBM NTT Microbenchmark ===");
    println!("Curve: BN254  Field: Fr (254-bit)  repeats={repeats} (median)");
    println!();
    println!(
        "{:<8} {:>8} {:>14} {:>14} {:>8} {:>16} {:>8}",
        "N", "log₂N", "RW-NTT(ms)", "ark-FFT(ms)", "passes", "I/O bytes(th)", "match"
    );
    println!("{}", "─".repeat(82));

    eprintln!("log_n,n,rw_ntt_ms,ark_fft_ms,passes,io_bytes_theory,correct,repeats");

    let mut rng = ark_std::test_rng();

    for log_n in log_n_min..=log_n_max {
        let n = 1usize << log_n;

        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // ── RW-NTT: repeats 회 반복, 중앙값 채택 ───────────────────────────
        let (rw_evals, t_rw) = measure_n(|| rw_ntt(coeffs.clone()), repeats);

        // ── ark-poly FFT: repeats 회 반복, 중앙값 채택 ─────────────────────
        let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
        let (ark_evals, t_ark) = measure_n(|| domain.fft(&coeffs), repeats);

        let correct = rw_evals == ark_evals;
        let passes = log_n;
        let io_bytes_theory = n as u64 * log_n as u64 * 32;

        let rw_ms = t_rw.as_secs_f64() * 1000.0;
        let ark_ms = t_ark.as_secs_f64() * 1000.0;

        println!(
            "{:<8} {:>8} {:>13.3} {:>14.3} {:>8} {:>16} {:>8}",
            n,
            log_n,
            rw_ms,
            ark_ms,
            passes,
            io_bytes_theory,
            if correct { "✓" } else { "✗ FAIL" }
        );

        eprintln!(
            "{},{},{:.3},{:.3},{},{},{},{}",
            log_n, n, rw_ms, ark_ms, passes, io_bytes_theory, correct, repeats
        );

        assert!(correct, "RW-NTT ≠ ark-poly FFT at N={n}");
    }

    println!();
    println!("모든 N에서 RW-NTT == ark-poly FFT 확인 ✓  (중앙값, {repeats}회 반복)");
    println!("CSV: cargo run --bin ntt_bench --release -- {log_n_max} {repeats} 2> ntt_bench.csv");
}
