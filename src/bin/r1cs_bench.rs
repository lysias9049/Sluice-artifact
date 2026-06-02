//! R1CS sparse mat-vec 비용 벤치마크
//!
//! Multiply→Sort→Reduce 각 단계를 독립적으로 시간 측정.
//! 각 단계를 5회(기본) 반복 → 중앙값(median) 보고.
//! 두 가지 회로 구조 비교:
//!   - Structured (대각 희소): S = N (행렬당 비영 원소 수)
//!   - Random sparse:          S = N × density  (density = 4 기본)
//!
//! 사용법:
//!   cargo run --bin r1cs_bench --release                  # N = 2^4 ~ 2^14
//!   cargo run --bin r1cs_bench --release -- 16            # N = 2^4 ~ 2^16
//!   cargo run --bin r1cs_bench --release -- 12 8          # log_n_max=12, density=8
//!   cargo run --bin r1cs_bench --release -- 14 4 5        # repeats=5
//!   cargo run --bin r1cs_bench --release -- 14 4 5 2> r1cs_bench.csv
//!
//! 인자: [log_n_max] [density] [repeats]
//!   log_n_max: 최대 N = 2^log_n_max (기본 14)
//!   density:   random 회로의 행렬당 비영 원소 = N × density (기본 4)
//!   repeats:   반복 횟수, 중앙값 채택 (기본 5)

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_std::{test_rng, UniformRand};

use rw_groth16::harness::measure_n;

// ── 타입 ─────────────────────────────────────────────────────────────────────

type R1csMatrix = Vec<(usize, usize, Fr)>; // (row, col, val)

// ── 3단계 재구현 (타이밍 분리) ────────────────────────────────────────────────

/// Phase 1 — Multiply: M·a 의 비영 항 생성.
fn phase_multiply(matrix: &R1csMatrix, witness: &[Fr]) -> Vec<(usize, Fr)> {
    matrix
        .iter()
        .map(|&(row, col, val)| (row, witness[col] * val))
        .collect()
}

/// Phase 2 — LSD Radix Sort: constraint index 기준 정렬.
fn phase_sort(mut pairs: Vec<(usize, Fr)>, key_bits: u32) -> Vec<(usize, Fr)> {
    for b in 0..key_bits {
        let mask = 1usize << b;
        let mut zeros = Vec::new();
        let mut ones = Vec::new();
        for item in pairs {
            if item.0 & mask == 0 {
                zeros.push(item);
            } else {
                ones.push(item);
            }
        }
        zeros.extend(ones);
        pairs = zeros;
    }
    pairs
}

/// Phase 3 — Reduce: 같은 constraint index의 값을 합산.
fn phase_reduce(sorted: Vec<(usize, Fr)>, n: usize) -> Vec<Fr> {
    let mut out = vec![Fr::zero(); n];
    for (row, val) in sorted {
        out[row] += val;
    }
    out
}

// ── 회로 구성 ─────────────────────────────────────────────────────────────────

/// Structured (대각 희소): 제약 i에서 wire 3i+1만 사용. S = N.
fn make_structured(n: usize) -> R1csMatrix {
    (0..n).map(|i| (i, 3 * i + 1, Fr::from(1u64))).collect()
}

/// Random sparse: 각 constraint에 density개의 무작위 wire. S ≈ N × density.
fn make_random_sparse(n: usize, density: usize) -> R1csMatrix {
    let mut rng = test_rng();
    let n_vars = 1 + 3 * n;
    let mut entries: R1csMatrix = Vec::with_capacity(n * density);
    for row in 0..n {
        for _ in 0..density {
            let col = (usize::rand(&mut rng)) % n_vars;
            let val = Fr::rand(&mut rng);
            entries.push((row, col, val));
        }
    }
    // column 기준 정렬 (streaming_matvec 요건)
    entries.sort_by_key(|&(_, col, _)| col);
    entries
}

/// 대응하는 witness 벡터 생성.
fn make_witness(n: usize) -> Vec<Fr> {
    let mut rng = test_rng();
    let n_vars = 1 + 3 * n;
    (0..n_vars).map(|_| Fr::rand(&mut rng)).collect()
}

// ── 단일 측정 함수 ────────────────────────────────────────────────────────────

struct PhaseResult {
    s: usize,         // 비영 원소 수
    multiply_ms: f64, // 중앙값
    sort_ms: f64,     // 중앙값
    reduce_ms: f64,   // 중앙값
    total_ms: f64,
}

fn bench_phases(matrix: &R1csMatrix, witness: &[Fr], n: usize, repeats: usize) -> PhaseResult {
    let key_bits = usize::BITS - n.leading_zeros();
    let s = matrix.len();

    // 각 단계를 독립적으로 repeats 회 반복 → 중앙값
    let (pairs, t_mul) = measure_n(|| phase_multiply(matrix, witness), repeats);
    let (sorted, t_sort) = measure_n(
        || phase_sort(phase_multiply(matrix, witness), key_bits),
        repeats,
    );
    let (_out, t_red) = measure_n(
        || phase_reduce(phase_sort(phase_multiply(matrix, witness), key_bits), n),
        repeats,
    );

    let mul_ms = t_mul.as_secs_f64() * 1000.0;
    let sort_ms = t_sort.as_secs_f64() * 1000.0;
    let red_ms = t_red.as_secs_f64() * 1000.0;

    // 마지막 pairs/sorted 값은 쓰지 않음 (측정 전용 재실행)
    let _ = pairs;
    let _ = sorted;

    PhaseResult {
        s,
        multiply_ms: mul_ms,
        sort_ms: sort_ms,
        reduce_ms: red_ms,
        total_ms: mul_ms + sort_ms + red_ms,
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let log_n_max: u32 = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(14);
    let density: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    let repeats: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);

    println!("=== R1CS Sparse Mat-Vec 비용 벤치마크 ===");
    println!("Curve: BN254   Field: Fr   density(random) = {density}   repeats={repeats} (median)");
    println!();

    // ── Structured (S=N) ──────────────────────────────────────────────────────
    println!("[ Structured 회로 (대각 희소, S = N) ]");
    println!(
        "{:<8} {:>6} {:>12} {:>12} {:>12} {:>12}",
        "N", "S", "mul(ms)", "sort(ms)", "red(ms)", "total(ms)"
    );
    println!("{}", "─".repeat(68));
    eprintln!("type,log_n,n,s,multiply_ms,sort_ms,reduce_ms,total_ms");

    for log_n in 4u32..=log_n_max {
        let n = 1 << log_n;
        let witness = make_witness(n);
        let mat = make_structured(n);
        let r = bench_phases(&mat, &witness, n, repeats);
        println!(
            "{:<8} {:>6} {:>11.3} {:>12.3} {:>12.3} {:>12.3}",
            n, r.s, r.multiply_ms, r.sort_ms, r.reduce_ms, r.total_ms
        );
        eprintln!(
            "structured,{log_n},{n},{},{:.3},{:.3},{:.3},{:.3}",
            r.s, r.multiply_ms, r.sort_ms, r.reduce_ms, r.total_ms
        );
    }

    println!();

    // ── Random Sparse (S = N × density) ──────────────────────────────────────
    println!("[ Random Sparse 회로 (S = N × {density}) ]");
    println!(
        "{:<8} {:>8} {:>12} {:>12} {:>12} {:>12}",
        "N", "S", "mul(ms)", "sort(ms)", "red(ms)", "total(ms)"
    );
    println!("{}", "─".repeat(68));

    for log_n in 4u32..=log_n_max {
        let n = 1 << log_n;
        let witness = make_witness(n);
        let mat = make_random_sparse(n, density);
        let r = bench_phases(&mat, &witness, n, repeats);
        println!(
            "{:<8} {:>8} {:>11.3} {:>12.3} {:>12.3} {:>12.3}",
            n, r.s, r.multiply_ms, r.sort_ms, r.reduce_ms, r.total_ms
        );
        eprintln!(
            "random,{log_n},{n},{},{:.3},{:.3},{:.3},{:.3}",
            r.s, r.multiply_ms, r.sort_ms, r.reduce_ms, r.total_ms
        );
    }

    println!();
    println!(
        "CSV: cargo run --bin r1cs_bench --release -- {log_n_max} {density} 2> r1cs_bench.csv"
    );
}
