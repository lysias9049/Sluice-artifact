//! Scalability benchmark: standard, partially streaming, and fully streaming provers.
//!
//! 사용법:
//!   cargo run --bin streaming_bench --release                     # Vec-CRS, 2^10 ~ 2^20
//!   cargo run --bin streaming_bench --release -- 10 20            # Vec-CRS, 2^10 ~ 2^20
//!   cargo run --bin streaming_bench --release -- 10 24 disk       # RW-File: CRS on disk
//!   cargo run --bin streaming_bench --release -- 10 24 rw         # RW-RW: QAP+witness+CRS on disk
//!   cargo run --bin streaming_bench --release -- 10 24 disk 2> s.csv
//!
//! 모드:
//!   (기본 / "vec")  setup + streaming_prove          — CRS in RAM Vec, O(N) RAM
//!   "disk"          streaming_setup + streaming_prove_disk — CRS on disk; QAP/witness caller RAM
//!   "rw"            streaming_setup + streaming_prove_rw   — QAP+witness+CRS on disk
//!
//! 회로: N개 곱셈 게이트 (aᵢ · bᵢ = cᵢ, 모두 private)

use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use ark_std::{One, UniformRand};

use rw_groth16::{
    file_vec::{io_counters, reset_io_counters, FileVec, FileVecWriter, IoCounters},
    harness::{measure, peak_rss_mb},
    setup::{make_streaming_qap, setup, streaming_setup},
    standard_prover::standard_prove,
    streaming_prover::{streaming_prove, streaming_prove_disk, streaming_prove_rw},
    types::Qap,
    verify::verify,
};

struct RunMeta {
    git_commit: String,
    machine_id: String,
}

fn command_output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

fn run_meta() -> RunMeta {
    let git_commit = command_output("git", &["rev-parse", "--short", "HEAD"])
        .unwrap_or_else(|| "unknown".to_owned());
    let machine_id = if std::env::var("RWG_RECORD_MACHINE_ID").ok().as_deref() == Some("1") {
        std::env::var("HOSTNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| command_output("hostname", &[]))
            .unwrap_or_else(|| "unknown".to_owned())
    } else {
        "artifact-host".to_owned()
    };
    RunMeta {
        git_commit,
        machine_id,
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn emit_csv(
    meta: &RunMeta,
    variant: &str,
    log_n: u32,
    n: usize,
    setup_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    setup_peak_rss_mb: f64,
    prove_start_peak_rss_mb: f64,
    prove_end_peak_rss_mb: f64,
    proof_bytes: usize,
    valid: bool,
    io: IoCounters,
) {
    let rss_delta_mb = prove_end_peak_rss_mb - prove_start_peak_rss_mb;
    let peak_rss_mb = prove_end_peak_rss_mb;
    eprintln!(
        "{},{},{},{:.1},{:.1},{:.3},{:.1},{:.1},{:.1},{:.1},{:.1},{},{},{},{},{},{},{},{}",
        variant,
        log_n,
        n,
        setup_ms,
        prove_ms,
        verify_ms,
        setup_peak_rss_mb,
        prove_start_peak_rss_mb,
        prove_end_peak_rss_mb,
        rss_delta_mb,
        peak_rss_mb,
        proof_bytes,
        valid,
        io.read_bytes,
        io.write_bytes,
        io.total_streams(),
        meta.git_commit,
        meta.machine_id,
        unix_timestamp()
    );
}

// ── 회로 ─────────────────────────────────────────────────────────────────────

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

// ── Standard Groth16 mode (ark-poly FFT, CRS in RAM, O(N) RAM) ───────────────

fn run_one_std(log_n: u32, meta: &RunMeta) {
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let qap = make_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    // Setup (CRS in RAM Vec) — same key as Vec mode
    let ((pk, vk), t_setup) = measure(|| setup::<Bn254, _>(&qap, &mut rng));
    let setup_ms = t_setup.as_secs_f64() * 1000.0;
    let setup_peak = peak_rss_mb();

    // ── standard_prove (ark-poly in-memory FFT) ──────────────────────────────
    reset_io_counters();
    let rss0 = peak_rss_mb();
    let (proof, t_prove) =
        measure(|| standard_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng));
    let rss1 = peak_rss_mb();
    let io = io_counters();

    // ── verify ───────────────────────────────────────────────────────────────
    let (valid, t_verify) = measure(|| verify::<Bn254>(&vk, &stmt, &proof));

    // ── proof size ───────────────────────────────────────────────────────────
    let mut buf = Vec::new();
    proof.a.serialize_compressed(&mut buf).unwrap();
    proof.b.serialize_compressed(&mut buf).unwrap();
    proof.c.serialize_compressed(&mut buf).unwrap();
    let proof_bytes = buf.len();

    let prove_ms = t_prove.as_secs_f64() * 1000.0;
    let verify_ms = t_verify.as_secs_f64() * 1000.0;
    let rss_delta = rss1 - rss0;

    println!(
        "{:<10} {:>6} {:>14.1} {:>12.3} {:>14.1} {:>8}",
        n,
        log_n,
        prove_ms,
        verify_ms,
        rss_delta,
        if valid { "✓" } else { "✗ FAIL" }
    );
    emit_csv(
        meta,
        "std",
        log_n,
        n,
        setup_ms,
        prove_ms,
        verify_ms,
        setup_peak,
        rss0,
        rss1,
        proof_bytes,
        valid,
        io,
    );
}

// ── Vec-CRS mode (original) ───────────────────────────────────────────────────

fn run_one_vec(log_n: u32, meta: &RunMeta) {
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let qap = make_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    // Setup (CRS in RAM Vec)
    let ((pk, vk), t_setup) = measure(|| setup::<Bn254, _>(&qap, &mut rng));
    let setup_ms = t_setup.as_secs_f64() * 1000.0;
    let setup_peak = peak_rss_mb();

    // ── streaming_prove ──────────────────────────────────────────────────────
    reset_io_counters();
    let rss0 = peak_rss_mb();
    let (proof_result, t_prove) =
        measure(|| streaming_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng));
    let rss1 = peak_rss_mb();
    let io = io_counters();
    let proof = proof_result.expect("streaming_prove failed");

    // ── verify ───────────────────────────────────────────────────────────────
    let (valid, t_verify) = measure(|| verify::<Bn254>(&vk, &stmt, &proof));

    // ── proof size ───────────────────────────────────────────────────────────
    let mut buf = Vec::new();
    proof.a.serialize_compressed(&mut buf).unwrap();
    proof.b.serialize_compressed(&mut buf).unwrap();
    proof.c.serialize_compressed(&mut buf).unwrap();
    let proof_bytes = buf.len();

    let prove_ms = t_prove.as_secs_f64() * 1000.0;
    let verify_ms = t_verify.as_secs_f64() * 1000.0;
    let rss_delta = rss1 - rss0;
    let valid_str = if valid { "✓" } else { "✗ FAIL" };

    println!(
        "{:<10} {:>6} {:>14.1} {:>12.3} {:>14.1} {:>8}",
        n, log_n, prove_ms, verify_ms, rss_delta, valid_str
    );
    emit_csv(
        meta,
        "rw_vec",
        log_n,
        n,
        setup_ms,
        prove_ms,
        verify_ms,
        setup_peak,
        rss0,
        rss1,
        proof_bytes,
        valid,
        io,
    );
}

// ── Disk-CRS mode (streaming_setup + streaming_prove_disk) ───────────────────

fn run_one_disk(log_n: u32, meta: &RunMeta) {
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let qap = make_qap(n);
    let witness = make_witness(n, &mut rng);
    let stmt: Vec<Fr> = vec![];

    // streaming_setup: CRS arrays written element-by-element to FileVec (disk)
    let rss_pre_setup = peak_rss_mb();
    let ((spk, vk), t_setup) =
        measure(|| streaming_setup::<Bn254, _>(&qap, &mut rng).expect("streaming_setup failed"));
    let rss_post_setup = peak_rss_mb();
    let setup_ms = t_setup.as_secs_f64() * 1000.0;
    let setup_delta = rss_post_setup - rss_pre_setup;

    eprintln!(
        "# setup: {:.1} ms  rss_delta: {:.1} MB  peak: {:.1} MB",
        setup_ms, setup_delta, rss_post_setup
    );

    // ── streaming_prove_disk ─────────────────────────────────────────────────
    reset_io_counters();
    let rss0 = peak_rss_mb();
    let (proof_result, t_prove) =
        measure(|| streaming_prove_disk::<Bn254, _>(&qap, &spk, &stmt, &witness, &mut rng));
    let rss1 = peak_rss_mb();
    let io = io_counters();
    let proof = proof_result.expect("streaming_prove_disk failed");

    // ── verify ───────────────────────────────────────────────────────────────
    let (valid, t_verify) = measure(|| verify::<Bn254>(&vk, &stmt, &proof));

    // ── proof size ───────────────────────────────────────────────────────────
    let mut buf = Vec::new();
    proof.a.serialize_compressed(&mut buf).unwrap();
    proof.b.serialize_compressed(&mut buf).unwrap();
    proof.c.serialize_compressed(&mut buf).unwrap();
    let proof_bytes = buf.len();

    let prove_ms = t_prove.as_secs_f64() * 1000.0;
    let verify_ms = t_verify.as_secs_f64() * 1000.0;
    let rss_delta = rss1 - rss0;
    let valid_str = if valid { "✓" } else { "✗ FAIL" };

    println!(
        "{:<10} {:>6} {:>14.1} {:>12.3} {:>14.1} {:>8}",
        n, log_n, prove_ms, verify_ms, rss_delta, valid_str
    );
    emit_csv(
        meta,
        "rw_file",
        log_n,
        n,
        setup_ms,
        prove_ms,
        verify_ms,
        rss_post_setup,
        rss0,
        rss1,
        proof_bytes,
        valid,
        io,
    );
}

// ── Fully RW streaming mode (QAP+witness+CRS all on disk) ────────────────────

fn make_assignment_fv(n: usize, rng: &mut impl ark_std::rand::Rng) -> FileVec<Fr> {
    use ark_std::{One, UniformRand};
    let mut w = FileVecWriter::<Fr>::new().expect("FileVecWriter::new");
    w.write(&Fr::one()).unwrap();
    for _ in 0..n {
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        w.write(&a).unwrap();
        w.write(&b).unwrap();
        w.write(&(a * b)).unwrap();
    }
    w.finish().expect("FileVecWriter::finish")
}

fn run_one_rw(log_n: u32, meta: &RunMeta) {
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let qap = make_qap(n);
    let stmt: Vec<Fr> = vec![];

    // Setup (CRS to disk)
    let rss_pre_setup = peak_rss_mb();
    let ((spk, vk), t_setup) =
        measure(|| streaming_setup::<Bn254, _>(&qap, &mut rng).expect("streaming_setup failed"));
    let rss_post_setup = peak_rss_mb();
    let setup_ms = t_setup.as_secs_f64() * 1000.0;
    eprintln!(
        "# setup: {:.1} ms  rss_delta: {:.1} MB  peak: {:.1} MB",
        setup_ms,
        rss_post_setup - rss_pre_setup,
        rss_post_setup
    );

    // QAP to disk, drop in-memory copy
    let sqap = make_streaming_qap(&qap).expect("make_streaming_qap failed");
    drop(qap);

    // Assignment (witness) generated directly on disk — never in RAM
    let assignment_fv = make_assignment_fv(n, &mut rng);

    // Prove: fully RW streaming
    reset_io_counters();
    let rss0 = peak_rss_mb();
    let (proof, t_prove) = measure(|| {
        streaming_prove_rw::<Bn254, _>(&sqap, &spk, &assignment_fv, &mut rng)
            .expect("streaming_prove_rw failed")
    });
    let rss1 = peak_rss_mb();
    let io = io_counters();

    let (valid, t_verify) = measure(|| verify::<Bn254>(&vk, &stmt, &proof));

    let mut buf = Vec::new();
    proof.a.serialize_compressed(&mut buf).unwrap();
    proof.b.serialize_compressed(&mut buf).unwrap();
    proof.c.serialize_compressed(&mut buf).unwrap();
    let proof_bytes = buf.len();

    let prove_ms = t_prove.as_secs_f64() * 1000.0;
    let verify_ms = t_verify.as_secs_f64() * 1000.0;
    let rss_delta = rss1 - rss0;

    println!(
        "{:<10} {:>6} {:>14.1} {:>12.3} {:>14.1} {:>8}",
        n,
        log_n,
        prove_ms,
        verify_ms,
        rss_delta,
        if valid { "✓" } else { "✗ FAIL" }
    );
    emit_csv(
        meta,
        "rw_rw",
        log_n,
        n,
        setup_ms,
        prove_ms,
        verify_ms,
        rss_post_setup,
        rss0,
        rss1,
        proof_bytes,
        valid,
        io,
    );
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let log_n_min: u32 = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(10);
    let log_n_max: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let mode = args.get(2).map(|s| s.as_str()).unwrap_or("vec");

    assert!(log_n_min >= 1, "log_n_min must be ≥ 1");
    assert!(log_n_max >= log_n_min, "log_n_max must be ≥ log_n_min");
    assert!(log_n_max <= 30, "log_n_max > 30 is unreasonably large");

    let mode_disk = mode == "disk";
    let mode_std = mode == "std";
    let mode_rw = mode == "rw";
    let meta = run_meta();

    println!("=== RW-Groth16 Streaming Prover — Scalability Benchmark ===");
    println!("Curve: BN254   Field: Fr (254-bit)");
    if mode_disk {
        println!("Mode: DISK  (streaming_setup + streaming_prove_disk)");
        println!("RW-File: CRS on disk; QAP and witness are caller-owned RAM inputs.");
    } else if mode_std {
        println!("Mode: STD   (setup + standard_prove)");
        println!("Standard Groth16.  ark-poly in-memory FFT.  CRS in RAM.  O(N) RAM.");
    } else if mode_rw {
        println!("Mode: RW    (streaming_setup + make_streaming_qap + streaming_prove_rw)");
        println!("QAP+CRS+Witness all on disk.  True O(log N) RAM ★★");
    } else {
        println!("Mode: VEC   (setup + streaming_prove)");
        println!("CRS in RAM Vec.  NTT intermediates → disk (FileVec).  O(N) RAM.");
    }
    println!();
    println!(
        "{:<10} {:>6} {:>14} {:>12} {:>14} {:>8}",
        "N", "log₂N", "prove(ms)", "verify(ms)", "RSS_delta(MB)", "valid"
    );
    println!("{}", "─".repeat(68));

    // CSV header to stderr
    eprintln!(
        "variant,log_n,n,setup_ms,prove_ms,verify_ms,\
         setup_peak_rss_mb,prove_start_peak_rss_mb,prove_end_peak_rss_mb,\
         rss_delta_mb,peak_rss_mb,proof_bytes,valid,read_bytes,write_bytes,\
         pass_count,git_commit,machine_id,timestamp"
    );

    for log_n in log_n_min..=log_n_max {
        if mode_disk {
            run_one_disk(log_n, &meta);
        } else if mode_std {
            run_one_std(log_n, &meta);
        } else if mode_rw {
            run_one_rw(log_n, &meta);
        } else {
            run_one_vec(log_n, &meta);
        }
    }

    println!();
    if mode_disk {
        println!(
            "완료.  CSV: cargo run --bin streaming_bench --release -- {} {} disk 2> disk.csv",
            log_n_min, log_n_max
        );
    } else if mode_rw {
        println!(
            "완료.  CSV: cargo run --bin streaming_bench --release -- {} {} rw 2> rw.csv",
            log_n_min, log_n_max
        );
    } else if mode_std {
        println!(
            "완료.  CSV: cargo run --bin streaming_bench --release -- {} {} std 2> std.csv",
            log_n_min, log_n_max
        );
    } else {
        println!(
            "완료.  CSV: cargo run --bin streaming_bench --release -- {} {} vec 2> vec.csv",
            log_n_min, log_n_max
        );
    }
}
