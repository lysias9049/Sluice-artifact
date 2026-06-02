//! Application-style workload sanity benchmark.
//!
//! This binary builds a field-native MiMC-style Merkle membership workload:
//! many independent Merkle paths, each level compressed by a small MiMC-like
//! permutation over BN254 Fr.  It is not intended as a production hash gadget;
//! its role is external-validity evidence that RW-Groth16 handles structured,
//! application-shaped R1CS instances rather than only independent
//! multiplication gates.
//!
//! Usage:
//!   cargo run --release --bin real_workload_bench -- mimc_merkle 16 20 1 \
//!     2> Experiments/real_workload_mimc_merkle_16_20_r1.csv

use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::SeedableRng, One};

use rw_groth16::{
    file_vec::{io_counters, reset_io_counters, FileVec, FileVecWriter, IoCounters},
    harness::{measure, peak_rss_mb},
    setup::{make_streaming_qap, setup, streaming_setup},
    standard_prover::standard_prove,
    streaming_prover::streaming_prove_rw,
    types::{Proof, Qap},
    verify::verify,
};

const DEFAULT_DEPTH: usize = 8;
const DEFAULT_ROUNDS: usize = 8;

struct Workload {
    qap: Qap<Fr>,
    assignment: Vec<Fr>,
    paths: usize,
    depth: usize,
    rounds: usize,
}

struct Builder {
    u: Vec<(usize, usize, Fr)>,
    v: Vec<(usize, usize, Fr)>,
    w: Vec<(usize, usize, Fr)>,
    assignment: Vec<Fr>,
    row: usize,
}

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

fn proof_size(proof: &Proof<Bn254>) -> usize {
    let mut buf = Vec::new();
    proof.a.serialize_compressed(&mut buf).unwrap();
    proof.b.serialize_compressed(&mut buf).unwrap();
    proof.c.serialize_compressed(&mut buf).unwrap();
    buf.len()
}

impl Builder {
    fn new(n_constraints: usize) -> Self {
        Self {
            u: Vec::with_capacity(3 * n_constraints),
            v: Vec::with_capacity(3 * n_constraints),
            w: Vec::with_capacity(n_constraints),
            assignment: vec![Fr::one()],
            row: 0,
        }
    }

    fn add_var(&mut self, value: Fr) -> usize {
        let idx = self.assignment.len();
        self.assignment.push(value);
        idx
    }

    fn value(&self, terms: &[(usize, Fr)]) -> Fr {
        terms.iter().fold(Fr::zero(), |acc, &(idx, coeff)| {
            acc + self.assignment[idx] * coeff
        })
    }

    fn add_constraint(&mut self, a: &[(usize, Fr)], b: &[(usize, Fr)], c: &[(usize, Fr)]) {
        for &(col, val) in a {
            if !val.is_zero() {
                self.u.push((self.row, col, val));
            }
        }
        for &(col, val) in b {
            if !val.is_zero() {
                self.v.push((self.row, col, val));
            }
        }
        for &(col, val) in c {
            if !val.is_zero() {
                self.w.push((self.row, col, val));
            }
        }
        self.row += 1;
    }

    fn finish(mut self, domain_size: usize) -> Workload {
        self.u.sort_by_key(|&(_, col, _)| col);
        self.v.sort_by_key(|&(_, col, _)| col);
        self.w.sort_by_key(|&(_, col, _)| col);

        let qap = Qap {
            domain_size,
            n_constraints: domain_size,
            n_vars: self.assignment.len(),
            n_pub: 0,
            u: self.u,
            v: self.v,
            w: self.w,
        };
        Workload {
            qap,
            assignment: self.assignment,
            paths: 0,
            depth: DEFAULT_DEPTH,
            rounds: DEFAULT_ROUNDS,
        }
    }
}

fn round_constant(path: usize, level: usize, round: usize) -> Fr {
    Fr::from(17u64 + (path as u64) * 131 + (level as u64) * 257 + (round as u64) * 65537)
}

fn mimc_compress(
    b: &mut Builder,
    path: usize,
    level: usize,
    left_wire: usize,
    right_wire: usize,
    rounds: usize,
) -> usize {
    let mut state_wire = left_wire;
    let right_coeff = Fr::from(7u64);

    for r in 0..rounds {
        let c = round_constant(path, level, r);
        let terms: Vec<(usize, Fr)> = if r == 0 {
            vec![(state_wire, Fr::one()), (right_wire, right_coeff), (0, c)]
        } else {
            vec![(state_wire, Fr::one()), (0, c)]
        };

        let e = b.value(&terms);
        let square_wire = b.add_var(e * e);
        b.add_constraint(&terms, &terms, &[(square_wire, Fr::one())]);

        let cube_wire = b.add_var(e * e * e);
        b.add_constraint(
            &[(square_wire, Fr::one())],
            &terms,
            &[(cube_wire, Fr::one())],
        );

        state_wire = cube_wire;
    }

    state_wire
}

fn add_filler_mul(b: &mut Builder, idx: usize) {
    let a = Fr::from(3u64 + idx as u64);
    let c = Fr::from(5u64 + idx as u64);
    let aw = b.add_var(a);
    let bw = b.add_var(c);
    let cw = b.add_var(a * c);
    b.add_constraint(&[(aw, Fr::one())], &[(bw, Fr::one())], &[(cw, Fr::one())]);
}

fn make_mimc_merkle(domain_log_n: u32, depth: usize, rounds: usize) -> Workload {
    let n = 1usize << domain_log_n;
    let constraints_per_path = depth * rounds * 2;
    let paths = (n / constraints_per_path).max(1);
    let mut b = Builder::new(n);

    for p in 0..paths {
        let leaf = b.add_var(Fr::from(1009u64 + p as u64));
        let mut cur = leaf;
        for level in 0..depth {
            if b.row + rounds * 2 > n {
                break;
            }
            let sibling = b.add_var(Fr::from(9001u64 + (p as u64) * 97 + level as u64));
            cur = mimc_compress(&mut b, p, level, cur, sibling, rounds);
        }
    }

    let mut filler = 0usize;
    while b.row < n {
        add_filler_mul(&mut b, filler);
        filler += 1;
    }

    let mut workload = b.finish(n);
    workload.paths = paths;
    workload.depth = depth;
    workload.rounds = rounds;
    workload
}

fn assignment_fv(assignment: &[Fr]) -> FileVec<Fr> {
    let mut w = FileVecWriter::<Fr>::new().expect("FileVecWriter::new");
    for x in assignment {
        w.write(x).expect("FileVecWriter::write");
    }
    w.finish().expect("FileVecWriter::finish")
}

fn emit_csv(
    meta: &RunMeta,
    workload: &str,
    variant: &str,
    log_n: u32,
    n: usize,
    constraints: usize,
    n_vars: usize,
    paths: usize,
    depth: usize,
    rounds: usize,
    rep: usize,
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
    eprintln!(
        "{},{},{},{},{},{},{},{},{},{},{},{:.1},{:.1},{:.3},{:.1},{:.1},{:.1},{:.1},{},{},{},{},{},{},{},{}",
        workload,
        variant,
        log_n,
        n,
        constraints,
        n_vars,
        paths,
        depth,
        rounds,
        rep,
        setup_ms,
        prove_ms,
        verify_ms,
        setup_peak_rss_mb,
        prove_start_peak_rss_mb,
        prove_end_peak_rss_mb,
        prove_end_peak_rss_mb - prove_start_peak_rss_mb,
        prove_end_peak_rss_mb,
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

fn bench_std(workload_name: &str, log_n: u32, workload: &Workload, repeats: usize, meta: &RunMeta) {
    let stmt: Vec<Fr> = Vec::new();
    let witness = &workload.assignment[1..];
    let mut setup_rng = ark_std::rand::rngs::StdRng::seed_from_u64(0x5354_445f_5150 + log_n as u64);

    let ((pk, vk), t_setup) = measure(|| setup::<Bn254, _>(&workload.qap, &mut setup_rng));
    let setup_ms = t_setup.as_secs_f64() * 1000.0;
    let setup_peak = peak_rss_mb();

    for rep in 0..repeats {
        let mut prove_rng = ark_std::rand::rngs::StdRng::seed_from_u64(
            0x5354_445f_5052 + log_n as u64 * 17 + rep as u64,
        );
        reset_io_counters();
        let rss0 = peak_rss_mb();
        let (proof, t_prove) = measure(|| {
            standard_prove::<Bn254, _>(&workload.qap, &pk, &stmt, witness, &mut prove_rng)
        });
        let rss1 = peak_rss_mb();
        let io = io_counters();
        let (valid, t_verify) = measure(|| verify::<Bn254>(&vk, &stmt, &proof));

        emit_csv(
            meta,
            workload_name,
            "std",
            log_n,
            workload.qap.domain_size,
            workload.qap.n_constraints,
            workload.qap.n_vars,
            workload.paths,
            workload.depth,
            workload.rounds,
            rep,
            setup_ms,
            t_prove.as_secs_f64() * 1000.0,
            t_verify.as_secs_f64() * 1000.0,
            setup_peak,
            rss0,
            rss1,
            proof_size(&proof),
            valid,
            io,
        );
        println!(
            "std log_n={} rep={} prove={:.1}s valid={}",
            log_n,
            rep,
            t_prove.as_secs_f64(),
            valid
        );
    }
}

fn bench_rw(workload_name: &str, log_n: u32, workload: Workload, repeats: usize, meta: &RunMeta) {
    let stmt: Vec<Fr> = Vec::new();
    let mut setup_rng = ark_std::rand::rngs::StdRng::seed_from_u64(0x5257_5150 + log_n as u64);

    let ((spk, vk), t_setup) = measure(|| {
        streaming_setup::<Bn254, _>(&workload.qap, &mut setup_rng).expect("streaming_setup failed")
    });
    let setup_ms = t_setup.as_secs_f64() * 1000.0;
    let setup_peak = peak_rss_mb();
    let sqap = make_streaming_qap(&workload.qap).expect("make_streaming_qap failed");
    let assignment = assignment_fv(&workload.assignment);

    let n = workload.qap.domain_size;
    let constraints = workload.qap.n_constraints;
    let n_vars = workload.qap.n_vars;
    let paths = workload.paths;
    let depth = workload.depth;
    let rounds = workload.rounds;
    drop(workload);

    for rep in 0..repeats {
        let mut prove_rng = ark_std::rand::rngs::StdRng::seed_from_u64(
            0x5257_5052 + log_n as u64 * 17 + rep as u64,
        );
        reset_io_counters();
        let rss0 = peak_rss_mb();
        let (proof, t_prove) = measure(|| {
            streaming_prove_rw::<Bn254, _>(&sqap, &spk, &assignment, &mut prove_rng)
                .expect("streaming_prove_rw failed")
        });
        let rss1 = peak_rss_mb();
        let io = io_counters();
        let (valid, t_verify) = measure(|| verify::<Bn254>(&vk, &stmt, &proof));

        emit_csv(
            meta,
            workload_name,
            "rw_rw",
            log_n,
            n,
            constraints,
            n_vars,
            paths,
            depth,
            rounds,
            rep,
            setup_ms,
            t_prove.as_secs_f64() * 1000.0,
            t_verify.as_secs_f64() * 1000.0,
            setup_peak,
            rss0,
            rss1,
            proof_size(&proof),
            valid,
            io,
        );
        println!(
            "rw_rw log_n={} rep={} prove={:.1}s valid={}",
            log_n,
            rep,
            t_prove.as_secs_f64(),
            valid
        );
    }
}

fn print_header() {
    eprintln!(
        "workload,variant,log_n,n,constraints,n_vars,paths,depth,rounds,rep,setup_ms,prove_ms,verify_ms,setup_peak_rss_mb,prove_start_peak_rss_mb,prove_end_peak_rss_mb,rss_delta_mb,peak_rss_mb,proof_bytes,valid,read_bytes,write_bytes,pass_count,git_commit,machine_id,timestamp"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let workload_name = args.get(0).map(String::as_str).unwrap_or("mimc_merkle");
    let log_min: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(16);
    let log_max: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(log_min);
    let repeats: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);

    if workload_name != "mimc_merkle" {
        eprintln!("unsupported workload: {workload_name}");
        std::process::exit(2);
    }

    let meta = run_meta();
    print_header();
    println!(
        "real workload benchmark: workload={workload_name} log_n={log_min}..{log_max} repeats={repeats}"
    );

    for log_n in log_min..=log_max {
        let workload = make_mimc_merkle(log_n, DEFAULT_DEPTH, DEFAULT_ROUNDS);
        println!(
            "built {workload_name}: log_n={} constraints={} vars={} paths={} depth={} rounds={}",
            log_n,
            workload.qap.n_constraints,
            workload.qap.n_vars,
            workload.paths,
            workload.depth,
            workload.rounds
        );
        bench_std(workload_name, log_n, &workload, repeats, &meta);
        bench_rw(workload_name, log_n, workload, repeats, &meta);
    }
}
