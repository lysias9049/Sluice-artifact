//! Native arkworks Groth16 baseline for production-oriented memory comparison.
//!
//! This binary builds the same class of structured BN254 field-native
//! MiMC-style Merkle membership workload used by `real_workload_bench`, but
//! proves it through arkworks' native `ark-groth16` implementation.  The goal
//! is not throughput competition with production provers; it is a small,
//! production-like memory-profile comparison against an established Groth16
//! implementation.
//!
//! Usage:
//!   cargo build --release --bin production_baseline_bench
//!   target/release/production_baseline_bench mimc_merkle 16 18 1 \
//!     2> Experiments/production_baseline_arkworks_16_18_r1.csv

use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::{prepare_verifying_key, Groth16, Proof};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;

use rw_groth16::harness::{measure, peak_rss_mb};

const DEFAULT_DEPTH: usize = 8;
const DEFAULT_ROUNDS: usize = 8;

#[derive(Clone, Copy)]
struct Wire {
    var: Variable,
    value: Fr,
}

#[derive(Clone)]
struct MimcMerkleCircuit {
    log_n: u32,
    depth: usize,
    rounds: usize,
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

fn round_constant(path: usize, level: usize, round: usize) -> Fr {
    Fr::from(17u64 + (path as u64) * 131 + (level as u64) * 257 + (round as u64) * 65537)
}

fn workload_shape(log_n: u32, depth: usize, rounds: usize) -> (usize, usize) {
    let constraints = 1usize << log_n;
    let constraints_per_path = depth * rounds * 2;
    let paths = (constraints / constraints_per_path).max(1);
    (constraints, paths)
}

impl MimcMerkleCircuit {
    fn new(log_n: u32, depth: usize, rounds: usize) -> Self {
        Self {
            log_n,
            depth,
            rounds,
        }
    }

    fn alloc_witness(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result<Wire, SynthesisError> {
        let var = cs.new_witness_variable(|| Ok(value))?;
        Ok(Wire { var, value })
    }

    fn mimc_compress(
        cs: &ConstraintSystemRef<Fr>,
        path: usize,
        level: usize,
        left: Wire,
        right: Wire,
        rounds: usize,
    ) -> Result<(Wire, usize), SynthesisError> {
        let mut state = left;
        let right_coeff = Fr::from(7u64);
        let mut constraints = 0usize;

        for r in 0..rounds {
            let c = round_constant(path, level, r);
            let (e_value, e_lc) = if r == 0 {
                (
                    state.value + right.value * right_coeff + c,
                    lc!() + state.var + (right_coeff, right.var) + (c, Variable::One),
                )
            } else {
                (state.value + c, lc!() + state.var + (c, Variable::One))
            };

            let square = Self::alloc_witness(cs, e_value.square())?;
            cs.enforce_constraint(e_lc.clone(), e_lc.clone(), lc!() + square.var)?;
            constraints += 1;

            let cube = Self::alloc_witness(cs, e_value.square() * e_value)?;
            cs.enforce_constraint(lc!() + square.var, e_lc, lc!() + cube.var)?;
            constraints += 1;

            state = cube;
        }

        Ok((state, constraints))
    }

    fn add_filler_mul(cs: &ConstraintSystemRef<Fr>, idx: usize) -> Result<(), SynthesisError> {
        let a = Fr::from(3u64 + idx as u64);
        let b = Fr::from(5u64 + idx as u64);
        let aw = Self::alloc_witness(cs, a)?;
        let bw = Self::alloc_witness(cs, b)?;
        let cw = Self::alloc_witness(cs, a * b)?;
        cs.enforce_constraint(lc!() + aw.var, lc!() + bw.var, lc!() + cw.var)?;
        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for MimcMerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let (target_constraints, paths) = workload_shape(self.log_n, self.depth, self.rounds);
        let mut rows = 0usize;

        for p in 0..paths {
            if rows + self.depth * self.rounds * 2 > target_constraints {
                break;
            }
            let leaf = Self::alloc_witness(&cs, Fr::from(1009u64 + p as u64))?;
            let mut cur = leaf;

            for level in 0..self.depth {
                if rows + self.rounds * 2 > target_constraints {
                    break;
                }
                let sibling =
                    Self::alloc_witness(&cs, Fr::from(9001u64 + (p as u64) * 97 + level as u64))?;
                let (next, used) = Self::mimc_compress(&cs, p, level, cur, sibling, self.rounds)?;
                rows += used;
                cur = next;
            }
        }

        let mut filler = 0usize;
        while rows < target_constraints {
            Self::add_filler_mul(&cs, filler)?;
            rows += 1;
            filler += 1;
        }

        Ok(())
    }
}

fn print_header() {
    eprintln!(
        "baseline,workload,log_n,n,constraints,paths,depth,rounds,rep,setup_ms,prove_ms,verify_ms,setup_peak_rss_mb,prove_start_peak_rss_mb,prove_end_peak_rss_mb,rss_delta_mb,peak_rss_mb,proof_bytes,valid,git_commit,machine_id,timestamp"
    );
}

fn emit_csv(
    meta: &RunMeta,
    workload: &str,
    log_n: u32,
    constraints: usize,
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
) {
    eprintln!(
        "arkworks_groth16,{},{},{},{},{},{},{},{},{:.1},{:.1},{:.3},{:.1},{:.1},{:.1},{:.1},{:.1},{},{},{},{},{}",
        workload,
        log_n,
        1usize << log_n,
        constraints,
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
        meta.git_commit,
        meta.machine_id,
        unix_timestamp()
    );
}

fn run_one(workload_name: &str, log_n: u32, repeats: usize, meta: &RunMeta) {
    let (constraints, paths) = workload_shape(log_n, DEFAULT_DEPTH, DEFAULT_ROUNDS);
    let mut setup_rng = ark_std::rand::rngs::StdRng::seed_from_u64(0x4152_4b5f_5354 + log_n as u64);
    let setup_circuit = MimcMerkleCircuit::new(log_n, DEFAULT_DEPTH, DEFAULT_ROUNDS);

    let (pk, t_setup) = measure(|| {
        Groth16::<Bn254>::generate_random_parameters_with_reduction(setup_circuit, &mut setup_rng)
            .expect("arkworks Groth16 setup failed")
    });
    let vk = pk.vk.clone();
    let pvk = prepare_verifying_key(&vk);
    let setup_ms = t_setup.as_secs_f64() * 1000.0;
    let setup_peak = peak_rss_mb();

    for rep in 0..repeats {
        let mut prove_rng = ark_std::rand::rngs::StdRng::seed_from_u64(
            0x4152_4b5f_5052 + log_n as u64 * 17 + rep as u64,
        );
        let prove_circuit = MimcMerkleCircuit::new(log_n, DEFAULT_DEPTH, DEFAULT_ROUNDS);
        let rss0 = peak_rss_mb();
        let (proof, t_prove) = measure(|| {
            Groth16::<Bn254>::create_random_proof_with_reduction(prove_circuit, &pk, &mut prove_rng)
                .expect("arkworks Groth16 prove failed")
        });
        let rss1 = peak_rss_mb();
        let (valid, t_verify) = measure(|| {
            Groth16::<Bn254>::verify_proof(&pvk, &proof, &[])
                .expect("arkworks Groth16 verify failed")
        });

        emit_csv(
            meta,
            workload_name,
            log_n,
            constraints,
            paths,
            DEFAULT_DEPTH,
            DEFAULT_ROUNDS,
            rep,
            setup_ms,
            t_prove.as_secs_f64() * 1000.0,
            t_verify.as_secs_f64() * 1000.0,
            setup_peak,
            rss0,
            rss1,
            proof_size(&proof),
            valid,
        );

        println!(
            "arkworks_groth16 log_n={} rep={} prove={:.1}s valid={}",
            log_n,
            rep,
            t_prove.as_secs_f64(),
            valid
        );
    }
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
        "arkworks production baseline: workload={workload_name} log_n={log_min}..{log_max} repeats={repeats}"
    );

    for log_n in log_min..=log_max {
        let (constraints, paths) = workload_shape(log_n, DEFAULT_DEPTH, DEFAULT_ROUNDS);
        println!(
            "built {workload_name}: log_n={} constraints={} paths={} depth={} rounds={}",
            log_n, constraints, paths, DEFAULT_DEPTH, DEFAULT_ROUNDS
        );
        run_one(workload_name, log_n, repeats, &meta);
    }
}
