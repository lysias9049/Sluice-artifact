//! Prove-only RSS experiment for the fully streaming RW-RW prover.
//!
//! Driver mode materializes setup/QAP/witness files in one process, then spawns
//! a fresh prove-only worker that reopens those files and runs only
//! `streaming_prove_rw`.  The resulting CSV therefore measures the prove
//! process' clean peak RSS without setup's monotone `ru_maxrss` high-water mark.
//!
//! Usage:
//!   cargo build --release --bin rw_prove_only
//!   target/release/rw_prove_only 23 Experiments/rw_prove_only_23_data \
//!       Experiments/rw_prove_only_23.csv

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::SeedableRng, One, UniformRand};

use rw_groth16::{
    file_vec::{
        io_counters, reset_io_counters, FileVec, FileVecWriter, G1Disk, G2Disk, MatrixEntry,
    },
    harness::{measure, peak_rss_mb, set_address_space_limit},
    setup::{make_streaming_qap, streaming_setup},
    streaming_prover::streaming_prove_rw,
    types::{Proof, Qap, StreamingProvingKey, StreamingQap, VerifyingKey},
    verify::verify,
};

const SETUP_SEED: u64 = 0x5355_5045_525f_5257;
const PROVE_SEED: u64 = 0x5052_4f56_455f_5257;

struct RunMeta {
    git_commit: String,
    machine_id: String,
}

struct SmallData {
    g1_alpha: G1Affine,
    g1_beta: G1Affine,
    g1_delta: G1Affine,
    g2_beta: G2Affine,
    g2_delta: G2Affine,
    vk_alpha_g1: G1Affine,
    vk_beta_g2: G2Affine,
    vk_gamma_g2: G2Affine,
    vk_delta_g2: G2Affine,
    vk_gamma_abc_g1: Vec<G1Affine>,
}

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

fn make_assignment_fv(n: usize, rng: &mut impl ark_std::rand::Rng) -> io::Result<FileVec<Fr>> {
    let mut w = FileVecWriter::<Fr>::new()?;
    w.write(&Fr::one())?;
    for _ in 0..n {
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        w.write(&a)?;
        w.write(&b)?;
        w.write(&(a * b))?;
    }
    w.finish()
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
    let git_commit = std::env::var("RWG_SOURCE_REVISION").ok()
        .or_else(|| command_output("git", &["rev-parse", "--short", "HEAD"]))
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

fn path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

fn copy_fv<T: rw_groth16::file_vec::StreamElem>(
    fv: &FileVec<T>,
    dir: &Path,
    name: &str,
) -> io::Result<()> {
    fv.copy_to_path(path(dir, name))
}

fn write_u64(w: &mut impl Write, x: u64) -> io::Result<()> {
    w.write_all(&x.to_le_bytes())
}

fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn serialize_uncompressed<T: CanonicalSerialize>(w: &mut impl Write, x: &T) -> io::Result<()> {
    x.serialize_uncompressed(w)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

fn deserialize_g1(r: &mut impl Read) -> io::Result<G1Affine> {
    G1Affine::deserialize_uncompressed_unchecked(r)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

fn deserialize_g2(r: &mut impl Read) -> io::Result<G2Affine> {
    G2Affine::deserialize_uncompressed_unchecked(r)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

fn write_small(
    path: &Path,
    spk: &StreamingProvingKey<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    serialize_uncompressed(&mut w, &spk.g1_alpha)?;
    serialize_uncompressed(&mut w, &spk.g1_beta)?;
    serialize_uncompressed(&mut w, &spk.g1_delta)?;
    serialize_uncompressed(&mut w, &spk.g2_beta)?;
    serialize_uncompressed(&mut w, &spk.g2_delta)?;
    serialize_uncompressed(&mut w, &vk.alpha_g1)?;
    serialize_uncompressed(&mut w, &vk.beta_g2)?;
    serialize_uncompressed(&mut w, &vk.gamma_g2)?;
    serialize_uncompressed(&mut w, &vk.delta_g2)?;
    write_u64(&mut w, vk.gamma_abc_g1.len() as u64)?;
    for x in &vk.gamma_abc_g1 {
        serialize_uncompressed(&mut w, x)?;
    }
    w.flush()
}

fn read_small(path: &Path) -> io::Result<SmallData> {
    let mut r = BufReader::new(File::open(path)?);
    let g1_alpha = deserialize_g1(&mut r)?;
    let g1_beta = deserialize_g1(&mut r)?;
    let g1_delta = deserialize_g1(&mut r)?;
    let g2_beta = deserialize_g2(&mut r)?;
    let g2_delta = deserialize_g2(&mut r)?;
    let vk_alpha_g1 = deserialize_g1(&mut r)?;
    let vk_beta_g2 = deserialize_g2(&mut r)?;
    let vk_gamma_g2 = deserialize_g2(&mut r)?;
    let vk_delta_g2 = deserialize_g2(&mut r)?;
    let gamma_len = read_u64(&mut r)? as usize;
    let mut vk_gamma_abc_g1 = Vec::with_capacity(gamma_len);
    for _ in 0..gamma_len {
        vk_gamma_abc_g1.push(deserialize_g1(&mut r)?);
    }
    Ok(SmallData {
        g1_alpha,
        g1_beta,
        g1_delta,
        g2_beta,
        g2_delta,
        vk_alpha_g1,
        vk_beta_g2,
        vk_gamma_g2,
        vk_delta_g2,
        vk_gamma_abc_g1,
    })
}

fn write_meta(dir: &Path, log_n: u32, n: usize, n_vars: usize, n_pub: usize) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path(dir, "meta.txt"))?);
    writeln!(w, "log_n={log_n}")?;
    writeln!(w, "n={n}")?;
    writeln!(w, "n_constraints={n}")?;
    writeln!(w, "n_vars={n_vars}")?;
    writeln!(w, "n_pub={n_pub}")?;
    writeln!(w, "qap_u_len={n}")?;
    writeln!(w, "qap_v_len={n}")?;
    writeln!(w, "qap_w_len={n}")?;
    writeln!(w, "assignment_len={}", 1 + 3 * n)?;
    writeln!(w, "g1_u_len={n_vars}")?;
    writeln!(w, "g1_v_len={n_vars}")?;
    writeln!(w, "g1_abc_len={}", n_vars - n_pub - 1)?;
    writeln!(w, "g1_h_len={}", n - 1)?;
    writeln!(w, "g2_v_len={n_vars}")?;
    w.flush()
}

fn read_meta(dir: &Path) -> io::Result<HashMap<String, usize>> {
    let s = fs::read_to_string(path(dir, "meta.txt"))?;
    let mut out = HashMap::new();
    for line in s.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let value = v
            .parse::<usize>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        out.insert(k.to_owned(), value);
    }
    Ok(out)
}

fn meta_get(meta: &HashMap<String, usize>, key: &str) -> io::Result<usize> {
    meta.get(key).copied().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing meta key {key}"),
        )
    })
}

fn materialize(log_n: u32, dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let n = 1usize << log_n;
    let qap = make_qap(n);
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(SETUP_SEED);

    println!("materialize: setup/QAP/witness for N=2^{log_n} ({n})");
    let ((spk, vk), t_setup) =
        measure(|| streaming_setup::<Bn254, _>(&qap, &mut rng).expect("streaming_setup failed"));
    println!("materialize: streaming_setup {:.1}s", t_setup.as_secs_f64());

    let (sqap, t_qap) = measure(|| make_streaming_qap(&qap).expect("make_streaming_qap failed"));
    println!(
        "materialize: make_streaming_qap {:.1}s",
        t_qap.as_secs_f64()
    );
    drop(qap);

    let (assignment, t_assignment) =
        measure(|| make_assignment_fv(n, &mut rng).expect("make_assignment_fv failed"));
    println!(
        "materialize: assignment FileVec {:.1}s",
        t_assignment.as_secs_f64()
    );

    copy_fv(&spk.g1_u_tau, dir, "crs_g1_u.bin")?;
    copy_fv(&spk.g1_v_tau, dir, "crs_g1_v.bin")?;
    copy_fv(&spk.g1_abc_over_delta, dir, "crs_g1_abc.bin")?;
    copy_fv(&spk.g1_h_pow_tau_over_delta, dir, "crs_g1_h.bin")?;
    copy_fv(&spk.g2_v_tau, dir, "crs_g2_v.bin")?;
    copy_fv(&sqap.u, dir, "qap_u.bin")?;
    copy_fv(&sqap.v, dir, "qap_v.bin")?;
    copy_fv(&sqap.w, dir, "qap_w.bin")?;
    copy_fv(&assignment, dir, "assignment.bin")?;
    write_small(&path(dir, "small.bin"), &spk, &vk)?;
    write_meta(dir, log_n, n, sqap.n_vars, sqap.n_pub)?;

    println!("materialize: wrote {}", dir.display());
    Ok(())
}

fn proof_size(proof: &Proof<Bn254>) -> io::Result<usize> {
    let mut buf = Vec::new();
    proof.a.serialize_compressed(&mut buf).unwrap();
    proof.b.serialize_compressed(&mut buf).unwrap();
    proof.c.serialize_compressed(&mut buf).unwrap();
    if let Ok(output) = std::env::var("RWG_PROOF_OUT") {
        fs::write(output, &buf)?;
    }
    Ok(buf.len())
}

fn prove_only(log_n: u32, dir: &Path, limit_mb: u64) -> io::Result<String> {
    if limit_mb > 0 {
        let ok = set_address_space_limit(limit_mb * 1024 * 1024);
        if !ok {
            return Err(io::Error::other("set_address_space_limit failed"));
        }
    }

    let meta = read_meta(dir)?;
    let n = meta_get(&meta, "n")?;
    let n_constraints = meta_get(&meta, "n_constraints")?;
    let n_vars = meta_get(&meta, "n_vars")?;
    let n_pub = meta_get(&meta, "n_pub")?;
    let small = read_small(&path(dir, "small.bin"))?;

    let sqap = StreamingQap {
        domain_size: n,
        n_constraints,
        n_vars,
        n_pub,
        u: FileVec::<MatrixEntry<Fr>>::from_existing(
            path(dir, "qap_u.bin"),
            meta_get(&meta, "qap_u_len")?,
        ),
        v: FileVec::<MatrixEntry<Fr>>::from_existing(
            path(dir, "qap_v.bin"),
            meta_get(&meta, "qap_v_len")?,
        ),
        w: FileVec::<MatrixEntry<Fr>>::from_existing(
            path(dir, "qap_w.bin"),
            meta_get(&meta, "qap_w_len")?,
        ),
    };
    let spk = StreamingProvingKey::<Bn254> {
        g1_u_tau: FileVec::<G1Disk>::from_existing(
            path(dir, "crs_g1_u.bin"),
            meta_get(&meta, "g1_u_len")?,
        ),
        g1_v_tau: FileVec::<G1Disk>::from_existing(
            path(dir, "crs_g1_v.bin"),
            meta_get(&meta, "g1_v_len")?,
        ),
        g1_abc_over_delta: FileVec::<G1Disk>::from_existing(
            path(dir, "crs_g1_abc.bin"),
            meta_get(&meta, "g1_abc_len")?,
        ),
        g1_h_pow_tau_over_delta: FileVec::<G1Disk>::from_existing(
            path(dir, "crs_g1_h.bin"),
            meta_get(&meta, "g1_h_len")?,
        ),
        g2_v_tau: FileVec::<G2Disk>::from_existing(
            path(dir, "crs_g2_v.bin"),
            meta_get(&meta, "g2_v_len")?,
        ),
        g1_alpha: small.g1_alpha,
        g1_beta: small.g1_beta,
        g1_delta: small.g1_delta,
        g2_beta: small.g2_beta,
        g2_delta: small.g2_delta,
        n_pub,
    };
    let vk = VerifyingKey::<Bn254> {
        alpha_g1: small.vk_alpha_g1,
        beta_g2: small.vk_beta_g2,
        gamma_g2: small.vk_gamma_g2,
        delta_g2: small.vk_delta_g2,
        gamma_abc_g1: small.vk_gamma_abc_g1,
    };
    let assignment = FileVec::<Fr>::from_existing(
        path(dir, "assignment.bin"),
        meta_get(&meta, "assignment_len")?,
    );
    let stmt: Vec<Fr> = vec![];
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(PROVE_SEED);

    reset_io_counters();
    let rss0 = peak_rss_mb();
    let (proof, t_prove) = measure(|| {
        streaming_prove_rw::<Bn254, _>(&sqap, &spk, &assignment, &mut rng)
            .expect("streaming_prove_rw failed")
    });
    let rss1 = peak_rss_mb();
    let io = io_counters();
    let (valid, t_verify) = measure(|| verify::<Bn254>(&vk, &stmt, &proof));
    let pbytes = proof_size(&proof)?;
    let run_meta = run_meta();

    Ok(format!(
        "rw_rw_prove_only,{},{},{:.1},{:.3},{:.1},{:.1},{},{},{},{},{},{},{},{},{},{},{}",
        log_n,
        n,
        t_prove.as_secs_f64() * 1000.0,
        t_verify.as_secs_f64() * 1000.0,
        rss1,
        rss1 - rss0,
        pbytes,
        valid,
        io.read_bytes,
        io.write_bytes,
        io.total_streams(),
        dir.join("crs").display(),
        dir.join("qap").display(),
        path(dir, "assignment.bin").display(),
        run_meta.git_commit,
        run_meta.machine_id,
        unix_timestamp()
    ))
}

fn csv_header() -> &'static str {
    "variant,log_n,n,prove_ms,verify_ms,peak_rss_mb,rss_delta_mb,proof_bytes,valid,read_bytes,write_bytes,pass_count,crs_path,qap_path,witness_path,git_commit,machine_id,timestamp"
}

fn driver(log_n: u32, dir: &Path, csv_path: &Path) -> io::Result<()> {
    materialize(log_n, dir)?;
    let exe = std::env::current_exe()?;
    println!("prove-only: spawning clean worker");
    let out = Command::new(exe)
        .arg("--prove")
        .arg(log_n.to_string())
        .arg(dir)
        .output()?;
    if !out.status.success() {
        io::stderr().write_all(&out.stderr)?;
        return Err(io::Error::other("prove-only worker failed"));
    }
    let row = String::from_utf8(out.stdout)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut w = BufWriter::new(File::create(csv_path)?);
    writeln!(w, "{}", csv_header())?;
    write!(w, "{row}")?;
    w.flush()?;
    println!("prove-only: wrote {}", csv_path.display());
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--materialize-only") {
        if args.len() != 3 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "usage: --materialize-only LOG_N DATA_DIR"));
        }
        let log_n: u32 = args[1].parse().map_err(|_|
            io::Error::new(io::ErrorKind::InvalidInput, "invalid LOG_N"))?;
        if !(1..=25).contains(&log_n) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "LOG_N must be between 1 and 25"));
        }
        let dir = PathBuf::from(&args[2]);
        if dir.exists() && fs::read_dir(&dir)?.next().is_some() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists,
                "DATA_DIR must be empty; refusing to overwrite prepared inputs"));
        }
        return materialize(log_n, &dir);
    }
    if args.first().map(|s| s.as_str()) == Some("--prove") {
        let log_n: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(23);
        let dir = PathBuf::from(
            args.get(2)
                .map(String::as_str)
                .unwrap_or("Experiments/rw_prove_only_data"),
        );
        let limit_mb = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        let row = prove_only(log_n, &dir, limit_mb)?;
        println!("{row}");
        return Ok(());
    }

    let log_n: u32 = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(23);
    let dir = PathBuf::from(
        args.get(1)
            .map(String::as_str)
            .unwrap_or("Experiments/rw_prove_only_23_data"),
    );
    let csv_path = PathBuf::from(
        args.get(2)
            .map(String::as_str)
            .unwrap_or("Experiments/rw_prove_only_23.csv"),
    );
    driver(log_n, &dir, &csv_path)
}
