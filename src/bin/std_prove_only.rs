//! Prove-only worker for the standard in-memory Groth16 baseline.
//!
//! Driver mode materializes a standard proving key, QAP, and witness to disk.
//! Worker mode reopens those files and runs only `standard_prove`.  This lets
//! cgroup-based memory-cap experiments fail or succeed at the prove boundary,
//! without charging trusted setup to the capped process.

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
    harness::{measure, peak_rss_mb, set_address_space_limit},
    setup::setup,
    standard_prover::standard_prove,
    types::{Proof, ProvingKey, Qap, VerifyingKey},
    verify::verify,
};

const SETUP_SEED: u64 = 0x5354_445f_5345_5455;
const WITNESS_SEED: u64 = 0x5354_445f_5749_544e;
const PROVE_SEED: u64 = 0x5354_445f_5052_4f56;

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

fn path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
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

fn deserialize_fr(r: &mut impl Read) -> io::Result<Fr> {
    Fr::deserialize_uncompressed_unchecked(r)
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
    writeln!(w, "witness_len={}", n_vars - n_pub - 1)?;
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

fn write_matrix(path: &Path, entries: &[(usize, usize, Fr)]) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    for &(row, col, val) in entries {
        write_u64(&mut w, row as u64)?;
        write_u64(&mut w, col as u64)?;
        serialize_uncompressed(&mut w, &val)?;
    }
    w.flush()
}

fn read_matrix(path: &Path, len: usize) -> io::Result<Vec<(usize, usize, Fr)>> {
    let mut r = BufReader::new(File::open(path)?);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let row = read_u64(&mut r)? as usize;
        let col = read_u64(&mut r)? as usize;
        let val = deserialize_fr(&mut r)?;
        out.push((row, col, val));
    }
    Ok(out)
}

fn write_witness(path: &Path, n: usize) -> io::Result<()> {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(WITNESS_SEED);
    let mut w = BufWriter::new(File::create(path)?);
    for _ in 0..n {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        serialize_uncompressed(&mut w, &a)?;
        serialize_uncompressed(&mut w, &b)?;
        serialize_uncompressed(&mut w, &(a * b))?;
    }
    w.flush()
}

fn read_fr_vec(path: &Path, len: usize) -> io::Result<Vec<Fr>> {
    let mut r = BufReader::new(File::open(path)?);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(deserialize_fr(&mut r)?);
    }
    Ok(out)
}

fn write_g1_vec(path: &Path, xs: &[G1Affine]) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    for x in xs {
        serialize_uncompressed(&mut w, x)?;
    }
    w.flush()
}

fn write_g2_vec(path: &Path, xs: &[G2Affine]) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    for x in xs {
        serialize_uncompressed(&mut w, x)?;
    }
    w.flush()
}

fn read_g1_vec(path: &Path, len: usize) -> io::Result<Vec<G1Affine>> {
    let mut r = BufReader::new(File::open(path)?);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(deserialize_g1(&mut r)?);
    }
    Ok(out)
}

fn read_g2_vec(path: &Path, len: usize) -> io::Result<Vec<G2Affine>> {
    let mut r = BufReader::new(File::open(path)?);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(deserialize_g2(&mut r)?);
    }
    Ok(out)
}

fn write_small(path: &Path, pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    serialize_uncompressed(&mut w, &pk.g1_alpha)?;
    serialize_uncompressed(&mut w, &pk.g1_beta)?;
    serialize_uncompressed(&mut w, &pk.g1_delta)?;
    serialize_uncompressed(&mut w, &pk.g2_beta)?;
    serialize_uncompressed(&mut w, &pk.g2_delta)?;
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

fn materialize(log_n: u32, dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let n = 1usize << log_n;
    println!("materialize standard: QAP/PK/witness for N=2^{log_n} ({n})");

    let qap = make_qap(n);
    write_meta(dir, log_n, n, qap.n_vars, qap.n_pub)?;
    write_matrix(&path(dir, "qap_u.bin"), &qap.u)?;
    write_matrix(&path(dir, "qap_v.bin"), &qap.v)?;
    write_matrix(&path(dir, "qap_w.bin"), &qap.w)?;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(SETUP_SEED);
    let ((pk, vk), t_setup) = measure(|| setup::<Bn254, _>(&qap, &mut rng));
    println!("materialize standard: setup {:.1}s", t_setup.as_secs_f64());

    write_g1_vec(&path(dir, "pk_g1_u.bin"), &pk.g1_u_tau)?;
    write_g1_vec(&path(dir, "pk_g1_v.bin"), &pk.g1_v_tau)?;
    write_g1_vec(&path(dir, "pk_g1_abc.bin"), &pk.g1_abc_over_delta)?;
    write_g1_vec(&path(dir, "pk_g1_h.bin"), &pk.g1_h_pow_tau_over_delta)?;
    write_g2_vec(&path(dir, "pk_g2_v.bin"), &pk.g2_v_tau)?;
    write_small(&path(dir, "small.bin"), &pk, &vk)?;
    drop(pk);
    drop(vk);
    drop(qap);

    let (_, t_witness) = measure(|| write_witness(&path(dir, "witness.bin"), n));
    println!(
        "materialize standard: witness {:.1}s",
        t_witness.as_secs_f64()
    );
    println!("materialize standard: wrote {}", dir.display());
    Ok(())
}

fn proof_size(proof: &Proof<Bn254>) -> usize {
    let mut buf = Vec::new();
    proof.a.serialize_compressed(&mut buf).unwrap();
    proof.b.serialize_compressed(&mut buf).unwrap();
    proof.c.serialize_compressed(&mut buf).unwrap();
    buf.len()
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
    let qap = Qap {
        domain_size: n,
        n_constraints: meta_get(&meta, "n_constraints")?,
        n_vars: meta_get(&meta, "n_vars")?,
        n_pub: meta_get(&meta, "n_pub")?,
        u: read_matrix(&path(dir, "qap_u.bin"), meta_get(&meta, "qap_u_len")?)?,
        v: read_matrix(&path(dir, "qap_v.bin"), meta_get(&meta, "qap_v_len")?)?,
        w: read_matrix(&path(dir, "qap_w.bin"), meta_get(&meta, "qap_w_len")?)?,
    };
    let witness = read_fr_vec(&path(dir, "witness.bin"), meta_get(&meta, "witness_len")?)?;
    let small = read_small(&path(dir, "small.bin"))?;
    let pk = ProvingKey {
        g1_u_tau: read_g1_vec(&path(dir, "pk_g1_u.bin"), meta_get(&meta, "g1_u_len")?)?,
        g1_v_tau: read_g1_vec(&path(dir, "pk_g1_v.bin"), meta_get(&meta, "g1_v_len")?)?,
        g1_abc_over_delta: read_g1_vec(
            &path(dir, "pk_g1_abc.bin"),
            meta_get(&meta, "g1_abc_len")?,
        )?,
        g1_h_pow_tau_over_delta: read_g1_vec(
            &path(dir, "pk_g1_h.bin"),
            meta_get(&meta, "g1_h_len")?,
        )?,
        g1_alpha: small.g1_alpha,
        g1_beta: small.g1_beta,
        g1_delta: small.g1_delta,
        g2_v_tau: read_g2_vec(&path(dir, "pk_g2_v.bin"), meta_get(&meta, "g2_v_len")?)?,
        g2_beta: small.g2_beta,
        g2_delta: small.g2_delta,
    };
    let vk = VerifyingKey {
        alpha_g1: small.vk_alpha_g1,
        beta_g2: small.vk_beta_g2,
        gamma_g2: small.vk_gamma_g2,
        delta_g2: small.vk_delta_g2,
        gamma_abc_g1: small.vk_gamma_abc_g1,
    };
    let stmt: Vec<Fr> = Vec::new();

    let rss0 = peak_rss_mb();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(PROVE_SEED);
    let (proof, t_prove) =
        measure(|| standard_prove::<Bn254, _>(&qap, &pk, &stmt, &witness, &mut rng));
    let rss1 = peak_rss_mb();
    let (valid, t_verify) = measure(|| verify::<Bn254>(&vk, &stmt, &proof));
    let proof_bytes = proof_size(&proof);
    let meta = run_meta();

    Ok(format!(
        "std_prove_only,{},{},{:.1},{:.3},{:.1},{:.1},{},{},{},{},{},{},{},{},{},{},{}",
        log_n,
        n,
        t_prove.as_secs_f64() * 1000.0,
        t_verify.as_secs_f64() * 1000.0,
        rss1,
        rss1 - rss0,
        proof_bytes,
        valid,
        0,
        0,
        0,
        path(dir, "small.bin").display(),
        path(dir, "qap_u.bin").display(),
        path(dir, "witness.bin").display(),
        meta.git_commit,
        meta.machine_id,
        unix_timestamp()
    ))
}

fn csv_header() -> &'static str {
    "variant,log_n,n,prove_ms,verify_ms,peak_rss_mb,rss_delta_mb,proof_bytes,valid,read_bytes,write_bytes,pass_count,pk_path,qap_path,witness_path,git_commit,machine_id,timestamp"
}

fn driver(log_n: u32, dir: &Path, csv_path: &Path) -> io::Result<()> {
    materialize(log_n, dir)?;
    println!("standard prove-only: spawning clean worker");
    let exe = std::env::current_exe()?;
    let out = Command::new(exe)
        .args(["--prove", &log_n.to_string()])
        .arg(dir)
        .output()?;
    if !out.status.success() {
        io::stderr().write_all(&out.stderr)?;
        return Err(io::Error::other("standard prove-only worker failed"));
    }
    let row = String::from_utf8(out.stdout)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut w = BufWriter::new(File::create(csv_path)?);
    writeln!(w, "{}", csv_header())?;
    write!(w, "{row}")?;
    w.flush()?;
    println!("standard prove-only: wrote {}", csv_path.display());
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) == Some("--prove") {
        let log_n: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(23);
        let dir = PathBuf::from(
            args.get(2)
                .map(String::as_str)
                .unwrap_or("Experiments/std_prove_only_data"),
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
            .unwrap_or("Experiments/std_prove_only_data"),
    );
    let csv_path = PathBuf::from(
        args.get(2)
            .map(String::as_str)
            .unwrap_or("Experiments/std_prove_only.csv"),
    );
    driver(log_n, &dir, &csv_path)
}
