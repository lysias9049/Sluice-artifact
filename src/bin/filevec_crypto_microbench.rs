//! Sequential FileVec-style plaintext vs AEAD I/O microbenchmark.
//!
//! This is intentionally a storage-layer benchmark, not an end-to-end
//! encrypted RW-Groth16 prover. It measures chunked sequential write/read
//! overhead using ChaCha20-Poly1305 with one authentication tag per chunk.
//!
//! Usage:
//!   cargo run --release --bin filevec_crypto_microbench -- 1024 256 5 \
//!     2> Experiments/filevec_crypto_microbench_1g_r5.csv

use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::PathBuf,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};

const TAG_BYTES: usize = 16;

#[derive(Clone, Copy)]
struct Args {
    total_mib: u64,
    chunk_kib: usize,
    repeats: usize,
}

#[derive(Clone, Copy)]
struct Timings {
    write_ms: f64,
    read_ms: f64,
    file_bytes: u64,
    valid: bool,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let total_mib = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1024);
    let chunk_kib = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(256);
    let repeats = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    if total_mib == 0 || chunk_kib == 0 || repeats == 0 {
        eprintln!("usage: filevec_crypto_microbench <total_mib> <chunk_kib> <repeats>");
        std::process::exit(2);
    }
    Args {
        total_mib,
        chunk_kib,
        repeats,
    }
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

fn git_commit() -> String {
    command_output("git", &["rev-parse", "--short", "HEAD"])
        .unwrap_or_else(|| "unknown".to_owned())
}

fn machine_id() -> String {
    if std::env::var("RWG_RECORD_MACHINE_ID").ok().as_deref() == Some("1") {
        std::env::var("HOSTNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| command_output("hostname", &[]))
            .unwrap_or_else(|| "unknown".to_owned())
    } else {
        "artifact-host".to_owned()
    }
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn temp_path(mode: &str, rep: usize) -> PathBuf {
    let pid = std::process::id();
    std::env::temp_dir().join(format!("rwg_filevec_crypto_{pid}_{mode}_{rep}.bin"))
}

fn fill_chunk(buf: &mut [u8], chunk_idx: u64) {
    let mut x = chunk_idx ^ 0x9e37_79b9_7f4a_7c15;
    for b in buf {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xff) as u8;
    }
}

fn nonce_for(chunk_idx: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(b"RWG1");
    nonce[4..12].copy_from_slice(&chunk_idx.to_le_bytes());
    nonce
}

fn associated_data(total_bytes: u64, chunk_len: usize, chunk_idx: u64) -> [u8; 24] {
    let mut ad = [0u8; 24];
    ad[0..8].copy_from_slice(&total_bytes.to_le_bytes());
    ad[8..16].copy_from_slice(&(chunk_len as u64).to_le_bytes());
    ad[16..24].copy_from_slice(&chunk_idx.to_le_bytes());
    ad
}

fn write_plain(path: &PathBuf, total_bytes: u64, chunk_bytes: usize) -> io::Result<f64> {
    let mut w = BufWriter::with_capacity(chunk_bytes, File::create(path)?);
    let mut chunk = vec![0u8; chunk_bytes];
    let mut remaining = total_bytes;
    let mut idx = 0u64;
    let t0 = Instant::now();
    while remaining > 0 {
        let n = remaining.min(chunk_bytes as u64) as usize;
        fill_chunk(&mut chunk[..n], idx);
        w.write_all(&chunk[..n])?;
        remaining -= n as u64;
        idx += 1;
    }
    w.flush()?;
    Ok(t0.elapsed().as_secs_f64() * 1000.0)
}

fn read_plain(path: &PathBuf, total_bytes: u64, chunk_bytes: usize) -> io::Result<(f64, bool)> {
    let mut r = BufReader::with_capacity(chunk_bytes, File::open(path)?);
    let mut chunk = vec![0u8; chunk_bytes];
    let mut expected = vec![0u8; chunk_bytes];
    let mut remaining = total_bytes;
    let mut idx = 0u64;
    let mut valid = true;
    let t0 = Instant::now();
    while remaining > 0 {
        let n = remaining.min(chunk_bytes as u64) as usize;
        r.read_exact(&mut chunk[..n])?;
        fill_chunk(&mut expected[..n], idx);
        valid &= chunk[..n] == expected[..n];
        remaining -= n as u64;
        idx += 1;
    }
    Ok((t0.elapsed().as_secs_f64() * 1000.0, valid))
}

fn run_plain(rep: usize, total_bytes: u64, chunk_bytes: usize) -> io::Result<Timings> {
    let path = temp_path("plain", rep);
    let write_ms = write_plain(&path, total_bytes, chunk_bytes)?;
    let (read_ms, valid) = read_plain(&path, total_bytes, chunk_bytes)?;
    let file_bytes = fs::metadata(&path)?.len();
    fs::remove_file(path)?;
    Ok(Timings {
        write_ms,
        read_ms,
        file_bytes,
        valid,
    })
}

fn write_aead(
    path: &PathBuf,
    total_bytes: u64,
    chunk_bytes: usize,
    cipher: &ChaCha20Poly1305,
) -> io::Result<f64> {
    let mut w = BufWriter::with_capacity(chunk_bytes + TAG_BYTES, File::create(path)?);
    let mut chunk = vec![0u8; chunk_bytes];
    let mut remaining = total_bytes;
    let mut idx = 0u64;
    let t0 = Instant::now();
    while remaining > 0 {
        let n = remaining.min(chunk_bytes as u64) as usize;
        fill_chunk(&mut chunk[..n], idx);
        let nonce = nonce_for(idx);
        let ad = associated_data(total_bytes, n, idx);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &ad, &mut chunk[..n])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encrypt failed"))?;
        w.write_all(&chunk[..n])?;
        w.write_all(&tag)?;
        remaining -= n as u64;
        idx += 1;
    }
    w.flush()?;
    Ok(t0.elapsed().as_secs_f64() * 1000.0)
}

fn read_aead(
    path: &PathBuf,
    total_bytes: u64,
    chunk_bytes: usize,
    cipher: &ChaCha20Poly1305,
) -> io::Result<(f64, bool)> {
    let mut r = BufReader::with_capacity(chunk_bytes + TAG_BYTES, File::open(path)?);
    let mut chunk = vec![0u8; chunk_bytes];
    let mut expected = vec![0u8; chunk_bytes];
    let mut tag_buf = [0u8; TAG_BYTES];
    let mut remaining = total_bytes;
    let mut idx = 0u64;
    let mut valid = true;
    let t0 = Instant::now();
    while remaining > 0 {
        let n = remaining.min(chunk_bytes as u64) as usize;
        r.read_exact(&mut chunk[..n])?;
        r.read_exact(&mut tag_buf)?;
        let nonce = nonce_for(idx);
        let ad = associated_data(total_bytes, n, idx);
        let tag = Tag::from_slice(&tag_buf);
        let auth_ok = cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), &ad, &mut chunk[..n], tag)
            .is_ok();
        fill_chunk(&mut expected[..n], idx);
        valid &= auth_ok && chunk[..n] == expected[..n];
        remaining -= n as u64;
        idx += 1;
    }
    Ok((t0.elapsed().as_secs_f64() * 1000.0, valid))
}

fn run_aead(rep: usize, total_bytes: u64, chunk_bytes: usize) -> io::Result<Timings> {
    let key = Key::from_slice(&[0x42u8; 32]);
    let cipher = ChaCha20Poly1305::new(key);
    let path = temp_path("aead", rep);
    let write_ms = write_aead(&path, total_bytes, chunk_bytes, &cipher)?;
    let (read_ms, valid) = read_aead(&path, total_bytes, chunk_bytes, &cipher)?;
    let file_bytes = fs::metadata(&path)?.len();
    fs::remove_file(path)?;
    Ok(Timings {
        write_ms,
        read_ms,
        file_bytes,
        valid,
    })
}

fn print_row(
    mode: &str,
    args: Args,
    rep: usize,
    timing: Timings,
    git_commit: &str,
    machine_id: &str,
) {
    let total_bytes = args.total_mib * 1024 * 1024;
    let chunk_bytes = args.chunk_kib * 1024;
    let chunks = total_bytes.div_ceil(chunk_bytes as u64);
    let total_ms = timing.write_ms + timing.read_ms;
    let stream_bytes = total_bytes * 2;
    let throughput_mib_s = (stream_bytes as f64 / (1024.0 * 1024.0)) / (total_ms / 1000.0);
    let tag_overhead_bytes = timing.file_bytes.saturating_sub(total_bytes);
    eprintln!(
        "{mode},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{},{},{},{},{},{},{}",
        args.total_mib,
        total_bytes,
        args.chunk_kib,
        chunk_bytes,
        chunks,
        timing.write_ms,
        timing.read_ms,
        total_ms,
        throughput_mib_s,
        timing.file_bytes,
        tag_overhead_bytes,
        timing.valid,
        rep,
        git_commit,
        machine_id,
        timestamp()
    );
}

fn main() -> io::Result<()> {
    let args = parse_args();
    let git = git_commit();
    let machine = machine_id();
    eprintln!("mode,total_mib,total_bytes,chunk_kib,chunk_bytes,chunks,write_ms,read_ms,total_ms,throughput_mib_s,file_bytes,tag_overhead_bytes,valid,rep,git_commit,machine_id,timestamp");
    for rep in 0..args.repeats {
        let plain = run_plain(rep, args.total_mib * 1024 * 1024, args.chunk_kib * 1024)?;
        print_row("plain", args, rep, plain, &git, &machine);
        let aead = run_aead(rep, args.total_mib * 1024 * 1024, args.chunk_kib * 1024)?;
        print_row("chacha20poly1305", args, rep, aead, &git, &machine);
    }
    Ok(())
}
