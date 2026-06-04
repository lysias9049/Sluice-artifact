//! FileVec: disk-backed fixed-size array for streaming computation.
//!
//! # Design
//!
//! `StreamElem` — trait for types serializable as exactly `BYTE_LEN` bytes.
//! `FileVec<T>`  — an owned, sequentially-readable array backed by a temp file.
//! `FileVecReader<T>` / `FileVecWriter<T>` — sequential I/O handles.
//!
//! By keeping NTT / R1CS / MSM intermediates on disk, the prover achieves
//! O(chunk_size) peak RAM instead of O(N), enabling N = 2^28 on commodity hardware.
//!
//! # Temp-file lifecycle
//!
//! Each `FileVec` owns its backing file and deletes it on `drop`.
//! Each `FileVecWriter` creates a new temp file; calling `finish()` hands
//! ownership to the resulting `FileVec`.

use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};

/// Internal I/O buffer size: 256 KB.
const BUF_CAPACITY: usize = 1 << 18;
const AEAD_MAGIC: &[u8; 8] = b"RWGAEAD1";
const AEAD_TAG_BYTES: usize = 16;

/// Application-level FileVec I/O counters for benchmark reporting.
///
/// These counters measure bytes serialized through `FileVecReader` and
/// `FileVecWriter`, plus the number of sequential stream opens/finishes.  They
/// intentionally exclude OS metadata traffic and page-cache effects.
#[derive(Clone, Copy, Debug, Default)]
pub struct IoCounters {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_streams: u64,
    pub write_streams: u64,
}

impl IoCounters {
    pub fn total_streams(self) -> u64 {
        self.read_streams + self.write_streams
    }
}

static READ_BYTES: AtomicU64 = AtomicU64::new(0);
static WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
static READ_STREAMS: AtomicU64 = AtomicU64::new(0);
static WRITE_STREAMS: AtomicU64 = AtomicU64::new(0);

pub fn reset_io_counters() {
    READ_BYTES.store(0, Ordering::Relaxed);
    WRITE_BYTES.store(0, Ordering::Relaxed);
    READ_STREAMS.store(0, Ordering::Relaxed);
    WRITE_STREAMS.store(0, Ordering::Relaxed);
}

pub fn io_counters() -> IoCounters {
    IoCounters {
        read_bytes: READ_BYTES.load(Ordering::Relaxed),
        write_bytes: WRITE_BYTES.load(Ordering::Relaxed),
        read_streams: READ_STREAMS.load(Ordering::Relaxed),
        write_streams: WRITE_STREAMS.load(Ordering::Relaxed),
    }
}

// ── Temp-file path generation ─────────────────────────────────────────────────

static FILE_ID: AtomicUsize = AtomicUsize::new(0);

fn next_temp_path() -> PathBuf {
    let id = FILE_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("rwg_{pid}_{id}.tmp"))
}

fn aead_enabled() -> bool {
    matches!(
        std::env::var("RWG_FILEVEC_AEAD").ok().as_deref(),
        Some("1") | Some("true") | Some("chacha20poly1305")
    )
}

fn aead_cipher() -> ChaCha20Poly1305 {
    // Benchmark key only. This proves compatibility of encrypted/authenticated
    // sequential FileVec access, not production key management.
    ChaCha20Poly1305::new(Key::from_slice(&[0x42u8; 32]))
}

fn aead_nonce(chunk_idx: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(b"RWG1");
    nonce[4..12].copy_from_slice(&chunk_idx.to_le_bytes());
    nonce
}

fn aead_ad(elem_len: usize, chunk_idx: u64, plain_len: usize) -> [u8; 24] {
    let mut ad = [0u8; 24];
    ad[0..8].copy_from_slice(&(elem_len as u64).to_le_bytes());
    ad[8..16].copy_from_slice(&chunk_idx.to_le_bytes());
    ad[16..24].copy_from_slice(&(plain_len as u64).to_le_bytes());
    ad
}

fn auth_err() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "FileVec AEAD authentication failed")
}

enum ReaderMode {
    Plain,
    Aead {
        cipher: ChaCha20Poly1305,
        chunk_idx: u64,
        plain: Vec<u8>,
        offset: usize,
    },
}

enum WriterMode {
    Plain,
    Aead {
        cipher: ChaCha20Poly1305,
        chunk_idx: u64,
        plain: Vec<u8>,
    },
}

// ── StreamElem trait ──────────────────────────────────────────────────────────

/// An element type that can be serialized to/from a fixed number of bytes.
///
/// Implementors must write/read exactly `BYTE_LEN` bytes per element so that
/// `FileVec<T>` can compute positions by multiplication (no scanning required).
pub trait StreamElem: Sized + Send + Sync + 'static {
    /// Fixed byte size of one serialized element.
    const BYTE_LEN: usize;

    /// Serialize `self` into `w`.  Must write exactly `BYTE_LEN` bytes.
    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()>;

    /// Deserialize one element from `r`.  Must consume exactly `BYTE_LEN` bytes.
    fn read_from<R: Read>(r: &mut R) -> io::Result<Self>;
}

// ── StreamElem impl for ark_bn254::Fr ─────────────────────────────────────────

use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

impl StreamElem for Fr {
    // BN254 Fr is 254 bits → 32 bytes uncompressed.
    const BYTE_LEN: usize = 32;

    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.serialize_uncompressed(w)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        // Use unchecked for performance: we only write valid field elements.
        Fr::deserialize_uncompressed_unchecked(r)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

// ── FileVec ───────────────────────────────────────────────────────────────────

/// A disk-backed array of `T` elements.
///
/// The backing temp file is created at construction and deleted when this
/// value is dropped.  All I/O is sequential; no random access is exposed.
pub struct FileVec<T: StreamElem> {
    pub(crate) path: PathBuf,
    pub(crate) len: usize,
    pub(crate) delete_on_drop: bool,
    _t: PhantomData<T>,
}

impl<T: StreamElem> Drop for FileVec<T> {
    fn drop(&mut self) {
        if self.delete_on_drop {
            // Silently ignore errors (file may already be deleted in edge cases).
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl<T: StreamElem> FileVec<T> {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the backing path.  This is intended for benchmark artifact
    /// materialization; normal algorithms should treat `FileVec` as opaque.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reopen an existing fixed-width stream without taking cleanup ownership.
    ///
    /// The caller is responsible for ensuring the file contains exactly `len`
    /// serialized elements of type `T`.
    pub fn from_existing(path: impl Into<PathBuf>, len: usize) -> Self {
        Self {
            path: path.into(),
            len,
            delete_on_drop: false,
            _t: PhantomData,
        }
    }

    /// Copy the backing stream to a persistent path.
    pub fn copy_to_path(&self, path: impl AsRef<Path>) -> io::Result<()> {
        fs::copy(&self.path, path)?;
        Ok(())
    }

    /// Serialize `data` to a new temp file and return the `FileVec`.
    pub fn from_vec(data: &[T]) -> io::Result<Self> {
        let mut w = FileVecWriter::<T>::new()?;
        for elem in data {
            w.write(elem)?;
        }
        w.finish()
    }

    /// Deserialize all elements back into a `Vec<T>`.
    ///
    /// Consumes `self` (and deletes the backing file).
    pub fn into_vec(self) -> io::Result<Vec<T>> {
        let mut r = FileVecReader::open(&self)?;
        let mut out = Vec::with_capacity(self.len);
        while let Some(elem) = r.next()? {
            out.push(elem);
        }
        Ok(out)
    }
}

// ── FileVecReader ─────────────────────────────────────────────────────────────

/// Sequential reader over a `FileVec<T>`.
///
/// Opened via `FileVecReader::open(fv)`.  The underlying `FileVec` is not
/// consumed; it is safe to open multiple readers from the same `FileVec`.
pub struct FileVecReader<T: StreamElem> {
    reader: BufReader<File>,
    remaining: usize,
    mode: ReaderMode,
    _t: PhantomData<T>,
}

impl<T: StreamElem> FileVecReader<T> {
    pub fn open(fv: &FileVec<T>) -> io::Result<Self> {
        let mut file = File::open(&fv.path)?;
        let mut magic = [0u8; AEAD_MAGIC.len()];
        let is_aead = file.read_exact(&mut magic).is_ok() && &magic == AEAD_MAGIC;
        if !is_aead {
            file.seek(SeekFrom::Start(0))?;
        }
        READ_STREAMS.fetch_add(1, Ordering::Relaxed);
        let mode = if is_aead {
            ReaderMode::Aead {
                cipher: aead_cipher(),
                chunk_idx: 0,
                plain: Vec::new(),
                offset: 0,
            }
        } else {
            ReaderMode::Plain
        };
        Ok(Self {
            reader: BufReader::with_capacity(BUF_CAPACITY, file),
            remaining: fv.len,
            mode,
            _t: PhantomData,
        })
    }

    fn refill_aead_chunk(
        reader: &mut BufReader<File>,
        cipher: &ChaCha20Poly1305,
        chunk_idx: &mut u64,
        plain: &mut Vec<u8>,
        offset: &mut usize,
    ) -> io::Result<()> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let plain_len = u32::from_le_bytes(len_buf) as usize;
        if plain_len == 0 || plain_len > BUF_CAPACITY + T::BYTE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid FileVec AEAD chunk length",
            ));
        }
        plain.resize(plain_len, 0);
        reader.read_exact(plain)?;
        let mut tag_buf = [0u8; AEAD_TAG_BYTES];
        reader.read_exact(&mut tag_buf)?;
        let nonce = aead_nonce(*chunk_idx);
        let ad = aead_ad(T::BYTE_LEN, *chunk_idx, plain_len);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &ad,
                plain,
                Tag::from_slice(&tag_buf),
            )
            .map_err(|_| auth_err())?;
        *chunk_idx += 1;
        *offset = 0;
        Ok(())
    }

    /// Return the next element, or `None` if all elements have been read.
    #[inline]
    pub fn next(&mut self) -> io::Result<Option<T>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let elem = match &mut self.mode {
            ReaderMode::Plain => T::read_from(&mut self.reader)?,
            ReaderMode::Aead {
                cipher,
                chunk_idx,
                plain,
                offset,
            } => {
                if plain.len().saturating_sub(*offset) < T::BYTE_LEN {
                    Self::refill_aead_chunk(
                        &mut self.reader,
                        cipher,
                        chunk_idx,
                        plain,
                        offset,
                    )?;
                }
                let end = *offset + T::BYTE_LEN;
                let mut elem_reader = &plain[*offset..end];
                let elem = T::read_from(&mut elem_reader)?;
                *offset = end;
                elem
            }
        };
        READ_BYTES.fetch_add(T::BYTE_LEN as u64, Ordering::Relaxed);
        self.remaining -= 1;
        Ok(Some(elem))
    }
}

// ── FileVecWriter ─────────────────────────────────────────────────────────────

/// Sequential writer that accumulates elements into a new temp file.
///
/// Call `finish()` to flush, close, and obtain the completed `FileVec<T>`.
/// If dropped without calling `finish()`, the temp file is deleted.
pub struct FileVecWriter<T: StreamElem> {
    path: PathBuf,
    writer: BufWriter<File>,
    mode: WriterMode,
    count: usize,
    finished: bool,
    _t: PhantomData<T>,
}

impl<T: StreamElem> FileVecWriter<T> {
    /// Create a new writer backed by a fresh temp file.
    pub fn new() -> io::Result<Self> {
        let path = next_temp_path();
        let mut writer = BufWriter::with_capacity(BUF_CAPACITY, File::create(&path)?);
        let mode = if aead_enabled() {
            writer.write_all(AEAD_MAGIC)?;
            WriterMode::Aead {
                cipher: aead_cipher(),
                chunk_idx: 0,
                plain: Vec::with_capacity(BUF_CAPACITY),
            }
        } else {
            WriterMode::Plain
        };
        Ok(Self {
            path,
            writer,
            mode,
            count: 0,
            finished: false,
            _t: PhantomData,
        })
    }

    fn flush_aead_chunk(
        writer: &mut BufWriter<File>,
        cipher: &ChaCha20Poly1305,
        chunk_idx: &mut u64,
        plain: &mut Vec<u8>,
    ) -> io::Result<()> {
        if plain.is_empty() {
            return Ok(());
        }
        let plain_len = plain.len();
        let nonce = aead_nonce(*chunk_idx);
        let ad = aead_ad(T::BYTE_LEN, *chunk_idx, plain_len);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &ad, plain)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "FileVec AEAD encrypt failed"))?;
        writer.write_all(&(plain_len as u32).to_le_bytes())?;
        writer.write_all(plain)?;
        writer.write_all(&tag)?;
        plain.clear();
        *chunk_idx += 1;
        Ok(())
    }

    /// Append one element to the file.
    #[inline]
    pub fn write(&mut self, elem: &T) -> io::Result<()> {
        match &mut self.mode {
            WriterMode::Plain => elem.write_to(&mut self.writer)?,
            WriterMode::Aead {
                cipher,
                chunk_idx,
                plain,
            } => {
                let start = plain.len();
                plain.resize(start + T::BYTE_LEN, 0);
                elem.write_to(&mut &mut plain[start..start + T::BYTE_LEN])?;
                if plain.len() >= BUF_CAPACITY {
                    Self::flush_aead_chunk(&mut self.writer, cipher, chunk_idx, plain)?;
                }
            }
        }
        WRITE_BYTES.fetch_add(T::BYTE_LEN as u64, Ordering::Relaxed);
        self.count += 1;
        Ok(())
    }

    /// Flush, close, and hand ownership to a `FileVec<T>`.
    pub fn finish(mut self) -> io::Result<FileVec<T>> {
        if let WriterMode::Aead {
            cipher,
            chunk_idx,
            plain,
        } = &mut self.mode
        {
            Self::flush_aead_chunk(&mut self.writer, cipher, chunk_idx, plain)?;
        }
        self.writer.flush()?;
        self.finished = true;
        WRITE_STREAMS.fetch_add(1, Ordering::Relaxed);
        let path = self.path.clone();
        let len = self.count;
        // Drop self: BufWriter flushes empty buffer (no-op), File closes.
        // finished=true so drop() will not delete the file.
        Ok(FileVec {
            path,
            len,
            delete_on_drop: true,
            _t: PhantomData,
        })
    }
}

impl<T: StreamElem> Drop for FileVecWriter<T> {
    fn drop(&mut self) {
        let _ = self.writer.flush();
        if !self.finished {
            // finish() was never called — clean up the orphaned temp file.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// ── StreamElem impl for ark_bn254 curve points ────────────────────────────────
//
// Rust's coherence rules prevent implementing the same trait twice for
// `Affine<G1Config>` and `Affine<G2Config>` even though the Config types
// are distinct, because both are `Affine<_>` from an upstream crate.
//
// Solution: newtype wrappers `G1Disk` / `G2Disk` that own the underlying
// affine point. All FileVec<G1/G2> usage in this crate uses these newtypes.

use ark_bn254::{G1Affine, G2Affine};

/// Newtype wrapper for BN254 G1Affine enabling `StreamElem` impl.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Disk(pub G1Affine);

/// Newtype wrapper for BN254 G2Affine enabling `StreamElem` impl.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Disk(pub G2Affine);

impl From<G1Affine> for G1Disk {
    fn from(x: G1Affine) -> Self {
        G1Disk(x)
    }
}
impl From<G2Affine> for G2Disk {
    fn from(x: G2Affine) -> Self {
        G2Disk(x)
    }
}
impl From<G1Disk> for G1Affine {
    fn from(x: G1Disk) -> Self {
        x.0
    }
}
impl From<G2Disk> for G2Affine {
    fn from(x: G2Disk) -> Self {
        x.0
    }
}

impl StreamElem for G1Disk {
    // BN254 G1Affine uncompressed: x || y, each 32 bytes = 64 bytes total.
    const BYTE_LEN: usize = 64;

    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = [0u8; 64];
        self.0
            .serialize_uncompressed(&mut buf[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        w.write_all(&buf)
    }

    fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 64];
        r.read_exact(&mut buf)?;
        G1Affine::deserialize_uncompressed_unchecked(&buf[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
            .map(G1Disk)
    }
}

impl StreamElem for G2Disk {
    // BN254 G2Affine uncompressed: x=(x0,x1) || y=(y0,y1), each Fq2=64 bytes = 128 bytes.
    const BYTE_LEN: usize = 128;

    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = [0u8; 128];
        self.0
            .serialize_uncompressed(&mut buf[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        w.write_all(&buf)
    }

    fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 128];
        r.read_exact(&mut buf)?;
        G2Affine::deserialize_uncompressed_unchecked(&buf[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
            .map(G2Disk)
    }
}

// ── MatrixEntry: R1CS matrix entry stored on disk ────────────────────────────

/// One nonzero R1CS matrix entry `(row, col, value)` stored on disk.
/// Matrices are always col-sorted when stored as `FileVec<MatrixEntry<F>>`.
/// Layout: 4 bytes (row as u32 LE) | 4 bytes (col as u32 LE) | F::BYTE_LEN bytes.
#[derive(Clone, Copy, Debug)]
pub struct MatrixEntry<F: StreamElem + Copy> {
    pub row: u32,
    pub col: u32,
    pub val: F,
}

impl<F: StreamElem + Copy> StreamElem for MatrixEntry<F> {
    const BYTE_LEN: usize = 8 + F::BYTE_LEN; // 4 + 4 + F

    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.row.to_le_bytes())?;
        w.write_all(&self.col.to_le_bytes())?;
        self.val.write_to(w)
    }

    fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut buf4 = [0u8; 4];
        r.read_exact(&mut buf4)?;
        let row = u32::from_le_bytes(buf4);
        r.read_exact(&mut buf4)?;
        let col = u32::from_le_bytes(buf4);
        let val = F::read_from(r)?;
        Ok(MatrixEntry { row, col, val })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_file_vec_roundtrip() {
        let mut rng = test_rng();
        for n in [1usize, 4, 16, 64] {
            let data: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let fv = FileVec::from_vec(&data).unwrap();
            assert_eq!(fv.len(), n);
            let back = fv.into_vec().unwrap();
            assert_eq!(back, data, "roundtrip failed for n={n}");
        }
    }

    #[test]
    fn test_file_vec_reader_writer() {
        let mut rng = test_rng();
        let n = 32usize;
        let data: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // Write via writer
        let mut w = FileVecWriter::new().unwrap();
        for x in &data {
            w.write(x).unwrap();
        }
        let fv = w.finish().unwrap();
        assert_eq!(fv.len(), n);

        // Read via reader
        let mut r = FileVecReader::open(&fv).unwrap();
        let mut got = Vec::new();
        while let Some(x) = r.next().unwrap() {
            got.push(x);
        }
        assert_eq!(got, data, "reader/writer roundtrip failed");
    }

    #[test]
    fn test_file_vec_temp_cleanup() {
        let mut rng = test_rng();
        let data: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let fv = FileVec::from_vec(&data).unwrap();
        let path = fv.path.clone();
        assert!(path.exists(), "file should exist while FileVec is alive");
        drop(fv);
        assert!(!path.exists(), "file should be deleted after drop");
    }
}
