//! Benchmark harness: wall-clock timing and peak-RSS measurement.
//!
//! # Timing functions
//!
//! - [`measure`]       – single run (for large-N experiments where 1 run ≥ 1s)
//! - [`measure_n`]     – n repeated runs → median duration (for fast operations)
//! - [`measure_stats`] – n repeated runs → (median, mean, std_dev) in seconds
//!
//! # Memory measurement note
//! `peak_rss_bytes()` calls `getrusage(RUSAGE_SELF)` which returns the
//! *lifetime peak* RSS for the whole process, not a point-in-time snapshot.
//! To measure the memory consumed by a single phase, call it immediately
//! before and after the phase and take the difference.  The difference is
//! non-negative and represents how much the peak grew during that phase.

use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Timing
// ─────────────────────────────────────────────────────────────────────────────

/// Single run: return the output and elapsed wall-clock time.
///
/// Use for operations that take ≥ 1 second (large-N prove/verify).
pub fn measure<T, F: FnOnce() -> T>(f: F) -> (T, Duration) {
    let t0 = Instant::now();
    let v = f();
    (v, t0.elapsed())
}

/// Repeated runs: call `f` `n` times, return the **last output** and
/// the **median** duration across all `n` runs.
///
/// Use for fast operations (NTT, MSM, R1CS phases) where a single run
/// has high OS-scheduling noise.  Recommended: n = 5 or 7.
pub fn measure_n<T, F: Fn() -> T>(f: F, n: usize) -> (T, Duration) {
    assert!(n >= 1, "measure_n: n must be ≥ 1");
    let mut times = Vec::with_capacity(n);
    let mut last = None;
    for _ in 0..n {
        let t0 = Instant::now();
        let v = f();
        times.push(t0.elapsed());
        last = Some(v);
    }
    times.sort();
    let median = times[n / 2]; // lower-median for even n
    (last.unwrap(), median)
}

/// Statistics across `n` runs: (last_output, median_s, mean_s, std_dev_s).
///
/// Useful when the CSV should include mean ± std for the paper.
pub fn measure_stats<T, F: Fn() -> T>(f: F, n: usize) -> (T, f64, f64, f64) {
    assert!(n >= 2, "measure_stats: n must be ≥ 2");
    let mut times = Vec::with_capacity(n);
    let mut last = None;
    for _ in 0..n {
        let t0 = Instant::now();
        let v = f();
        times.push(t0.elapsed().as_secs_f64());
        last = Some(v);
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = times[n / 2];
    let mean = times.iter().sum::<f64>() / n as f64;
    let var = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
    let std_dev = var.sqrt();
    (last.unwrap(), median, mean, std_dev)
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory (peak RSS)
// ─────────────────────────────────────────────────────────────────────────────

/// Process lifetime peak RSS in **bytes**.
///
/// - macOS   : `ru_maxrss` is in bytes.
/// - Linux   : `ru_maxrss` is in KiB → multiplied by 1024.
/// - Windows : `PeakWorkingSetSize` from `K32GetProcessMemoryInfo` (bytes).
/// - Other   : returns 0.
///
/// This value is monotonically non-decreasing over the process lifetime.
/// To measure the memory consumed by a single phase, call it before and
/// after that phase and take the difference.
pub fn peak_rss_bytes() -> u64 {
    peak_rss_impl()
}

/// Current RSS (physical pages currently in RAM) in **bytes**.
///
/// Unlike `peak_rss_bytes`, this value can decrease when memory is freed.
/// Use this for point-in-time snapshots during a benchmark phase.
///
/// - macOS / Linux : reads `/proc/self/status` VmRSS on Linux; falls back
///   to `peak_rss_bytes` on macOS (no cheap current-RSS syscall).
/// - Windows       : `WorkingSetSize` from `K32GetProcessMemoryInfo`.
/// - Other         : returns 0.
pub fn current_rss_bytes() -> u64 {
    current_rss_impl()
}

/// Process lifetime peak RSS in **MiB** (convenient for printing).
pub fn peak_rss_mb() -> f64 {
    peak_rss_bytes() as f64 / (1024.0 * 1024.0)
}

/// Current RSS in **MiB**.
pub fn current_rss_mb() -> f64 {
    current_rss_bytes() as f64 / (1024.0 * 1024.0)
}

// ── macOS ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn peak_rss_impl() -> u64 {
    unsafe {
        let mut u: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut u);
        u.ru_maxrss as u64
    }
}

#[cfg(target_os = "macos")]
fn current_rss_impl() -> u64 {
    // mach task_info gives the current (not peak) resident size on macOS.
    extern "C" {
        fn mach_task_self() -> u32;
        fn task_info(
            target_task: u32,
            flavor: u32,
            task_info_out: *mut u64,
            task_info_count: *mut u32,
        ) -> i32;
    }
    const MACH_TASK_BASIC_INFO: u32 = 20;
    // mach_task_basic_info struct: virtual_size, resident_size, resident_size_max,
    // user_time (2×u32), system_time (2×u32), policy, suspend_count  → 12 × u32 = 48B
    let mut info = [0u64; 6]; // 48 bytes
    let mut count: u32 = 12; // MACH_TASK_BASIC_INFO_COUNT
    unsafe {
        task_info(
            mach_task_self(),
            MACH_TASK_BASIC_INFO,
            info.as_mut_ptr(),
            &mut count,
        );
        // resident_size is at byte offset 8 (second u64 in the struct)
        info[1]
    }
}

// ── Linux ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn peak_rss_impl() -> u64 {
    unsafe {
        let mut u: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut u);
        (u.ru_maxrss as u64).saturating_mul(1024)
    }
}

#[cfg(target_os = "linux")]
fn current_rss_impl() -> u64 {
    // Parse VmRSS from /proc/self/status (value is in kB).
    let Ok(s) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            if let Ok(kb) = rest.trim().trim_end_matches(" kB").parse::<u64>() {
                return kb.saturating_mul(1024);
            }
        }
    }
    0
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod win_mem {
    // PROCESS_MEMORY_COUNTERS as defined in <psapi.h>.
    // K32GetProcessMemoryInfo is exported from kernel32.dll on Windows 7+
    // (no extra link directive needed — kernel32 is always linked by Rust on Windows).
    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct PROCESS_MEMORY_COUNTERS {
        pub cb: u32,
        pub PageFaultCount: u32,
        pub PeakWorkingSetSize: usize,
        pub WorkingSetSize: usize,
        pub QuotaPeakPagedPoolUsage: usize,
        pub QuotaPagedPoolUsage: usize,
        pub QuotaPeakNonPagedPoolUsage: usize,
        pub QuotaNonPagedPoolUsage: usize,
        pub PagefileUsage: usize,
        pub PeakPagefileUsage: usize,
    }

    extern "system" {
        pub fn GetCurrentProcess() -> *mut core::ffi::c_void;
        pub fn K32GetProcessMemoryInfo(
            Process: *mut core::ffi::c_void,
            ppsmemCounters: *mut PROCESS_MEMORY_COUNTERS,
            cb: u32,
        ) -> i32;
    }
}

#[cfg(windows)]
fn query_pmc() -> win_mem::PROCESS_MEMORY_COUNTERS {
    unsafe {
        let h = win_mem::GetCurrentProcess();
        let mut pmc: win_mem::PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        pmc.cb = std::mem::size_of::<win_mem::PROCESS_MEMORY_COUNTERS>() as u32;
        win_mem::K32GetProcessMemoryInfo(h, &mut pmc, pmc.cb);
        pmc
    }
}

#[cfg(windows)]
fn peak_rss_impl() -> u64 {
    query_pmc().PeakWorkingSetSize as u64
}

#[cfg(windows)]
fn current_rss_impl() -> u64 {
    query_pmc().WorkingSetSize as u64
}

// ── Fallback ──────────────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn peak_rss_impl() -> u64 {
    0
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn current_rss_impl() -> u64 {
    0
}

// ── Memory-limit helper (Unix only) ──────────────────────────────────────────

/// Impose a hard virtual-address-space limit on the **current process**.
///
/// Any allocation that would push virtual memory beyond `bytes` will fail,
/// causing Rust's global allocator to abort (OOM).  Call this at process
/// startup (e.g., in a worker subprocess) before any large allocations.
///
/// Returns `true` on success, `false` if the OS rejected the limit.
///
/// **Platform notes**
/// - macOS / Linux : uses `setrlimit(RLIMIT_AS, ...)`.
/// - Windows       : no-op, always returns `false`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn set_address_space_limit(bytes: u64) -> bool {
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        libc::setrlimit(libc::RLIMIT_AS, &limit) == 0
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn set_address_space_limit(_bytes: u64) -> bool {
    false
}
