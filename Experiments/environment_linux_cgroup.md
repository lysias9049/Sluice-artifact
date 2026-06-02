# Linux Cgroup Experiment Environment

This file records the host/container environment for the fresh Apple Silicon
rerun started on 2026-05-29.  It intentionally uses an anonymous host label and
omits local serial numbers, UUIDs, user names, and private paths.

## Host

- Host label: `m1pro-32gb-20260529`
- Machine class: MacBook Pro 16-inch, 2021
- CPU: Apple M1 Pro, 10 cores (8 performance, 2 efficiency)
- RAM: 32 GB unified memory
- macOS: Tahoe 26.5, build 25F71
- Darwin kernel: 25.5.0, arm64
- Repository commit at environment capture: `2199b96`

## Native Toolchain

- Rust host: `aarch64-apple-darwin`
- Rust version: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo version: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Docker CLI: `Docker version 29.5.2, build 79eb04c`

## Docker / Linux Cgroup Backend

- Docker server version: `29.5.2`
- Docker OS type: Linux
- Docker architecture: `aarch64`
- Docker storage driver: `overlayfs`
- Cgroup version: v2
- Docker root dir inside VM: `/var/lib/docker`
- Docker VM memory at capture time: `8321712128` bytes (~7.75 GiB)

For the full `N=2^23` bounded-memory rerun, Docker Desktop Resources should be
raised to at least 20 GiB and preferably 24 GiB before running materialization
and the 16 GiB standard-prover cap.

## Linux Binaries

The fresh Docker build produced Linux aarch64 release binaries:

- `target-linux/release/rw_prove_only`: ELF 64-bit ARM aarch64
- `target-linux/release/std_prove_only`: ELF 64-bit ARM aarch64

## Measurement Interpretation

- The bounded-memory experiment uses Docker cgroup memory caps on Linux.
- `/usr/bin/time -v` reports the worker process maximum resident set size
  inside the Linux container.
- The macOS `rss_delta_mb` columns in native CSVs and Linux cgroup MaxRSS are
  related but not identical metrics.  Paper claims should name which metric is
  being used.
- Setup/materialization is outside the capped prove-only worker unless a command
  explicitly states otherwise.

## Fresh-Rerun Data Hygiene

Pre-rerun data from the previous environment were moved to:

```text
Experiments/archive/20260529_140207_pre_m1_fresh_rerun
```

New files generated directly under `Experiments/` after this point are intended
to be Apple Silicon fresh-rerun data.
