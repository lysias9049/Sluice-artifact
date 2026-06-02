# RW-Groth16 Artifact

This artifact contains the Rust prototype, benchmark drivers, raw
measurement summaries, bounded-memory logs, and reproduction notes used for
the RW-Groth16 evaluation.

## Contents

- `src/`: RW-Groth16 prototype implementation.
- `src/bin/`: benchmark and prove-only drivers.
- `tests/`: correctness tests for standard and streaming paths.
- `Experiments/`: CSV/log summaries, cgroup logs, and reproduction scripts.
- `Experiments/README_ARTIFACT.md`: paper-to-artifact mapping and expected
  bounded-memory outcomes.
- `Experiments/environment_linux_cgroup.md`: Linux cgroup environment notes.

Large generated directories such as `target/`, `target-linux/`,
`.cargo-linux/`, and `Experiments/*_data/` are intentionally excluded.

## Quick Start

Build and run the unit/integration tests:

```bash
cargo build --release
cargo test --release
```

Check the bounded-memory result files without rerunning the long experiments:

```bash
./Experiments/run_cgroup_n23.sh verify
```

See `Experiments/README_ARTIFACT.md` for exact commands, expected proof
validity, proof size, and the mapping from paper tables/figures to CSV and log
files.

## Scope

The main bounded-memory claim is a prove-only claim after CRS/QAP/witness
streams have been materialized.  The `N=2^23` cgroup logs compare standard
Groth16 and RW-Groth16 at the same size.  The `N=2^25` capped RW-RW run is an
RW-RW-only scaling check, not a same-size standard-vs-RW comparison.
