# RW-Groth16 Experiment Artifact Notes

This directory contains the canonical CSV/log files used by the evaluation
section of the RW-Groth16 paper.  The main bounded-memory claim is the
`N=2^23` Linux cgroup experiment in `cap_logs/`.

The structured MiMC-style Merkle sanity check and native arkworks Groth16
baseline are auxiliary external-validity experiments.  They should not be
used as the main RW-RW memory evidence.

Archived data and large materialized input directories are excluded from
this distribution. Generate fresh inputs using the root README workflow.

## Bounded-Memory Result

The bounded-memory experiment separates materialization from proving:

1. CRS, QAP, and witness data are materialized first.
2. Fresh prove-only workers are then launched under Linux cgroup memory caps.
3. The capped workers produce or fail to produce Groth16 proofs.

Canonical bounded-memory files:

```text
cap_logs/rw_rw_8gb_23.csv
cap_logs/rw_rw_8gb_23.stderr
cap_logs/rw_rw_8gb_23.exit
cap_logs/rw_rw_8gb_23.wall_s

cap_logs/std_8gb_23.csv
cap_logs/std_8gb_23.stderr
cap_logs/std_8gb_23.exit
cap_logs/std_8gb_23.wall_s

cap_logs/std_12gb_23.csv
cap_logs/std_12gb_23.stderr
cap_logs/std_12gb_23.exit
cap_logs/std_12gb_23.wall_s

cap_logs/std_16gb_23.csv
cap_logs/std_16gb_23.stderr
cap_logs/std_16gb_23.exit
cap_logs/std_16gb_23.wall_s
```

Expected core results:

```text
RW-RW, 8GB cap: exit=0, valid=true, proof_bytes=128
Std,   8GB cap: exit=137, terminated by SIGKILL near 8GB RSS
Std,  12GB cap: exit=137, terminated by SIGKILL near 12GB RSS
Std,  16GB cap: exit=0, valid=true, proof_bytes=128
```

Observed values from the current artifact:

```text
RW-RW 8GB:
  wall time: 2720 s = 45.3 min
  proof: valid, 128 bytes
  max RSS: 29828 KiB = 29.1 MiB
  I/O: read 223.4 GiB, write 209.2 GiB, 2861 stream openings

Std 8GB:
  exit: 137
  stderr: Command terminated by signal 9
  wall time: 21 s (GNU time: 21.61 s)
  max RSS: 8354600 KiB = 7.97 GiB

Std 12GB:
  exit: 137
  stderr: Command terminated by signal 9
  wall time: 32 s (GNU time: 32.35 s)
  max RSS: 12534912 KiB = 11.95 GiB

Std 16GB:
  exit: 0
  wall time: 655 s = 10.9 min
  proof: valid, 128 bytes
  max RSS: 13962508 KiB = 13.3 GiB
```

## Quick Verification

From the `rw-groth16/` crate directory:

```bash
./Experiments/run_cgroup_n23.sh verify
```

This does not rerun the long experiment.  It checks that the expected CSV and
log files are present and contain the success/failure outcomes used in the
paper.

## Reproducing the Cgroup Runs

The commands below are the historical experiment workflow and write into
`Experiments/cap_logs/`. For AE reproduction, use the isolated Docker
workflow in the artifact root `README.md` (`AE/run.py`) to preserve these
records. Historical exit-137 logs do not contain direct cgroup OOM-event
measurements and should not be described as independently confirmed OOM.


The scripts assume Docker/Colima or another Docker-compatible Linux backend.
The cgroup limit must be enforced by Docker, not by macOS `ulimit`.

Build the image and Linux binaries:

```bash
./Experiments/run_cgroup_n23.sh build-image
./Experiments/run_cgroup_n23.sh build
```

If the precomputed materialized directories are missing, create them:

```bash
./Experiments/run_cgroup_n23.sh materialize-rw
./Experiments/run_cgroup_n23.sh materialize-std
```

Run the three canonical capped workers:

```bash
./Experiments/run_cgroup_n23.sh run-rw-8gb
./Experiments/run_cgroup_n23.sh run-std-8gb
./Experiments/run_cgroup_n23.sh run-std-12gb
./Experiments/run_cgroup_n23.sh run-std-16gb
```

Or run them sequentially:

```bash
./Experiments/run_cgroup_n23.sh run-all-capped
```

The long-running commands should be wrapped by `caffeinate -dimsu` on macOS if
the machine might sleep.

## Paper Mapping

Use these files for the bounded-memory table/prose:

```text
RW-RW 8GB row:
  cap_logs/rw_rw_8gb_23.csv
  cap_logs/rw_rw_8gb_23.stderr
  cap_logs/rw_rw_8gb_23.exit
  cap_logs/rw_rw_8gb_23.wall_s

Std 8GB row:
  cap_logs/std_8gb_23.stderr
  cap_logs/std_8gb_23.exit
  cap_logs/std_8gb_23.wall_s

Std 16GB row:
  cap_logs/std_16gb_23.csv
  cap_logs/std_16gb_23.stderr
  cap_logs/std_16gb_23.exit
  cap_logs/std_16gb_23.wall_s
```

`Std 12GB` is a sensitivity point showing that the standard prove-only
worker still fails below 16GB:

```text
cap_logs/std_12gb_23.stderr
cap_logs/std_12gb_23.exit
cap_logs/std_12gb_23.wall_s
```

Do not use the Linux 29.1 MiB RW-RW RSS value to replace the macOS five-run
clean prove-only scaling point (`rw_prove_only_23_repeats.csv`).  The bounded
memory experiment is a separate cgroup success/failure result.

## Structured Workload and Arkworks Baseline

Structured workload sanity-check files:

```text
real_workload_mimc_merkle_16_20_r1.csv
real_workload_mimc_merkle_16_20_r1.log
real_workload_mimc_merkle_16_18_r3.csv
real_workload_mimc_merkle_16_18_r3.log
```

Native arkworks Groth16 baseline files:

```text
production_baseline_arkworks_16_20_r1.csv
production_baseline_arkworks_16_20_r1.log
production_baseline_arkworks_16_18_r3.csv
production_baseline_arkworks_16_18_r3.log
production_baseline_arkworks_21_22_r3.csv
production_baseline_arkworks_21_22_r3.log
production_baseline_arkworks_21_22_r3_summary.csv
production_baseline_arkworks_23_r1.csv
production_baseline_arkworks_23_r1.log
production_baseline_arkworks_21_23_summary.csv
```

Reproduction commands:

```bash
cargo build --release --bin real_workload_bench --bin production_baseline_bench

target/release/real_workload_bench mimc_merkle 16 20 1 \
  > Experiments/real_workload_mimc_merkle_16_20_r1.log \
  2> Experiments/real_workload_mimc_merkle_16_20_r1.csv

target/release/real_workload_bench mimc_merkle 16 18 3 \
  > Experiments/real_workload_mimc_merkle_16_18_r3.log \
  2> Experiments/real_workload_mimc_merkle_16_18_r3.csv

target/release/production_baseline_bench mimc_merkle 16 20 1 \
  > Experiments/production_baseline_arkworks_16_20_r1.log \
  2> Experiments/production_baseline_arkworks_16_20_r1.csv

target/release/production_baseline_bench mimc_merkle 16 18 3 \
  > Experiments/production_baseline_arkworks_16_18_r3.log \
  2> Experiments/production_baseline_arkworks_16_18_r3.csv
```

The MiMC-style workload is field-native and application-shaped, but it is not
a production hash benchmark.  The arkworks baseline is included to show a
native production-oriented Groth16 memory/time point; it is expected to be much
faster than the single-threaded streaming prototype.  Its `prove_ms` column is
the arkworks proof-generation call after arkworks setup has produced a proving
key.  Its RSS columns are process high-water marks from the same worker: setup
runs first, then one or more prove calls, so `peak_rss_mb` includes memory
retained after setup/key generation and should not be read as the same metric
as the clean RW-RW prove-only `Delta RSS` claim.

The paper's appendix table uses `production_baseline_arkworks_21_23_summary.csv`.
At `N=2^21` and `N=2^22` the arkworks rows are three-run summaries; the
`N=2^23` row is a single production-oriented sanity run.

## Protected FileVec / AEAD Evidence

The default large-scale proving results use plaintext `FileVec` streams on
trusted local storage.  The artifact also includes an optional
ChaCha20-Poly1305 AEAD `FileVec` mode and two bounded sanity checks.

Storage-layer microbenchmark summaries:

```text
filevec_crypto_microbench_1g_r5.csv
filevec_crypto_microbench_25g_r1.csv
filevec_crypto_microbench_summary.csv
```

End-to-end AEAD prove-only sanity summaries:

```text
rw_prove_only_18_aead_prove_only.csv
rw_prove_only_18_aead_prove_only.stderr
rw_prove_only_18_aead.log
rw_prove_only_20_aead.csv
rw_prove_only_20_aead.log
rw_prove_only_aead_summary.csv
```

The AEAD runs use a fixed benchmark key and are included only to show that
the sequential `FileVec` access pattern is compatible with authenticated
encryption.  They do not claim production key management or large-scale
encrypted proving.

Useful commands:

```bash
cargo build --release --bin filevec_crypto_microbench

target/release/filevec_crypto_microbench 1 5 \
  > Experiments/filevec_crypto_microbench_1g_r5.csv

target/release/filevec_crypto_microbench 25 1 \
  > Experiments/filevec_crypto_microbench_25g_r1.csv

RWG_FILEVEC_AEAD=1 target/release/rw_prove_only 20 \
  Experiments/rw_prove_only_20_aead_data \
  Experiments/rw_prove_only_20_aead.csv
```

## Direct Scaling Repeat Evidence

The canonical direct scaling curve uses `rw_rw_direct_scaling.csv` and
`rw_rw_direct_scaling_repeats.csv`.  The file
`rw_prove_only_23_repeat_summary.csv` records an auxiliary plaintext
`N=2^23` repeat after the AEAD code path was added.  It is a mixed-commit
repeat, so it is repeat evidence rather than a replacement for the canonical
direct-scaling row.

Storage-throughput values in the appendix are summarized in:

```text
storage_throughput_summary.csv
```

## Correctness and Artifact Anonymity

The CI-sized proof-equivalence check is:

```bash
cargo test --test streaming_e2e test_streaming_prove_n16 -- --exact
```

The test uses fixed prover randomness and asserts that the streaming and
standard proofs serialize to identical 128-byte Groth16 proofs.

By default, benchmark binaries now write `artifact-host` in the `machine_id`
CSV column.  Set `RWG_RECORD_MACHINE_ID=1` only for private local debugging.
Before public artifact release, verify that CSVs, logs, scripts, and git
metadata contain no author names, usernames, hostnames, absolute local paths,
or non-anonymous remotes.
