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
- `Experiments/filevec_crypto_microbench_*.csv` and
  `Experiments/rw_prove_only_aead_summary.csv`: optional AEAD FileVec
  microbenchmark and small end-to-end proving sanity summaries.
- `Experiments/production_baseline_arkworks_21_23_summary.csv`: native
  arkworks structured-workload baseline summary through `N=2^23`.

Large generated directories such as `target/`, `target-linux/`,
`.cargo-linux/`, and `Experiments/*_data/` are intentionally excluded.

## Quick Start

### Docker evaluation workflow

Run the following from this directory. Python 3.9+ is required on the host;
Docker must provide Linux containers with cgroup v2. The Dockerfile installs
Rust 1.96.0, Python, and GNU time. The initial build needs network access;
measurement containers run with networking disabled.

```bash
python3 AE/run.py build
python3 AE/run.py test
python3 AE/run.py smoke
```

The smoke test generates fresh inputs at `N=2^10` and runs both prove-only
drivers. Each successful prover must verify its proof and export a
128-byte `proof.bin`. This is a functionality check, not evidence for the
large-input memory bound.

For the main comparison:

```bash
python3 AE/run.py full
python3 AE/run.py results
```

`full` first generates RW and standard inputs at `N=2^23`, then runs
Full-RW at 8 GiB, standard at 8 GiB, and standard at 16 GiB. Expected
outcomes are `verified`, `oom`, and `verified`, respectively. Swap is
disabled for these containers. Input generation has a separate 22 GiB cap.
The current runner checks for at least 23 GiB of Docker RAM and 100 GiB of
free disk before large-input preparation; allocate at least 24 GiB to Docker for this workflow. These are
provisioning settings, not measured minimum requirements. See
`AE/REQUIREMENTS.md` for complete hardware and software requirements.

### Prepare inputs and rerun individual cases

`prepare` materializes one variant's inputs; `prove` reuses those inputs in
a fresh capped container. Use the same work directory and image for all commands:

```bash
python3 AE/run.py prepare --variant rw --log-n 23
python3 AE/run.py prepare --variant std --log-n 23
python3 AE/run.py prove --variant rw --log-n 23 --cap 8g --expect verified
python3 AE/run.py prove --variant std --log-n 23 --cap 8g --expect oom
python3 AE/run.py prove --variant std --log-n 23 --cap 12g --expect oom
python3 AE/run.py prove --variant std --log-n 23 --cap 16g --expect verified
```

Skip `prepare` if `full` has already materialized the same inputs in this work
directory. The cap choices are `256m`, `1g`, `8g`, `12g`, and `16g` (binary
MiB/GiB). `--cap` and `--expect` apply to `prove`; preparation uses a separate
22 GiB cap. An optional sensitivity run is:

```bash
python3 AE/run.py prove --variant rw --log-n 23 --cap 256m --expect verified
```

An AE reviewer independently reproduced the v1.0.0 workflow on x86_64 Linux
with native Docker 29.8 and reported standard OOM at 12 GiB and Full-RW
verification at 256 MiB. These are reviewer-reported observations, separate
from the retained author-side ARM64 measurements in `AE/validation/`.

Results go to `.ae-work/logs/`, inputs to `.ae-work/data/`, and temporary
streams to `.ae-work/tmp/`. Use `--work /path/to/work` consistently on all
commands to choose another location. Historical `Experiments/` files are
not overwritten. Existing nonempty input directories are not overwritten;
use a fresh work directory and build record for an independent full run.

Each case retains stdout, stderr, GNU time measurements, cgroup memory
events, selected Docker state, and a JSON outcome. Exit code 137 alone is
not treated as proof of OOM: the runner checks cgroup OOM events or Docker's
OOMKilled status. A user-interrupted run is not a memory-limit result.

Containers run with the host user's UID/GID, so new work files remain writable
on native Linux with rootful Docker. The image permits that user to access
Cargo's test cache; no host ACL configuration is needed for a fresh work
directory. If an older run left root-owned files, use a fresh `--work` directory
or have its owner restore access before reuse. Containers are removed even if
host-side logging fails or the command is interrupted.

### Memory-limit integrity

Before starting the measured command, the worker checks the requested
`memory.max` and requires `memory.swap.max=0`. It polls both every 100 ms and
also watches the files with Linux inotify. Any observed limit mismatch, file
change notification (even if the value is restored), unavailable watch, read
error, or polling gap over one second invalidates the case. On a detected
violation the measured process group is killed and the outcome is
`invalid_limits`, never an expected OOM success. A complete valid monitor
record, matching Docker settings, and the expected outcome are all required
for `passed=true`; missing worker results cannot pass, including after OOM.

`cap-monitor.json` records the sampling interval, sample count, largest gap,
last observed values, and violations. The monitor is an operational integrity
check, not a proof against arbitrary privileged host changes; polling alone
cannot rule out changes between samples, and file notifications cover writes
visible through the watched files. A file rewrite that preserves the limit is
also conservatively rejected. The monitor shares the container's cap; if it
is killed and cannot finish its record, the host rejects the case.

The Linux harness regression tests run with `python3 AE/test_harness.py`.

### Native build and historical records

Build and run the unit/integration tests:

```bash
cargo build --locked --release
cargo test --locked --release
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

The two standalone drivers use the same workload size but distinct fixed
benchmark seeds; their independently generated CRS/witness data are not
identical. The byte-equivalence tests have their own identical-input and
fixed-randomness conditions. The prototype's deterministic benchmark setup
is for reproduction, not production trusted-setup or key management.

## AE rehearsal results and release

Working release: 1.0.1; see `CHANGELOG.md`. The published AE-evaluated v1.0.0
is preserved at DOI `10.5281/zenodo.22763230`. The v1.0.1 DOI will be added
after publication; that existing DOI identifies v1.0.0, not these updates.

Local candidate validation is in `AE/validation-v1.0.1/`: 42 Rust tests
passed (two ignored), 14 Linux harness checks passed, and both fresh N=2^10
smoke proofs verified with 128 bytes. Live changes to swap and memory settings
were rejected, while a small N=2^16 standard OOM under 64 MiB was accepted
with valid monitoring. The latter is a harness check, not new paper evidence.
Validation used an offline image derived from the previously validated image;
all Rust/Cargo sources were compared byte-for-byte. The standard Dockerfile
build's base-image lookup timed out. The full N=2^23 workflow and native
x86_64/systemd scenario have not been rerun with this candidate.

The historical v1.0.0 full N=2^23 rehearsal completed successfully on Linux ARM64:

| Stage | Wall time | Result |
|---|---:|---|
| RW input generation | 7464.672 s | Completed; 10401875346 bytes |
| Standard input generation | 7372.019 s | Completed; 10603201903 bytes |
| Full-RW, 8 GiB cap | 2787.984 s | Verified, 128-byte proof; peak process RSS 28.5 MiB |
| Standard, 8 GiB cap | 18.440 s | Exit 137; cgroup oom_kill increased by 1 |
| Standard, 16 GiB cap | 539.910 s | Verified, 128-byte proof; peak process RSS 13635.3 MiB |

Total: approximately 5 hours 3 minutes excluding build. Setup is not part
of the prove-phase memory claim. Raw rehearsal records and exported proofs
are in `AE/validation/`. The 42 passing tests and small-input smoke checks
are also recorded there; two larger tests are ignored by the default suite.

Read `AE/CLAIMS.md` for paper-to-data mapping and limits, and
`AE/DEPENDENCIES.md` for dependency license declarations. The historical tested runtime
fingerprint is in `AE/validation/build.json`; documentation additions do not
change the source fingerprint used by the runner. New builds can have
new image hashes because base images and OS packages are not fully pinned.

## License

The software in this package is released under the MIT license; see
`LICENSE`. Dependencies retain their respective licenses.
