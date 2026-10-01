# Claims and evidence

This document maps the accepted manuscript to the supplied evidence.
Table/figure numbers follow the current accepted-paper build. The evaluation
scope is the prove phase after materialization unless explicitly stated.

## Primary reproduction request

| Claim | Paper | Command from artifact root | Input | Output and expected result |
|---|---|---|---|---|
| The implementation produces verifier-accepted standard-format Groth16 proofs | Correctness and evaluation | `python3 AE/run.py test`, then `python3 AE/run.py smoke` | Generated small instances, smoke at N=2^10 | Test logs; both smoke proofs verify and serialize to 128 bytes |
| Full-RW can prove at N=2^23 under an 8 GiB no-swap cap | Table 3 | `python3 AE/run.py full` | Fresh materialized CRS/QAP/witness streams | RW 8 GiB case: verified; standard 8 GiB case: OOM evidence; standard 16 GiB case: verified |

First run `python3 AE/run.py build`. The default output directory is
`.ae-work`; use the same `--work` argument throughout if relocating it.
See the root README for the current resource settings. The full rehearsal took approximately 5 hours 3 minutes, excluding build.
See `AE/REQUIREMENTS.md` and `AE/validation/` for resources and raw results.

The full suite includes input generation before any prove-phase cap is
applied. Per-case `result.json`, `stdout.txt`, `stderr.txt`, `time.txt`,
`cgroup.*.json`, and `docker.json` record the outcome. Successful proving
also exports `proof.bin`. For v1.0.1, `cap-monitor.json` records runtime limit
checks and file-write notifications. The runner's `passed` flag requires the
expected outcome and complete valid limit evidence with matching Docker
settings; it is not an AE badge decision. Historical v1.0.0 records used the
previous harness and remain unchanged.

## Published-data mapping

All paths below are relative to `Experiments/`. Reading these files does
not constitute an independent reproduction. Historical files are retained
unchanged; new measurements are saved separately.

| Paper item | Retained data |
|---|---|
| Table 3: N=2^23 capped comparison | `cap_logs/rw_rw_8gb_23.*`, `cap_logs/std_8gb_23.*`, `cap_logs/std_16gb_23.*` |
| Table 3: N=2^25 Full-RW-only case | `cap_logs/rw_rw_8gb_25.*` |
| Table 4 and Figure 1: direct Full-RW scaling | `rw_rw_direct_scaling.csv`, `rw_rw_direct_scaling_repeats.csv`; standard comparison point in `std_prove_only_23.csv` |
| Figure 2: NTT and MSM components | `ntt_bench_16_r5.csv`, `msm_tradeoff_4096.csv` |
| Table 5: structured workload | `real_workload_mimc_merkle_20_20_r3.csv`, `production_baseline_arkworks_21_23_summary.csv`, and their corresponding raw runs |
| Table 6: R1CS phase breakdown | `r1cs_bench_14_d4_r5.csv` |

Tables 1 and 2 are analytical comparisons, not measured CSV tables.
Additional experiments are described in `Experiments/README_ARTIFACT.md`.
Do not overwrite these files when running historical benchmark commands.

## Interpretation limits

- Exact running times need not match across machines. Record hardware,
  architecture, toolchain, thread settings, and storage characteristics.
- Peak RSS, cgroup memory (which includes additional charged memory),
  cumulative I/O, and peak disk occupancy are different measurements.
- The Full-RW memory evidence uses `streaming_prove_rw`. Timing evidence
  from `streaming_prove_disk` must not be substituted for it.
- The N=2^25 Full-RW-only case does not establish a same-size standard
  prover comparison. It is not part of the primary three-case AE rerun.
- Historical SIGKILL records alone do not prove cgroup OOM; the new runner
  records explicit OOM events. User interruption is not an OOM result.
- The byte-equivalence integration test exercises `streaming_prove` under
  fixed randomness; it does not by itself establish byte equivalence for
  all Full-RW paths. Full-RW verification has separate test coverage.
- Structured-workload baseline process RSS includes setup and retained
  proving-key memory, unlike a fresh prove-only worker's measurements.
- These experiments do not compare Full-RW against a standard prover with
  swap enabled and do not establish superiority over swap.
