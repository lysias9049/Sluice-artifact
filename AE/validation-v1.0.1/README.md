# Local v1.0.1 candidate validation

These are new harness checks, separate from the immutable v1.0.0 records in
`../validation/`. See `summary.json` for results and limitations.

## Build provenance

The standard `python3 AE/run.py build` attempt stopped while querying
`rust:1.96.0-bookworm` metadata on Docker Hub. No source compilation error was
reported. For local validation, `Dockerfile.validation` applied the runtime
permission change and new AE files to the existing `sluice-ae:release-check`
image. All 32 Cargo/Rust source files inside the derived image were compared
byte-for-byte to the current artifact. `build.json` explicitly records this
alternative build; it does not certify a complete standard Dockerfile build.

For a fresh ordinary build with network access, run from the artifact root:

```sh
python3 AE/run.py build --work /path/to/fresh-work
python3 AE/run.py test --work /path/to/fresh-work
python3 AE/run.py smoke --work /path/to/fresh-work
docker run --rm --network none --memory 256m --memory-swap 256m \
  --user "$(id -u):$(id -g)" sluice-ae:1.0.1 python3 AE/test_harness.py
```

## Checks

- `test-*`: normal Cargo suite under the host UID/GID; 42 passed, 0 failed,
  2 ignored. Cargo cache permissions and limit monitoring were active.
- `materialize-*-n10-*` and successful `prove-*-n10-256m-*`: fresh small
  inputs; both exported proofs verified and have exactly 128 bytes.
- `prove-rw-n10-8g-*`: during separate runs, `docker update --memory-swap -1`
  or `docker update --memory 512m --memory-swap 512m` changed only the selected
  test container. Both cases returned `invalid_limits`, `limits_valid=false`,
  and `passed=false`; file-write notifications caught the changes.
- `materialize-std-n16-*` and `prove-std-n16-64m-*`: small real OOM regression,
  using `run_case(..., 'prove', 'std', 16, '64m', 'oom')`. GNU time reported
  exit 137 and cgroup `oom_kill` increased by one. Monitoring remained valid,
  so the expected OOM passed. `64m` is an internal regression cap, not an
  added public `--cap` choice or a paper measurement.
- `python3 AE/test_harness.py` in the Linux image passed all 14 checks,
  including a limit change restored before the next poll and cleanup after
  a simulated host-side PermissionError. macOS skips its seven Linux watch
  tests; the Linux run skipped none.

The full N=2^23 experiment and native x86_64 rootful Docker/systemd scenario
were not rerun here. The independent AE x86_64 results refer to v1.0.0.
