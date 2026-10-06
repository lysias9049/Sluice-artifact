# Release changes

## 1.0.2 — published, 2026-10-06

Review #8B identified two additional packaging issues:

- Remove the hard-coded BuildKit-only `--progress=plain` option from the
  Docker build command. Use the configured Docker builder with common flags
  and retain its output in the build log. Document BuildKit/Buildx and the
  legacy backend where it remains available.
- Explain the optional Bash `install.sh` helper, its packaged and standalone
  locations, argument forwarding, and the separate test/smoke/full steps.
- Clarify Docker-group and sudo invocation accounts, and update prior-version
  publication links and validation history.
- Add two CLI compatibility regressions: a legacy-style build creates a
  usable build record, and a failed build never creates a success record.

Validation and its limits are recorded in `AE/validation-v1.0.2/`.
Both real BuildKit and legacy-backend builds passed on Linux ARM64 Docker
Desktop, followed by 42 Rust tests (two ignored) and both verified 128-byte
N=2^10 smoke proofs on each image. All 16 Linux harness tests passed, and
both packaged and standalone helper build invocations passed.
The Rust prover, circuits, proof format, and historical experiment records
are unchanged. No full N=2^23 or native Ubuntu x86_64 rerun was performed.
Published v1.0.2 DOI:
[10.5281/zenodo.23179739](https://doi.org/10.5281/zenodo.23179739).
The immutable Zenodo archive retains the documentation prepared before
publication; the repository documentation now includes this publication link.

## 1.0.1 — published, 2026-10-01

AE feedback on v1.0.0 motivated these changes:

- Run measurement containers with the host UID/GID and make the image's Cargo
  test cache writable for that user. Fresh work directories require no ACL fix.
- Always attempt container cleanup, including after host logging failures and
  interruption.
- Check the requested cgroup memory cap and zero swap before and during the
  measured command, using 100 ms polling plus inotify file-write monitoring.
  Reject changed limits, unavailable or incomplete monitoring, and gaps over
  one second. Proof verification or Docker OOM status alone cannot pass a case.
- Document `prepare`, `prove`, `--cap`, `--expect`, and individual sensitivity
  runs. Record the AE reviewer's independent x86_64 reproduction of v1.0.0.
- Add harness regression checks for limit changes, changes restored between
  polls, missing evidence, and cleanup after a host-side permission error.

The Rust prover, circuits, proof format, and historical measurements are
unchanged. `AE/validation/` contains v1.0.0 evidence; its fingerprints do not
describe this updated harness. New validation must be recorded separately.

Initial validation is retained in `AE/validation-v1.0.1/`. The existing Rust
suite passed 42 tests with two ignored; all 14 Linux harness regression checks
passed. Both fresh N=2^10 smoke proofs verified and serialized to 128 bytes.
Live swap/memory changes were rejected, and a real N=2^16 standard OOM under
64 MiB was accepted with valid monitoring. This small OOM is a harness check.
Validation used an offline image derived from the prior validated image with
32 Rust/Cargo files checked for byte identity. The first standard Dockerfile
build was blocked by a Docker Hub base-image metadata timeout. A later
standard Dockerfile build using existing cache, 42 Rust tests, 14 harness
checks, and both smoke proofs passed; the published `VALIDATION.json`
contains that post-packaging record. Full N=2^23 and native x86_64/systemd
tests were not rerun for this version.

Published v1.0.1 DOI: `10.5281/zenodo.23073215`.
The v1.0.0 DOI remains `10.5281/zenodo.22763230`.
