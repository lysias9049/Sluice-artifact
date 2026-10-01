# Release changes

## 1.0.1 — local candidate, 2026-10-01

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

Local validation is retained in `AE/validation-v1.0.1/`. The existing Rust
suite passed 42 tests with two ignored; all 14 Linux harness regression checks
passed. Both fresh N=2^10 smoke proofs verified and serialized to 128 bytes.
Live swap/memory changes were rejected, and a real N=2^16 standard OOM under
64 MiB was accepted with valid monitoring. This small OOM is a harness check.
Validation used an offline image derived from the prior validated image with
32 Rust/Cargo files checked for byte identity. The standard Dockerfile build
was blocked by a Docker Hub base-image metadata timeout. Full N=2^23 and native
x86_64/systemd tests remain unverified for this candidate.

This candidate has not been published on Zenodo or assigned a new Zenodo DOI. The
v1.0.0 DOI remains `10.5281/zenodo.22763230`.
