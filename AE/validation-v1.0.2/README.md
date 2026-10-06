# v1.0.2 packaging validation

These are author-side checks on Linux ARM64 under Docker Desktop 29.5.2,
cgroup v2, using the standard `AE/Dockerfile`. They are separate from the
AE reviewers' native x86_64 observations and the historical full N=2^23
records in `AE/validation/`.

The source fingerprint and image IDs are in `build.json`, the legacy builder
subdirectory, and `standalone-helper/build.json`. Raw capped results include
the complete monitor report, selected Docker state, stdout/stderr, and the
exported smoke proofs. `summary.json` describes the completed checks.

## Build and helper checks

From the extracted artifact root:

```bash
bash AE/install.sh --work /path/to/buildkit-work --image sluice-ae:1.0.2
python3 AE/run.py test --work /path/to/buildkit-work --image sluice-ae:1.0.2
python3 AE/run.py smoke --work /path/to/buildkit-work --image sluice-ae:1.0.2
```

The standard BuildKit build used existing Rust/OS build cache. The legacy
build was selected explicitly with a different image and work directory:

```bash
DOCKER_BUILDKIT=0 python3 AE/run.py build --work /path/to/legacy-work --image sluice-ae:1.0.2-legacy
python3 AE/run.py test --work /path/to/legacy-work --image sluice-ae:1.0.2-legacy
python3 AE/run.py smoke --work /path/to/legacy-work --image sluice-ae:1.0.2-legacy
```

The standalone helper was tested beside an extracted copy of the ZIP with
explicit `--work` and `--image` arguments; it located the packaged runner,
completed a real Docker build, and created the expected build record.
The helper also passed Bash syntax and help checks.

## CLI and memory-monitor regressions

```bash
docker run --rm --network none --memory 256m --memory-swap 256m \
  --user "$(id -u):$(id -g)" sluice-ae:1.0.2 python3 AE/test_harness.py
```

All 16 tests passed on Linux. Two new CLI compatibility checks use a
legacy-style executable fixture that accepts the common build flags and
rejects unsupported ones. The published v1.0.1 command fails this fixture
with exit 125; v1.0.2 builds and records the image. A genuine build error
also propagates without creating a successful build record.
These fixture checks are distinct from the real legacy-backend Docker build.

## Scope

The Rust/Cargo source files (32 files) were compared byte-for-byte to the
published v1.0.1 archive. The prover, circuits, and proof format are unchanged.
Small smoke inputs use N=2^10; they are functionality checks and do not
establish the large-input memory bound. No new full N=2^23 workflow or native
Ubuntu x86_64 legacy-builder/systemctl scenario was run for this update.
