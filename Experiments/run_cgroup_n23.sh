#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-rwg-cap:rust}"
CPUS="${CPUS:-8}"
BUILD_MEMORY="${BUILD_MEMORY:-22g}"
LOG_DIR="$ROOT/Experiments/cap_logs"

cd "$ROOT"
mkdir -p "$LOG_DIR"

usage() {
  cat <<'EOF'
Usage:
  ./Experiments/run_cgroup_n23.sh verify
  ./Experiments/run_cgroup_n23.sh build-image
  ./Experiments/run_cgroup_n23.sh build
  ./Experiments/run_cgroup_n23.sh materialize-rw
  ./Experiments/run_cgroup_n23.sh materialize-std
  ./Experiments/run_cgroup_n23.sh run-rw-8gb
  ./Experiments/run_cgroup_n23.sh run-std-8gb
  ./Experiments/run_cgroup_n23.sh run-std-12gb
  ./Experiments/run_cgroup_n23.sh run-std-16gb
  ./Experiments/run_cgroup_n23.sh run-all-capped

Environment overrides:
  IMAGE=rwg-cap:rust
  CPUS=8
  BUILD_MEMORY=22g
EOF
}

need_file() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "missing: $path" >&2
    return 1
  fi
}

build_image() {
  docker build -t "$IMAGE" - <<'EOF'
FROM rust:1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends time ca-certificates git && rm -rf /var/lib/apt/lists/*
EOF
}

docker_shell() {
  local memory="$1"
  local script="$2"
  docker run --rm --memory="$memory" --memory-swap="$memory" --cpus="$CPUS" \
    -v "$ROOT":/work -w /work "$IMAGE" bash -c "$script"
}

build_bins() {
  docker_shell "$BUILD_MEMORY" '
set -euxo pipefail
export PATH=/usr/local/cargo/bin:$PATH
mkdir -p /work/.cargo-linux /work/target-linux /work/Experiments/cap_logs
export CARGO_HOME=/work/.cargo-linux
export CARGO_TARGET_DIR=/work/target-linux
cargo --version
cargo build --release --bin rw_prove_only --bin std_prove_only \
  2>&1 | tee /work/Experiments/cap_logs/build_linux.log
ls -lh /work/target-linux/release/rw_prove_only /work/target-linux/release/std_prove_only
'
}

materialize_rw() {
  docker_shell "$BUILD_MEMORY" '
set -euxo pipefail
export PATH=/usr/local/cargo/bin:$PATH
test -x target-linux/release/rw_prove_only
target-linux/release/rw_prove_only \
  23 \
  Experiments/rw_prove_only_23_data \
  Experiments/rw_prove_only_23.csv \
  > Experiments/cap_logs/rw_materialize_23.log 2>&1
'
}

materialize_std() {
  docker_shell "$BUILD_MEMORY" '
set -euxo pipefail
export PATH=/usr/local/cargo/bin:$PATH
test -x target-linux/release/std_prove_only
target-linux/release/std_prove_only \
  23 \
  Experiments/std_prove_only_23_data \
  Experiments/std_prove_only_23.csv \
  > Experiments/cap_logs/std_materialize_23.log 2>&1
'
}

run_capped() {
  local cap="$1"
  local bin="$2"
  local data_dir="$3"
  local stem="$4"
  docker_shell "$cap" "
set +e
export PATH=/usr/local/cargo/bin:\$PATH
test -x target-linux/release/$bin
START=\$(date +%s)
/usr/bin/time -v target-linux/release/$bin \
  --prove 23 $data_dir 0 \
  > Experiments/cap_logs/$stem.csv \
  2> Experiments/cap_logs/$stem.stderr
STATUS=\$?
END=\$(date +%s)
echo \"\$STATUS\" > Experiments/cap_logs/$stem.exit
echo \"\$((END-START))\" > Experiments/cap_logs/$stem.wall_s
exit 0
"
}

verify() {
  local ok=0

  need_file "$LOG_DIR/rw_rw_8gb_23.csv" || ok=1
  need_file "$LOG_DIR/rw_rw_8gb_23.exit" || ok=1
  need_file "$LOG_DIR/rw_rw_8gb_23.stderr" || ok=1
  need_file "$LOG_DIR/std_8gb_23.exit" || ok=1
  need_file "$LOG_DIR/std_8gb_23.stderr" || ok=1
  need_file "$LOG_DIR/std_16gb_23.csv" || ok=1
  need_file "$LOG_DIR/std_16gb_23.exit" || ok=1
  need_file "$LOG_DIR/std_16gb_23.stderr" || ok=1

  if [[ "$ok" -ne 0 ]]; then
    return "$ok"
  fi

  local rw_exit std8_exit std16_exit
  rw_exit="$(tr -d '[:space:]' < "$LOG_DIR/rw_rw_8gb_23.exit")"
  std8_exit="$(tr -d '[:space:]' < "$LOG_DIR/std_8gb_23.exit")"
  std16_exit="$(tr -d '[:space:]' < "$LOG_DIR/std_16gb_23.exit")"

  [[ "$rw_exit" == "0" ]] || { echo "bad RW-RW 8GB exit: $rw_exit" >&2; ok=1; }
  [[ "$std8_exit" == "137" ]] || { echo "bad Std 8GB exit: $std8_exit" >&2; ok=1; }
  [[ "$std16_exit" == "0" ]] || { echo "bad Std 16GB exit: $std16_exit" >&2; ok=1; }

  grep -q 'rw_rw_prove_only,23,8388608' "$LOG_DIR/rw_rw_8gb_23.csv" || { echo "missing RW-RW CSV row" >&2; ok=1; }
  grep -q ',128,true,' "$LOG_DIR/rw_rw_8gb_23.csv" || { echo "RW-RW proof/valid check failed" >&2; ok=1; }
  grep -q 'Command terminated by signal 9' "$LOG_DIR/std_8gb_23.stderr" || { echo "Std 8GB SIGKILL line missing" >&2; ok=1; }
  grep -q 'std_prove_only,23,8388608' "$LOG_DIR/std_16gb_23.csv" || { echo "missing Std 16GB CSV row" >&2; ok=1; }
  grep -q ',128,true,' "$LOG_DIR/std_16gb_23.csv" || { echo "Std 16GB proof/valid check failed" >&2; ok=1; }

  echo "RW-RW 8GB:"
  cat "$LOG_DIR/rw_rw_8gb_23.exit" "$LOG_DIR/rw_rw_8gb_23.wall_s"
  tail -n 1 "$LOG_DIR/rw_rw_8gb_23.csv"
  grep -E 'Elapsed|Maximum resident|Exit status' "$LOG_DIR/rw_rw_8gb_23.stderr"

  echo
  echo "Std 8GB:"
  cat "$LOG_DIR/std_8gb_23.exit" "$LOG_DIR/std_8gb_23.wall_s"
  grep -E 'Command terminated|Elapsed|Maximum resident' "$LOG_DIR/std_8gb_23.stderr"

  echo
  if [[ -f "$LOG_DIR/std_12gb_23.exit" && -f "$LOG_DIR/std_12gb_23.stderr" ]]; then
    echo "Std 12GB sensitivity:"
    cat "$LOG_DIR/std_12gb_23.exit" "$LOG_DIR/std_12gb_23.wall_s"
    grep -E 'Command terminated|Elapsed|Maximum resident' "$LOG_DIR/std_12gb_23.stderr"
    echo
  fi

  echo
  echo "Std 16GB:"
  cat "$LOG_DIR/std_16gb_23.exit" "$LOG_DIR/std_16gb_23.wall_s"
  tail -n 1 "$LOG_DIR/std_16gb_23.csv"
  grep -E 'Elapsed|Maximum resident|Exit status' "$LOG_DIR/std_16gb_23.stderr"

  if [[ "$ok" -eq 0 ]]; then
    echo
    echo "PASS: bounded-memory artifact logs match expected outcomes."
  fi
  return "$ok"
}

cmd="${1:-verify}"
case "$cmd" in
  verify)
    verify
    ;;
  build-image)
    build_image
    ;;
  build)
    build_bins
    ;;
  materialize-rw)
    materialize_rw
    ;;
  materialize-std)
    materialize_std
    ;;
  run-rw-8gb)
    run_capped 8g rw_prove_only Experiments/rw_prove_only_23_data rw_rw_8gb_23
    ;;
  run-std-8gb)
    run_capped 8g std_prove_only Experiments/std_prove_only_23_data std_8gb_23
    ;;
  run-std-12gb)
    run_capped 12g std_prove_only Experiments/std_prove_only_23_data std_12gb_23
    ;;
  run-std-16gb)
    run_capped 16g std_prove_only Experiments/std_prove_only_23_data std_16gb_23
    ;;
  run-all-capped)
    run_capped 8g rw_prove_only Experiments/rw_prove_only_23_data rw_rw_8gb_23
    run_capped 8g std_prove_only Experiments/std_prove_only_23_data std_8gb_23
    run_capped 12g std_prove_only Experiments/std_prove_only_23_data std_12gb_23
    run_capped 16g std_prove_only Experiments/std_prove_only_23_data std_16gb_23
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
