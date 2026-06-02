#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-rwg-cap:rust}"
CPUS="${CPUS:-8}"
LOG_DIR="$ROOT/Experiments/cap_logs"

usage() {
  cat <<'EOF'
Usage:
  ./Experiments/run_rw_lowmem_sweep.sh LOG_N CAPS

Examples:
  ./Experiments/run_rw_lowmem_sweep.sh 20 64m,96m,128m,192m,256m,512m
  ./Experiments/run_rw_lowmem_sweep.sh 23 96m,128m,192m,256m

This script runs the pre-materialized RW-RW prove-only worker under Docker
cgroup memory caps.  It does not run setup/materialization.

Environment overrides:
  IMAGE=rwg-cap:rust
  CPUS=8
EOF
}

sanitize_cap() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '_'
}

run_cap() {
  local log_n="$1"
  local cap="$2"
  local data_dir="Experiments/rw_prove_only_${log_n}_data"
  local cap_name
  cap_name="$(sanitize_cap "$cap")"
  local stem="rw_rw_${cap_name}_${log_n}"
  local docker_status
  local worker_status="missing"
  local wall_s="missing"

  echo "[RW-RW log_n=$log_n cap=$cap] start"
  rm -f \
    "$LOG_DIR/$stem.csv" \
    "$LOG_DIR/$stem.stderr" \
    "$LOG_DIR/$stem.exit" \
    "$LOG_DIR/$stem.wall_s" \
    "$LOG_DIR/$stem.docker_exit"

  set +e
  docker run --rm --memory="$cap" --memory-swap="$cap" --cpus="$CPUS" \
    -v "$ROOT":/work -w /work "$IMAGE" bash -c "
set +e
export PATH=/usr/local/cargo/bin:\$PATH
test -x target-linux/release/rw_prove_only
test -d $data_dir
START=\$(date +%s)
/usr/bin/time -v target-linux/release/rw_prove_only \
  --prove $log_n $data_dir 0 \
  > Experiments/cap_logs/$stem.csv \
  2> Experiments/cap_logs/$stem.stderr
STATUS=\$?
END=\$(date +%s)
echo \"\$STATUS\" > Experiments/cap_logs/$stem.exit
echo \"\$((END-START))\" > Experiments/cap_logs/$stem.wall_s
exit 0
"
  docker_status=$?
  set -e
  echo "$docker_status" > "$LOG_DIR/$stem.docker_exit"

  if [[ -f "$LOG_DIR/$stem.exit" ]]; then
    worker_status="$(tr -d '[:space:]' < "$LOG_DIR/$stem.exit")"
  fi
  if [[ -f "$LOG_DIR/$stem.wall_s" ]]; then
    wall_s="$(tr -d '[:space:]' < "$LOG_DIR/$stem.wall_s")"
  fi

  echo "[RW-RW log_n=$log_n cap=$cap] docker_exit=$docker_status exit=$worker_status wall_s=$wall_s"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
    usage
    exit 0
  fi

  local log_n="${1:-20}"
  local caps="${2:-64m,96m,128m,192m,256m,512m}"
  local data_dir="$ROOT/Experiments/rw_prove_only_${log_n}_data"

  mkdir -p "$LOG_DIR"
  cd "$ROOT"

  if [[ ! -x target-linux/release/rw_prove_only ]]; then
    echo "missing target-linux/release/rw_prove_only; run ./Experiments/run_cgroup_n23.sh build first" >&2
    exit 1
  fi

  if [[ ! -d "$data_dir" ]]; then
    echo "missing $data_dir; materialize it before running this sweep" >&2
    exit 1
  fi

  IFS=',' read -r -a cap_array <<< "$caps"
  for cap in "${cap_array[@]}"; do
    run_cap "$log_n" "$cap"
  done
}

main "$@"
