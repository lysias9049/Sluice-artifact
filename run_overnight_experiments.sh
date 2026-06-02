#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

STAMP="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="Experiments/overnight_logs/$STAMP"
SUMMARY="$LOG_DIR/summary.txt"

mkdir -p "$LOG_DIR"
touch "$SUMMARY"

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$SUMMARY"
}

run_step() {
  local name="$1"
  shift
  local step_log="$LOG_DIR/${name}.log"

  log "START $name"
  log "CMD: $*"

  "$@" >"$step_log" 2>&1
  local status=$?

  log "END $name status=$status log=$step_log"
  return "$status"
}

run_step_continue() {
  run_step "$@" || true
}

if command -v caffeinate >/dev/null 2>&1; then
  KEEP_AWAKE=(caffeinate -dimsu)
  log "Using caffeinate to keep the machine awake."
else
  KEEP_AWAKE=()
  log "caffeinate not found; continuing without an awake guard."
fi

log "Overnight experiment run started."
log "Working directory: $ROOT"

run_step_continue \
  "01_build_rw_prove_only" \
  cargo build --release --bin rw_prove_only

run_step_continue \
  "02_rw_prove_only_23" \
  "${KEEP_AWAKE[@]}" target/release/rw_prove_only \
  23 \
  Experiments/rw_prove_only_23_data \
  Experiments/rw_prove_only_23.csv

run_step_continue \
  "03_std_isolated_23" \
  "${KEEP_AWAKE[@]}" ./bench_isolated.sh std 23 23

run_step_continue \
  "04_oom_boundary_16_23" \
  "${KEEP_AWAKE[@]}" bash -c \
  'cargo run --bin oom_boundary --release -- 16 23 256,512,1024,2048 2> Experiments/oom_boundary_16_23.csv'

log "Overnight experiment run finished."
log "Expected result files:"
log "  Experiments/rw_prove_only_23.csv"
log "  Experiments/std_isolated_23_23.csv"
log "  Experiments/oom_boundary_16_23.csv"
