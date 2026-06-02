#!/bin/bash
# bench_isolated.sh — N 하나씩 별도 프로세스로 실행 → 정확한 RSS 측정
#
# 사용법:
#   ./bench_isolated.sh rw   10 23    # RW-RW 모드, N=2^10~2^23
#   ./bench_isolated.sh disk 10 22    # RW-File 모드, N=2^10~2^22
#   ./bench_isolated.sh vec  10 20    # RW-Vec 모드, N=2^10~2^20
#
# 원리: 각 N을 독립 프로세스(cargo run)로 실행 → ru_maxrss가 0에서 시작
#       → rss_delta = 해당 N 단독 실행 시의 실제 prove 피크

set -e

MODE=${1:-disk}
LO=${2:-10}
HI=${3:-20}
OUT="Experiments/${MODE}_isolated_${LO}_${HI}.csv"
TMP=$(mktemp /tmp/bench_XXXXXX.csv)

case "$MODE" in
    std)  VARIANT="std" ;;
    vec)  VARIANT="rw_vec" ;;
    disk) VARIANT="rw_file" ;;
    rw)   VARIANT="rw_rw" ;;
    *)    VARIANT="$MODE" ;;
esac

echo "=== bench_isolated.sh: MODE=$MODE, N=2^$LO ~ 2^$HI ==="
echo "출력: $OUT"
echo ""

# CSV 헤더
echo "variant,log_n,n,setup_ms,prove_ms,verify_ms,setup_peak_rss_mb,prove_start_peak_rss_mb,prove_end_peak_rss_mb,rss_delta_mb,peak_rss_mb,proof_bytes,valid,read_bytes,write_bytes,pass_count,git_commit,machine_id,timestamp" > "$OUT"

for log_n in $(seq "$LO" "$HI"); do
    n=$((1 << log_n))
    printf "N=2^%d (%d)  ... " "$log_n" "$n"

    # 독립 프로세스 실행: stdout 버림, stderr만 캡처
    if cargo run --bin streaming_bench --release -- "$log_n" "$log_n" "$MODE" \
            2>"$TMP" 1>/dev/null; then
        # CSV 데이터 행만 추출 (variant,log_n으로 시작하는 행)
        if grep -E "^${VARIANT},${log_n}," "$TMP" >> "$OUT"; then
            # prove_ms와 peak_rss 추출해서 출력
            row=$(grep -E "^${VARIANT},${log_n}," "$TMP")
            prove_s=$(echo "$row" | cut -d',' -f5 | awk '{printf "%.1f", $1/1000}')
            peak=$(echo "$row" | cut -d',' -f11 | awk '{printf "%.0f", $1}')
            delta=$(echo "$row" | cut -d',' -f10 | awk '{printf "%.1f", $1}')
            read_gb=$(echo "$row" | cut -d',' -f14 | awk '{printf "%.2f", $1/1073741824}')
            write_gb=$(echo "$row" | cut -d',' -f15 | awk '{printf "%.2f", $1/1073741824}')
            passes=$(echo "$row" | cut -d',' -f16)
            echo "prove=${prove_s}s  peak_rss=${peak}MB  delta=${delta}MB  io=${read_gb}/${write_gb}GiB  passes=${passes}  ✓"
        else
            echo "데이터 행 없음 — FAILED"
        fi
    else
        echo "실행 실패"
    fi
done

rm -f "$TMP"
echo ""
echo "완료: $OUT"
