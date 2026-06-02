# RW-Groth16 실험 데이터 가이드

> 최종 업데이트: 2026-05-22
> 논문: `Paper/Contents/implementation.tex`  
> 컴파일: `cd Paper && pdflatex -interaction=nonstopmode main.tex`

---

## 1. 현재 파일 목록 및 역할

```
Experiments/
├── rw_isolated.csv          ★ 핵심 — 진정한 O(log N) 프루버 (streaming_prove_rw)
├── rw_prove_only_20_repeats.csv ★ 핵심 — N=2^20 clean prove-only 반복 평균
├── rw_prove_only_23_repeats.csv ★ 핵심 — N=2^23 clean prove-only 5회 평균
├── rw_prove_only_23.csv     — 최초 N=2^23 clean prove-only 단일 실행(provenance)
├── std_isolated_10_22.csv   ★ 핵심 — Standard Groth16 메모리 비교 기준
├── std_isolated_23_23.csv   ★ 핵심 — Standard N=2^23 확장 baseline
├── disk_isolated.csv        — RW-File (streaming_prove_disk) 격리 측정
├── vec_isolated.csv         — RW-Vec (CRS in RAM) 격리 측정
├── disk_10_25.csv           — 비격리 순차실행 (N=2^10~25, tab:streaming 소스)
├── disk_10_25_setup.csv     — disk_10_25.csv의 setup 메타데이터
├── benchmark_small.csv      — 소규모 N 3-way 비교 (tab:small 소스)
├── ntt_bench.csv            — SBM NTT vs ark-poly 마이크로벤치
├── r1cs_bench.csv           — R1CS 스트리밍 3단계 분해
├── msm_tradeoff.csv         — Pippenger window size 트레이드오프
└── archive/                 — 구버전 파일 (사용 금지)
```

---

## 2. 핵심 파일 상세

### Canonical CSV schema for new runs

새로 실행하는 `streaming_bench`/`bench_isolated.sh` 결과는 아래 스키마를 사용한다.
기존 CSV 중 일부는 이전 8-column schema로 남아 있으므로, 논문 수치를 갱신할 때는
재실행한 canonical CSV를 우선 사용한다.

```
variant, log_n, n,
setup_ms, prove_ms, verify_ms,
setup_peak_rss_mb, prove_start_peak_rss_mb, prove_end_peak_rss_mb,
rss_delta_mb, peak_rss_mb,
proof_bytes, valid,
read_bytes, write_bytes, pass_count,
git_commit, machine_id, timestamp
```

- `rss_delta_mb = prove_end_peak_rss_mb - prove_start_peak_rss_mb`.
- `read_bytes`, `write_bytes`, `pass_count`는 prove call 내부의 application-level
  FileVec I/O만 센다. OS metadata traffic과 page cache 효과는 포함하지 않는다.
- `pass_count`는 FileVec sequential read-open/write-finish stream count이다.

### `rw_isolated.csv` ★ 가장 중요

**측정 대상**: `streaming_prove_rw` — QAP + witness + CRS 전부 디스크(FileVec).  
prove 경로에 O(N) Vec 없음. **진정한 O(log N) working RAM.**

기존 파일은 8-column legacy schema이다. 새로 실행하면 위 canonical schema로 생성된다.

| log₂N | N | rss_delta (MB) | peak_rss (MB) |
|--------|---|:-:|:-:|
| 10 | 1K   | 87.7  | 90.3  |
| 11 | 2K   | 90.8  | 94.4  |
| 12 | 4K   | 83.9  | 88.5  |
| 13 | 8K   | 90.5  | 97.8  |
| 14 | 16K  | 107.8 | 119.3 |
| 15 | 32K  | 119.6 | 139.8 |
| 16 | 64K  | 118.8 | 156.0 |
| 17 | 128K | 121.5 | 194.2 |
| 18 | 256K | 119.0 | 261.4 |
| 19 | 512K | 133.5 | 416.2 |
| 20 | 1M   | **149.6** | 150.4 |
| 21 | 2M   | 153.1 | 1275.6 |
| 22 | 4M   | **145.5** | 2387.8 |
| 23 | 8M   | **177.3** | prove-only 5회 평균 |

**핵심 주장**: rss_delta가 N=2^10~2^23 (8192× 범위)에서 **84~177 MB** 유지.
N=2^23 기준 Std(3418.1 MB) 대비 **19.3× 메모리 절감**.

**추가 N=2^23 canonical run**: `rw_isolated_23_23.csv`에서
`rw_rw,23`이 성공했다. setup 9731.9 s (2.70 h), prove 2698.5 s
(45.0 min), verify 2.857 ms, proof 128 bytes, valid=true.
FileVec prove-call I/O는 read 223.4 GiB, write 209.2 GiB,
pass_count 2861이다. 단, setup이 먼저 peak RSS 4481.7 MB를 찍고
prove가 이를 넘지 않아 `rss_delta_mb=0.0`으로 기록되므로, 이 값은
prove-phase memory curve에 쓰지 않고 “censored by setup high-water mark”로
해석한다. N=2^23 memory point는 `rw_prove_only_23_repeats.csv`의
5회 clean prove-only 평균(`peak_rss_mb=178.1±16.0`,
`rss_delta_mb=177.3±16.0`)을 사용한다. 최초 단일 실행
`rw_prove_only_23.csv`는 provenance로만 유지한다.

**rss_delta 해석 주의사항**:
- 기존 `rw_isolated.csv`의 N=2^20 값 60.7 MB는 setup high-water mark에 의해
  부분 검열된 artifact로 판단한다.
- 논문/그래프에서는 `rw_prove_only_20_repeats.csv`의 5회 clean prove-only 평균을
  사용한다: prove 325.6±23.9 s, peak RSS 150.4±12.4 MB,
  rss_delta 149.6±12.4 MB.
- rss_delta = prove 직전 peak와 prove 완료 후 peak의 차이

---

### `std_isolated_10_22.csv` + `std_isolated_23_23.csv` ★ 비교 기준

**측정 대상**: `standard_prove` — ark-poly 인메모리 FFT, CRS in RAM. O(N) 프루버.

`std_isolated_10_22.csv`는 canonical schema 도입 이전의 legacy schema이고,
`std_isolated_23_23.csv`는 새 isolated schema로 측정한 확장점이다. 추가 standard
baseline 측정은 `./bench_isolated.sh std <lo> <hi>`로 생성하고,
`setup_peak_rss_mb`, `prove_start_peak_rss_mb`, `prove_end_peak_rss_mb`,
`rss_delta_mb`를 구분해 사용한다.

| log₂N | rss_delta (MB) | peak_rss (MB) |
|--------|:-:|:-:|
| 10 | 54.4  | 57.3   |
| 14 | 50.4  | 79.4   |
| 16 | 53.2  | 165.9  |
| 18 | 108.4 | 555.5  |
| 20 | 245.0 | 2030.1 |
| 21 | 459.7 | 4028.8 |
| 22 | **882.8** | 8019.9 |
| 23 | **3418.1** | 13687.7 |

**O(N) 성장 확인**: N=2^16→2^23 (128×)에서 rss_delta 53→3418 MB (64.2×).

---

### `disk_isolated.csv`

**측정 대상**: `streaming_prove_disk` — CRS 디스크, witness는 RAM(`&[Fr]`).  
구버전 구현. witness가 O(N) RAM이므로 진정한 O(log N) 아님.  
현재 논문에서는 `fig:scalability(b)`의 RW-File ablation curve 소스로 사용한다.

| 범위 | N | 비고 |
|------|---|------|
| 2^10~2^22 | 전체 | 격리 실험 |
| 2^23~2^24 | rss_delta=0 | setup peak가 너무 높아 prove delta 안 잡힘 |

---

### `vec_isolated.csv`

**측정 대상**: `streaming_prove` — NTT를 FileVec으로, CRS는 RAM에 보관.  
현재 논문에서는 `fig:scalability(b)`의 RW-Vec ablation curve 소스로 사용한다.

| 범위 | N | peak_rss |
|------|---|----------|
| 2^10~2^22 | 전체 | 58→7199 MB (O(N) 성장) |

---

### `disk_10_25.csv`

**측정 대상**: `streaming_prove_disk` — 비격리 순차 실행 (단일 프로세스에서 N=2^10→2^25 순서대로).  
**tab:streaming** 소스 (prove_ms, verify_ms, peak_rss_mb).

- 파일은 순수 CSV 형식이다. 실행 로그와 setup 주석은 제거했고,
  setup 메타데이터는 `disk_10_25_setup.csv`로 분리했다.
- rss_delta: 순차 실행 특성상 노이즈 많음 → **논문에서 delta 컬럼 미사용**
- peak_rss_mb: 이전 모든 N의 누적 최댓값이므로 monotone 증가
- N≥2^23: rss_delta=0, peak에 `†` 표기 (setup page cache 포함)

---

### `benchmark_small.csv`

**측정 대상**: N=64/256/1024/4096에서 Std / RW-Vec / RW-File 3-way 비교.  
**tab:small** 소스.

```
log_n, n, standard_ms, rw_vec_ms, rw_file_ms, rss1, rss2, rss3, st_ok, rw_ok, sv_ok
```

- prove time 3열(standard_ms, rw_vec_ms, rw_file_ms)만 논문에 사용
- rss1/2/3: 순차 실행으로 노이즈 → **논문에서 미사용**
- ~4.5 s 상수 floor = Pippenger libblst 초기화 (N 무관)

---

## 3. 논문 ↔ 데이터 매핑

| 논문 위치 | 소스 파일 | 사용 컬럼 |
|-----------|----------|----------|
| `tab:streaming` | `disk_10_25.csv` | prove_ms÷1000, verify_ms, peak_rss_mb |
| setup metadata | `disk_10_25_setup.csv` | setup_ms, setup_rss_delta_mb, setup_peak_rss_mb |
| `tab:small` | `benchmark_small.csv` | standard_ms, rw_vec_ms, rw_file_ms |
| `tab:large` | `rw_isolated.csv` + `rw_prove_only_20_repeats.csv` + `rw_prove_only_23_repeats.csv` + standard isolated CSVs | Std/RW-RW rss_delta_mb, RW-RW prove_ms÷1000 |
| `tab:r1cs` | `r1cs_bench.csv` | mult_ms, sort_ms, reduce_ms, total_ms |
| `fig:scalability(a)` | `disk_10_25.csv` | prove_ms÷1000 (N=2^10~25) |
| `fig:scalability(b)` RW-Vec 곡선 | `vec_isolated.csv` | peak_rss_mb |
| `fig:scalability(b)` RW-File 곡선 | `disk_isolated.csv` | peak_rss_mb |
| `fig:scalability(b)` RW-RW 곡선 ★ | `rw_isolated.csv` + `rw_prove_only_20_repeats.csv` + `rw_prove_only_23_repeats.csv` | rss_delta_mb |
| `fig:scalability(b)` Std 곡선 ★ | `std_isolated_10_22.csv` + `std_isolated_23_23.csv` | rss_delta_mb |
| I/O accounting | `rw_isolated_23_23.csv` | read_bytes, write_bytes, pass_count |
| `fig:components(a)` | `ntt_bench.csv` | rw_ntt_ms, ark_fft_ms |
| `fig:msm-window` | `msm_tradeoff.csv` | window_w, prove_ms |
| Memory 단락 (§8.3) | `rw_isolated.csv` + `rw_prove_only_20_repeats.csv` + `rw_prove_only_23_repeats.csv` + standard isolated CSVs | rss_delta_mb 비교 |

---

## 4. 논문의 핵심 수치 및 출처

| 주장 | 수치 | 출처 |
|------|------|------|
| O(log N) RAM 범위 | 84~177 MB (N=2^10~23, 8192× 범위) | `rw_isolated.csv` + `rw_prove_only_20_repeats.csv` + `rw_prove_only_23_repeats.csv` rss_delta |
| N=2^23 메모리 절감 | **19.3×** (177.3 MB vs 3418.1 MB) | `rw_prove_only_23_repeats.csv` vs `std_isolated_23_23.csv` |
| N=2^23 RW-RW prove | 2981.1±352.2 s (49.7 min mean), valid | `rw_prove_only_23_repeats.csv` |
| N=2^23 RW-RW I/O | read 223.4 GiB, write 209.2 GiB, 2861 streams | `rw_isolated_23_23.csv` |
| N=2^25 prove time | 8,994 s (~2.5시간) | `disk_10_25.csv` |
| 검증 시간 | ~2.1 ms (모든 N) | 모든 격리 CSV verify_ms 컬럼 |
| proof size | 128 bytes (모든 N) | 모든 CSV proof_bytes 컬럼 |
| NTT overhead | 1.9~2.4× (vs ark-poly) | `ntt_bench.csv` rw/ark 비율 |
| MSM 최적 window | w=8 (457 ms, N=4096) | `msm_tradeoff.csv` |
| Pippenger 상수 | ~50 MB (N 무관) | `rw_isolated.csv` 소규모 N delta |

---

## 5. 장시간 run 완료 후 확인 항목

`./bench_isolated.sh rw 23 23` 완료 후에는 아래 항목을 먼저 확인한다.

```bash
tail -n 2 Experiments/rw_isolated_23_23.csv
```

확인 기준:

- 데이터 행이 정확히 1개이고 `variant=rw_rw`, `log_n=23`이어야 한다.
- `valid=true`, `proof_bytes=128`이어야 한다.
- `setup_peak_rss_mb`, `prove_start_peak_rss_mb`, `prove_end_peak_rss_mb`,
  `rss_delta_mb`, `peak_rss_mb`가 모두 비어 있지 않아야 한다.
- `rss_delta_mb`는 prove-phase working memory claim에 사용한다. 단, setup
  high-water mark 때문에 `rss_delta_mb=0`으로 검열된 장시간 run은 memory
  curve에 넣지 않고 timing/I/O 성공점으로만 해석한다.
- `read_bytes`, `write_bytes`, `pass_count`는 I/O accounting 문장에 사용한다.
- `prove_ms`는 초 단위로 변환해 `tab:large` 또는 본문 prose에 반영한다.

이 파일이 정상일 때만 기존 `rw_isolated.csv`에 같은 schema로 병합하거나,
논문에는 별도 `N=2^23` 대표점으로 추가한다.

---

## 6. Clean prove-only RSS 측정

setup과 prove를 서로 다른 프로세스로 분리해 `streaming_prove_rw`의 clean
prove-process peak RSS를 측정한다. 이 실험이 `N=2^23` memory claim의
가장 강한 근거다.

```bash
cd <artifact-root>/rw-groth16
cargo build --release --bin rw_prove_only
caffeinate -dimsu target/release/rw_prove_only \
  23 \
  Experiments/rw_prove_only_23_data \
  Experiments/rw_prove_only_23.csv
```

출력 CSV:

```text
variant,log_n,n,prove_ms,verify_ms,peak_rss_mb,rss_delta_mb,proof_bytes,valid,read_bytes,write_bytes,pass_count,crs_path,qap_path,witness_path,git_commit,machine_id,timestamp
```

해석:

- `peak_rss_mb`는 prove-only worker 프로세스의 lifetime peak RSS이다.
- `rss_delta_mb`는 prove worker 시작 후 prove call이 추가로 올린 peak이다.
- setup/materialization은 별도 프로세스에서 수행되므로 setup high-water mark가
  prove RSS를 가리지 않는다.
- materialized data directory(`rw_prove_only_23_data`)는 재사용 가능하다.

현재 N=2^23 대표 결과:

- `rw_prove_only_23_repeats.csv` 5회 평균을 논문 대표값으로 사용한다.
- prove 2981.1±352.2 s (49.7 min mean), valid=true for all runs
- peak RSS 178.1±16.0 MB, rss_delta 177.3±16.0 MB
- read 223.4 GiB, write 209.2 GiB, pass_count 2861
- standard `std_isolated_23_23.csv`의 prove delta 3418.1 MB 대비 19.3× 절감
- 최초 단일 실행 `rw_prove_only_23.csv`(prove 2340.3 s, rss_delta 146.1 MB)는
  provenance로만 둔다.

메모리 cap/OOM 실험:

```bash
target/release/rw_prove_only --prove 23 Experiments/rw_prove_only_23_data 2048
```

단, macOS에서는 `setrlimit(RLIMIT_AS)`가 실패할 수 있다. 이 경우 OOM boundary는
Linux/VM에서 수행하고, macOS 로컬에서는 clean prove-only RSS를 우선 사용한다.

---

## 7. LaTeX 수정 방법

### 수치 변경 시 규칙
```latex
% 천 단위 thin space
1\,332    % → 1,332
% 분수 s 단위 (ms를 s로 변환)
prove_ms ÷ 1000 → 소수점 1자리

% 특수 기호
\checkmark   % ✓
\dag         % †
\mathbf{19.3\times}  % bold 배수 강조
```

### tab:large 업데이트 예시
현재 `tab:large`는 Std vs RW-RW memory comparison 중심으로 유지한다:
```latex
16 &  53 & 119 & 0.4$\times$ &   51.9\,s \\
18 & 108 & 119 & 0.9$\times$ &  129.1\,s \\
20 & 245 & 150 & 1.6$\times$ &  325.6\,s \\
21 & 460 & 153 & 3.0$\times$ &  929.5\,s \\
22 & 883 & 146 & \textbf{6.1$\times$} & 1\,181.8\,s \\
23 & 3\,418 & 177 & \textbf{19.3$\times$} & 2\,981.1\,s \\
```

### fig:scalability(b) 데이터 포인트 업데이트 예시
```latex
% rw_isolated.csv → RW-RW dashed 곡선
\addplot[green!60!black, mark=square*, dashed] coordinates {
  (10,87.7) (11,90.8) ... (20,149.6) ... (22,145.5) (23,177.3)
};

% std_isolated_10_22.csv + std_isolated_23_23.csv → Std dashed 곡선
\addplot[orange!80!black, mark=diamond*, dashed] coordinates {
  (10,54.4) ... (22,882.8) (23,3418.1)
};
```

### 컴파일 및 확인
```bash
cd <artifact-root>/Paper
pdflatex -interaction=nonstopmode main.tex 2>&1 | grep -E "^!|Output written"
# → "Output written on main.pdf (17 pages, ...)" 정상
```

---

## 8. RSS 측정 방식 해설

### macOS `ru_maxrss` 특성
- 프로세스 생존 동안 **단조 증가 최댓값** — 한 번 올라가면 내려오지 않음
- **격리 실험** (bench_isolated.sh): N별 독립 프로세스 → 각 N의 진짜 RSS 측정 가능
- **순차 실험** (disk_10_25.csv): 단일 프로세스 → 이전 N 누적치 반영, delta 부정확

### rss_delta 의미
```
rss0 = prove 시작 직전의 peak_rss  (setup 완료 후)
rss1 = prove 완료 후의 peak_rss
rss_delta = rss1 - rss0           (prove phase가 추가로 사용한 RAM)
```

### 왜 rss_delta가 prove-phase O(log N)의 증거인가
- setup은 O(N) 내부 할당 후 해제 → setup 완료 시점 rss0는 O(N) peak
- prove (`streaming_prove_rw`)는 O(log N) 추가 할당만 → rss_delta = O(log N)
- **N=2^10~23 (8192×)에서 rss_delta 84~177 MB** → O(N)이었다면 훨씬 커져야 하며,
  실제 standard prover는 N=2^23에서 3418 MB delta까지 증가함

---

## 9. 구현 버전 구분 (중요)

| 함수 | CRS | Witness | QAP | RAM | 사용 파일 |
|------|-----|---------|-----|-----|----------|
| `streaming_prove_rw` | FileVec | FileVec | FileVec | **O(log N)** ★ | `rw_isolated.csv`, `rw_prove_only_20_repeats.csv`, `rw_prove_only_23_repeats.csv` |
| `streaming_prove_disk` | FileVec | `&[Fr]` RAM | `&Qap` RAM | O(N) | `disk_isolated.csv` |
| `streaming_prove` | RAM Vec | `&[Fr]` RAM | `&Qap` RAM | O(N) | `vec_isolated.csv` |
| `standard_prove` | RAM Vec | `&[Fr]` RAM | `&Qap` RAM | O(N) | `std_isolated_10_22.csv`, `std_isolated_23_23.csv` |

**논문의 O(log N) 주장은 `streaming_prove_rw` 기준.**  
`streaming_prove_disk`와 혼동 주의 — 이름이 비슷하지만 caller-side QAP/witness가 RAM에 있어
O(log N) memory claim의 직접 근거가 아니다.
