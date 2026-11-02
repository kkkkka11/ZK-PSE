#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_ROOT="${1:-$PROJECT_ROOT/experiments/e2e_regex1_5_5repeats_$(date +%Y%m%d_%H%M%S)}"
RUN_ROOT="$(realpath -m "$RUN_ROOT")"

NUM_TASKS="${NUM_TASKS:-64}"
REPEATS="${REPEATS:-5}"
N_PARAM="${N_PARAM:-16}"
L_PARAM="${L_PARAM:-2}"
T_PARAM="${T_PARAM:-2}"
M_PARAM="${M_PARAM:-32768}"
RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-1}"
AGGREGATION_RAYON_NUM_THREADS="${AGGREGATION_RAYON_NUM_THREADS:-$(nproc)}"
CIRCUIT_SET_DIR="${CIRCUIT_SET_DIR:-$PROJECT_ROOT/fixtures/password_policies_5_ascii}"
PROOF_BIN="${PROOF_BIN:-$PROJECT_ROOT/target/release/examples/regex}"
AGGREGATION_BIN="${AGGREGATION_BIN:-$PROJECT_ROOT/target/release/aggregation_server}"

# A subset is useful for long runs; never silently expand it to all regexes.
read -r -a REGEX_ID_LIST <<< "${REGEX_IDS-1 2 3 4 5}"
if (( ${#REGEX_ID_LIST[@]} == 0 )); then
  echo "REGEX_IDS must contain one or more distinct IDs from 1 to 5" >&2
  exit 1
fi
seen_ids=" "
for regex_id in "${REGEX_ID_LIST[@]}"; do
  if ! [[ "$regex_id" =~ ^[1-5]$ ]] || [[ "$seen_ids" == *" $regex_id "* ]]; then
    echo "REGEX_IDS must contain distinct IDs from 1 to 5: $regex_id" >&2
    exit 1
  fi
  seen_ids+="$regex_id "
done
selection="$(IFS=,; echo "${REGEX_ID_LIST[*]}")"

if ! [[ "$NUM_TASKS" =~ ^[1-9][0-9]*$ && "$REPEATS" =~ ^[1-9][0-9]*$ ]]; then
  echo "NUM_TASKS and REPEATS must be positive integers" >&2
  exit 1
fi

if [[ "${SKIP_BUILD:-1}" != "1" ]]; then
  (cd "$PROJECT_ROOT" && cargo build --release --example regex --features parallel && cargo build --release --bin aggregation_server)
fi
for bin in "$PROOF_BIN" "$AGGREGATION_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "Missing executable: $bin (rerun with SKIP_BUILD=0)" >&2
    exit 1
  fi
done

for regex_id in "${REGEX_ID_LIST[@]}"; do
  r1cs="$CIRCUIT_SET_DIR/regex_${regex_id}/build/GeneratedRegex${regex_id}.r1cs"
  wasm="$CIRCUIT_SET_DIR/regex_${regex_id}/build/GeneratedRegex${regex_id}_js/GeneratedRegex${regex_id}.wasm"
  if [[ ! -f "$r1cs" || ! -f "$wasm" ]]; then
    echo "Missing circuit assets for Regex $regex_id: $r1cs or $wasm" >&2
    exit 1
  fi
done

for case_type in good bad; do
  witness_dir="$PROJECT_ROOT/fixtures/regex/witness-$case_type"
  mapfile -t witness_files < <(find "$witness_dir" -maxdepth 1 -type f \( -name 'task*.json' -o -name 'party*.json' \) | sort -V)
  if (( ${#witness_files[@]} < NUM_TASKS )); then
    echo "Need $NUM_TASKS witnesses in $witness_dir; found ${#witness_files[@]}" >&2
    exit 1
  fi
done

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "Ready: ${#REGEX_ID_LIST[@]} regexes x 2 cases x $REPEATS rounds x $NUM_TASKS proofs; IDs: $selection; output: $RUN_ROOT"
  exit 0
fi

mkdir -p "$RUN_ROOT"
exec 9>"$RUN_ROOT/.run.lock"
if ! flock -n 9; then
  echo "Another run is using $RUN_ROOT" >&2
  exit 1
fi

configuration="$({
  printf 'NUM_TASKS=%s REPEATS=%s N=%s L=%s T=%s M=%s RAYON=%s AGG_RAYON=%s' \
    "$NUM_TASKS" "$REPEATS" "$N_PARAM" "$L_PARAM" "$T_PARAM" "$M_PARAM" \
    "$RAYON_NUM_THREADS" "$AGGREGATION_RAYON_NUM_THREADS"
  # Preserve the historical configuration format for the default full run.
  if [[ "$selection" != "1,2,3,4,5" ]]; then
    printf ' REGEX_IDS=%s' "$selection"
  fi
  printf '\n'
  sha256sum "$PROOF_BIN" "$AGGREGATION_BIN"
  for regex_id in "${REGEX_ID_LIST[@]}"; do
    sha256sum "$CIRCUIT_SET_DIR/regex_${regex_id}/build/GeneratedRegex${regex_id}.r1cs" \
      "$CIRCUIT_SET_DIR/regex_${regex_id}/build/GeneratedRegex${regex_id}_js/GeneratedRegex${regex_id}.wasm"
  done
  for case_type in good bad; do
    witness_dir="$PROJECT_ROOT/fixtures/regex/witness-$case_type"
    mapfile -t witness_files < <(find "$witness_dir" -maxdepth 1 -type f \( -name 'task*.json' -o -name 'party*.json' \) | sort -V)
    sha256sum "${witness_files[@]:0:NUM_TASKS}"
  done
})"
if [[ -f "$RUN_ROOT/config.txt" ]]; then
  if [[ "$(<"$RUN_ROOT/config.txt")" != "$configuration" ]]; then
    echo "Run configuration or input files changed; use a new output directory" >&2
    exit 1
  fi
else
  printf '%s\n' "$configuration" > "$RUN_ROOT/config.txt"
fi

write_results() {
  local raw_tmp summary_tmp ms regex_id case_type round case_dir
  raw_tmp="$(mktemp "$RUN_ROOT/.e2e_raw.XXXXXX")"
  summary_tmp="$(mktemp "$RUN_ROOT/.e2e_summary.XXXXXX")"
  printf 'regex,case,round,wall_time_ms,wall_time_min\n' > "$raw_tmp"
  for regex_id in "${REGEX_ID_LIST[@]}"; do
    for case_type in good bad; do
      for ((round=1; round<=REPEATS; round++)); do
        case_dir="$RUN_ROOT/regex${regex_id}_${case_type}_round${round}"
        if [[ -f "$case_dir/e2e_ms" ]]; then
          ms="$(<"$case_dir/e2e_ms")"
          printf '%s,%s,%s,%s,%s\n' "$regex_id" "$case_type" "$round" "$ms" \
            "$(awk -v ms="$ms" 'BEGIN {printf "%.3f", ms/60000}')" >> "$raw_tmp"
        fi
      done
    done
  done
  mv "$raw_tmp" "$RUN_ROOT/e2e_raw.csv"
  awk -F, 'NR>1 {key=$1 "," $2; count[key]++; total[key]+=$4}
    END {
      print "regex,case,completed_repeats,mean_wall_time_ms,mean_wall_time_min"
      for (regex=1; regex<=5; regex++) {
        for (c=1; c<=2; c++) {
          case_type=(c==1 ? "good" : "bad")
          key=regex "," case_type
          if (count[key]>0)
            printf "%d,%s,%d,%.0f,%.3f\n", regex, case_type, count[key], total[key]/count[key], total[key]/count[key]/60000
        }
      }
    }' "$RUN_ROOT/e2e_raw.csv" > "$summary_tmp"
  mv "$summary_tmp" "$RUN_ROOT/e2e_summary.csv"
}

write_results
for regex_id in "${REGEX_ID_LIST[@]}"; do
  r1cs="$CIRCUIT_SET_DIR/regex_${regex_id}/build/GeneratedRegex${regex_id}.r1cs"
  for ((round=1; round<=REPEATS; round++)); do
    for case_type in good bad; do
      case_dir="$RUN_ROOT/regex${regex_id}_${case_type}_round${round}"
      if [[ -f "$case_dir/e2e_ms" ]]; then
        echo "Skipping completed Regex $regex_id $case_type round $round/$REPEATS"
        continue
      fi

      witness_dir="$PROJECT_ROOT/fixtures/regex/witness-$case_type"
      mapfile -t witness_files < <(find "$witness_dir" -maxdepth 1 -type f \( -name 'task*.json' -o -name 'party*.json' \) | sort -V)
      expected_match=0
      [[ "$case_type" == good ]] && expected_match=1
      attempt_dir="$case_dir/attempt_$(date +%Y%m%d_%H%M%S)_$$"
      mkdir -p "$attempt_dir/logs/metrics" "$attempt_dir/proof_data/agg"
      echo "Starting Regex $regex_id $case_type round $round/$REPEATS: $attempt_dir"
      start_ms="$(date +%s%3N)"

      for ((task_id=0; task_id<NUM_TASKS; task_id++)); do
        echo "Regex $regex_id $case_type round $round/$REPEATS: task $((task_id+1))/$NUM_TASKS"
        if ! (cd "$attempt_dir" && RAYON_NUM_THREADS="$RAYON_NUM_THREADS" RUST_BACKTRACE=1 RUST_LOG=info \
          "$PROOF_BIN" 0 "$task_id" "$PROJECT_ROOT/network-address/$N_PARAM" \
          "$L_PARAM" "$T_PARAM" "$M_PARAM" "$r1cs" "${witness_files[$task_id]}" \
          "$expected_match" "$N_PARAM" > "logs/task${task_id}_local_mpc.log" 2>&1); then
          echo "Failed: $attempt_dir/logs/task${task_id}_local_mpc.log" >&2
          exit 1
        fi
        if [[ ! -f "$attempt_dir/proof_data/regex_proof_${task_id}.json" ]]; then
          echo "Task $task_id exited without producing a proof in $attempt_dir" >&2
          exit 1
        fi
      done

      if ! (cd "$attempt_dir" && RAYON_NUM_THREADS="$AGGREGATION_RAYON_NUM_THREADS" RUST_BACKTRACE=1 RUST_LOG=info \
        "$AGGREGATION_BIN" ./proof_data ./proof_data/verification_key.bin "$NUM_TASKS" \
        > logs/aggregation.log 2>&1); then
        echo "Aggregation failed: $attempt_dir/logs/aggregation.log" >&2
        exit 1
      fi
      metrics="$attempt_dir/logs/metrics/aggregation_metrics.csv"
      if [[ ! -f "$metrics" ]] || \
        [[ "$(awk -F, '$1=="num_proofs_input" {print $2}' "$metrics")" != "$NUM_TASKS" ]] || \
        ! grep -Fq 'Aggregate proof verified successfully!' "$attempt_dir/logs/aggregation.log"; then
        echo "Aggregation did not verify all $NUM_TASKS proofs: $attempt_dir" >&2
        exit 1
      fi

      elapsed_ms=$(( $(date +%s%3N) - start_ms ))
      printf '%s\n' "$elapsed_ms" > "$case_dir/e2e_ms"
      printf '%s\n' "$attempt_dir" > "$case_dir/completed_attempt"
      write_results
      echo "Completed Regex $regex_id $case_type round $round/$REPEATS: $elapsed_ms ms"
    done
  done
done

echo "Raw results: $RUN_ROOT/e2e_raw.csv"
echo "Averages across $REPEATS round(s): $RUN_ROOT/e2e_summary.csv"
