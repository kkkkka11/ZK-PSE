#!/usr/bin/env bash
set -e

if [ "$#" -lt 4 ]; then
  echo "Usage: $0 <label> <r1cs_file> <wasm_dir> <archive_suffix> [default_num_tasks]"
  exit 1
fi

LABEL="$1"
R1CS_FILE="$2"
WASM_DIR="$3"
ARCHIVE_SUFFIX="$4"
DEFAULT_NUM_TASKS="${5:-64}"

METRICS_DIR="logs/metrics"
SCRIPT_START_TIME=$(date +%s%3N)

WITNESS_DIR="${WITNESS_DIR:-./fixtures/regex/witness}"
EXPECTED_MATCH="${EXPECTED_MATCH:-1}"
NUM_TASKS="${NUM_TASKS:-$DEFAULT_NUM_TASKS}"
RESUME_FROM="${RESUME_FROM:-0}"
L_PARAM="${L_PARAM:-2}"
T_PARAM="${T_PARAM:-2}"
N_PARAM="${N_PARAM:-16}"
M_PARAM="${M_PARAM:-32768}"
AGGREGATION_REPEATS="${AGGREGATION_REPEATS:-10}"
NETWORK_CONFIG_DIR="${NETWORK_CONFIG_DIR:-./network-address}"
PROOF_BIN="./target/release/examples/regex"
AGGREGATION_BIN="./target/release/aggregation_server"

log_status() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

get_metric_from_csv() {
  local csv_file="$1"
  local metric_name="$2"

  if [ -f "$csv_file" ]; then
    grep "^$metric_name," "$csv_file" | cut -d',' -f2 | head -n1
  else
    echo "0"
  fi
}

add_decimal() {
  local left="$1"
  local right="$2"

  if command -v bc >/dev/null 2>&1; then
    echo "$left + $right" | bc
  else
    left="${left%.*}"
    right="${right%.*}"
    echo $((left + right))
  fi
}

average_decimal() {
  local total="$1"
  local count="$2"

  if [ "$count" -eq 0 ]; then
    echo "0"
  elif command -v bc >/dev/null 2>&1; then
    echo "scale=2; $total / $count" | bc
  else
    total="${total%.*}"
    echo $((total / count))
  fi
}

create_directories() {
  if [ "$RESUME_FROM" -gt 0 ]; then
    log_status "Resuming $LABEL from task $RESUME_FROM; preserving existing logs/ and proof_data/"
  else
    log_status "Creating fresh logs/ and proof_data/ for $LABEL"
    rm -rf logs proof_data
  fi
  mkdir -p "$METRICS_DIR" proof_data/agg
}

find_witness_files() {
  if [ ! -d "$WITNESS_DIR" ]; then
    echo "Error: witness directory not found: $WITNESS_DIR"
    exit 1
  fi

  mapfile -t WITNESS_FILES < <(find "$WITNESS_DIR" \( -name 'task*.json' -o -name 'party*.json' \) | sort -V)

  if [ "${#WITNESS_FILES[@]}" -eq 0 ]; then
    echo "Error: no task*.json or party*.json files found in $WITNESS_DIR"
    exit 1
  fi

  if [ "${#WITNESS_FILES[@]}" -lt "$NUM_TASKS" ]; then
    log_status "Only ${#WITNESS_FILES[@]} witness files available; using that many tasks"
    NUM_TASKS="${#WITNESS_FILES[@]}"
  fi

  log_status "Using $NUM_TASKS witness files from $WITNESS_DIR"
}

validate_inputs() {
  local circuit_name
  circuit_name="$(basename "$R1CS_FILE" .r1cs)"

  if [ ! -f "$R1CS_FILE" ]; then
    echo "Error: R1CS file not found: $R1CS_FILE"
    exit 1
  fi

  if [ ! -f "$WASM_DIR/$circuit_name.wasm" ]; then
    echo "Error: WASM file not found: $WASM_DIR/$circuit_name.wasm"
    exit 1
  fi
}

build_binaries() {
  if [ "${SKIP_BUILD:-0}" = "1" ]; then
    log_status "Skipping cargo build because SKIP_BUILD=1"
    return
  fi

  log_status "Building regex and aggregation_server"
  cargo build --release --example regex --features parallel
  cargo build --release --bin aggregation_server
}

run_local_mpc_simulation() {
  local task_id

  log_status "Starting local MPC simulation for $LABEL"
  log_status "Parameters: n=$N_PARAM, l=$L_PARAM, t=$T_PARAM, m=$M_PARAM, expected_match=$EXPECTED_MATCH"
  log_status "Task range: $RESUME_FROM to $((NUM_TASKS - 1))"

  for task_id in $(seq "$RESUME_FROM" $((NUM_TASKS - 1))); do
    local witness_file="${WITNESS_FILES[$task_id]}"
    local log_file="logs/task${task_id}_local_mpc.log"

    log_status "Task $task_id: $witness_file"
    RUST_BACKTRACE=1 RUST_LOG=info "$PROOF_BIN" \
      0 \
      "$task_id" \
      "$NETWORK_CONFIG_DIR/$N_PARAM" \
      "$L_PARAM" \
      "$T_PARAM" \
      "$M_PARAM" \
      "$R1CS_FILE" \
      "$witness_file" \
      "$EXPECTED_MATCH" \
      "$N_PARAM" \
      2>&1 | tee "$log_file"
  done
}

generate_performance_summary() {
  local total_execution_time="$1"
  local summary_csv="$METRICS_DIR/performance_summary.csv"
  local total_client_time=0
  local total_mpc_preprocessing=0
  local total_mpc_computation=0
  local total_mpc_h=0
  local total_mpc_a=0
  local total_mpc_b_g1=0
  local total_mpc_b_g2=0
  local total_mpc_c=0
  local total_mpc_reconstruction=0
  local total_witness_generation=0
  local total_witness_sharing=0
  local total_proof_size=0
  local constraint_count=0
  local aggregation_total=0
  local compression_ratio=0
  local throughput=0
  local i

  for i in $(seq 0 $((NUM_TASKS - 1))); do
    local task_csv="$METRICS_DIR/task_${i}_metrics.csv"
    if [ -f "$task_csv" ]; then
      local client_time="$(get_metric_from_csv "$task_csv" "client_total_time_ms")"
      local mpc_preprocessing="$(get_metric_from_csv "$task_csv" "mpc_preprocessing_ms")"
      local mpc_total="$(get_metric_from_csv "$task_csv" "mpc_total_time_ms")"
      local mpc_h="$(get_metric_from_csv "$task_csv" "mpc_h_computation_ms")"
      local mpc_a="$(get_metric_from_csv "$task_csv" "mpc_a_computation_ms")"
      local mpc_b_g1="$(get_metric_from_csv "$task_csv" "mpc_b_g1_computation_ms")"
      local mpc_b_g2="$(get_metric_from_csv "$task_csv" "mpc_b_g2_computation_ms")"
      local mpc_c="$(get_metric_from_csv "$task_csv" "mpc_c_computation_ms")"
      local mpc_reconstruction="$(get_metric_from_csv "$task_csv" "mpc_reconstruction_ms")"
      local witness_generation="$(get_metric_from_csv "$task_csv" "witness_generation_ms")"
      local witness_sharing="$(get_metric_from_csv "$task_csv" "witness_secret_sharing_ms")"
      local proof_size="$(get_metric_from_csv "$task_csv" "proof_size_bytes")"

      total_client_time="$(add_decimal "$total_client_time" "$client_time")"
      total_mpc_preprocessing="$(add_decimal "$total_mpc_preprocessing" "$mpc_preprocessing")"
      total_mpc_computation="$(add_decimal "$total_mpc_computation" "$mpc_total")"
      total_mpc_h="$(add_decimal "$total_mpc_h" "$mpc_h")"
      total_mpc_a="$(add_decimal "$total_mpc_a" "$mpc_a")"
      total_mpc_b_g1="$(add_decimal "$total_mpc_b_g1" "$mpc_b_g1")"
      total_mpc_b_g2="$(add_decimal "$total_mpc_b_g2" "$mpc_b_g2")"
      total_mpc_c="$(add_decimal "$total_mpc_c" "$mpc_c")"
      total_mpc_reconstruction="$(add_decimal "$total_mpc_reconstruction" "$mpc_reconstruction")"
      total_witness_generation="$(add_decimal "$total_witness_generation" "$witness_generation")"
      total_witness_sharing="$(add_decimal "$total_witness_sharing" "$witness_sharing")"
      total_proof_size="$(add_decimal "$total_proof_size" "$proof_size")"

      if [ "$constraint_count" = "0" ]; then
        constraint_count="$(get_metric_from_csv "$task_csv" "constraint_count")"
      fi
    fi
  done

  if [ -f "$METRICS_DIR/aggregation_metrics.csv" ]; then
    aggregation_total="$(get_metric_from_csv "$METRICS_DIR/aggregation_metrics.csv" "aggregation_total_ms")"
    compression_ratio="$(get_metric_from_csv "$METRICS_DIR/aggregation_metrics.csv" "compression_ratio")"
  fi

  if [ "$total_execution_time" -gt 0 ] && command -v bc >/dev/null 2>&1; then
    throughput="$(echo "scale=3; $NUM_TASKS * 1000 / $total_execution_time" | bc)"
  fi

  cat > "$summary_csv" <<EOF
metric,value
experiment,$LABEL
execution_mode,local_mpc_simulation
total_execution_ms,$total_execution_time
num_tasks_completed,$NUM_TASKS
packing_parameter_l,$L_PARAM
internal_virtual_parties,$N_PARAM
mpc_n_param,$N_PARAM
effective_threshold_t,$T_PARAM
expected_match,$EXPECTED_MATCH
throughput_proofs_per_second,$throughput
constraint_count,$constraint_count
client_work_total_ms,$total_client_time
avg_client_time_ms,$(average_decimal "$total_client_time" "$NUM_TASKS")
total_mpc_preprocessing_ms,$total_mpc_preprocessing
total_mpc_computation_ms,$total_mpc_computation
avg_mpc_computation_ms,$(average_decimal "$total_mpc_computation" "$NUM_TASKS")
total_mpc_h_computation_ms,$total_mpc_h
total_mpc_a_computation_ms,$total_mpc_a
total_mpc_b_g1_computation_ms,$total_mpc_b_g1
total_mpc_b_g2_computation_ms,$total_mpc_b_g2
total_mpc_c_computation_ms,$total_mpc_c
total_mpc_reconstruction_ms,$total_mpc_reconstruction
total_witness_generation_time_ms,$total_witness_generation
total_witness_sharing_time_ms,$total_witness_sharing
total_individual_proof_size_bytes,$total_proof_size
aggregation_total_ms,$aggregation_total
aggregation_compression_ratio,$compression_ratio
EOF

  log_status "Performance summary saved to $summary_csv"
}

run_aggregation_if_possible() {
  local proof_count
  local run_id

  proof_count="$(find proof_data -maxdepth 1 -name 'regex_proof_*.json' | wc -l | tr -d ' ')"
  if [ "$proof_count" -eq 0 ]; then
    echo "Error: no proof_data/regex_proof_*.json files were generated"
    exit 1
  fi

  if [ ! -f "proof_data/verification_key.bin" ]; then
    echo "Error: proof_data/verification_key.bin was not generated"
    exit 1
  fi

  if [ "${SKIP_AGGREGATION:-0}" = "1" ]; then
    log_status "Skipping aggregation because SKIP_AGGREGATION=1"
    return
  fi

  log_status "Aggregating $proof_count proofs ($AGGREGATION_REPEATS repeats)"
  for run_id in $(seq 1 "$AGGREGATION_REPEATS"); do
    log_status "Aggregation run $run_id/$AGGREGATION_REPEATS"
    RUST_BACKTRACE=1 RUST_LOG=info "$AGGREGATION_BIN" ./proof_data ./proof_data/verification_key.bin \
      2>&1 | tee "logs/aggregation_run_${run_id}.log"
    cp "$METRICS_DIR/aggregation_metrics.csv" "$METRICS_DIR/aggregation_run_${run_id}_metrics.csv"
  done
}

generate_benchmark_csvs() {
  local proof_raw_csv="$METRICS_DIR/proof_raw.csv"
  local aggregation_raw_csv="$METRICS_DIR/aggregation_raw.csv"
  local summary_csv="$METRICS_DIR/benchmark_summary.csv"
  local i

  echo "label,task_id,witness_file,expected_match,constraints,client_time_ms,proof_size_bytes,commitment_size_bytes,setup_time_ms,mpc_preprocessing_time_ms" > "$proof_raw_csv"
  for i in $(seq 0 $((NUM_TASKS - 1))); do
    local task_csv="$METRICS_DIR/task_${i}_metrics.csv"
    if [ -f "$task_csv" ]; then
      echo "$LABEL,$i,${WITNESS_FILES[$i]},$EXPECTED_MATCH,$(get_metric_from_csv "$task_csv" "constraint_count"),$(get_metric_from_csv "$task_csv" "client_total_time_ms"),$(get_metric_from_csv "$task_csv" "proof_size_bytes"),$(get_metric_from_csv "$task_csv" "commitment_size_bytes"),$(get_metric_from_csv "$task_csv" "circuit_building_ms"),$(get_metric_from_csv "$task_csv" "mpc_preprocessing_ms")" >> "$proof_raw_csv"
    fi
  done

  echo "label,run_id,num_proofs,aggregation_setup_time_ms,batch_verify_time_ms,aggregation_total_ms,aggregate_proof_size_bytes,compression_ratio" > "$aggregation_raw_csv"
  if [ "${SKIP_AGGREGATION:-0}" != "1" ]; then
    for i in $(seq 1 "$AGGREGATION_REPEATS"); do
      local agg_csv="$METRICS_DIR/aggregation_run_${i}_metrics.csv"
      if [ -f "$agg_csv" ]; then
        echo "$LABEL,$i,$(get_metric_from_csv "$agg_csv" "num_proofs_input"),$(get_metric_from_csv "$agg_csv" "srs_setup_ms"),$(get_metric_from_csv "$agg_csv" "aggregate_verification_ms"),$(get_metric_from_csv "$agg_csv" "aggregation_total_ms"),$(get_metric_from_csv "$agg_csv" "aggregate_proof_size_bytes"),$(get_metric_from_csv "$agg_csv" "compression_ratio")" >> "$aggregation_raw_csv"
      fi
    done
  fi

  awk -F, '
    NR == 1 { next }
    {
      proof_count += 1
      constraints = $5
      client += $6
      proof_size += $7
      commitment_size += $8
      if (proof_count == 1) setup_once = $9
      mpc_preprocessing += $10
    }
    END {
      if (proof_count == 0) proof_count = 1
      printf "metric,value\n" > summary
      printf "experiment,%s\n", label >> summary
      printf "expected_match,%s\n", expected >> summary
      printf "num_proofs,%d\n", proof_count >> summary
      printf "constraints,%s\n", constraints >> summary
      printf "avg_client_time_ms,%.2f\n", client / proof_count >> summary
      printf "avg_proof_size_bytes,%.2f\n", proof_size / proof_count >> summary
      printf "avg_commitment_size_bytes,%.2f\n", commitment_size / proof_count >> summary
      printf "setup_time_ms,%.2f\n", setup_once >> summary
      printf "avg_mpc_preprocessing_time_ms,%.2f\n", mpc_preprocessing / proof_count >> summary
    }
  ' label="$LABEL" expected="$EXPECTED_MATCH" summary="$summary_csv" "$proof_raw_csv"

  awk -F, '
    NR == 1 { next }
    {
      agg_count += 1
      agg_setup += $4
      batch_verify += $5
      agg_total += $6
      agg_proof_size += $7
      compression += $8
    }
    END {
      if (agg_count == 0) {
        printf "aggregation_repeats_completed,0\n" >> summary
        exit
      }
      printf "aggregation_repeats_completed,%d\n", agg_count >> summary
      printf "avg_aggregation_setup_time_ms,%.2f\n", agg_setup / agg_count >> summary
      printf "avg_batch_verify_time_ms,%.2f\n", batch_verify / agg_count >> summary
      printf "avg_aggregation_total_time_ms,%.2f\n", agg_total / agg_count >> summary
      printf "avg_aggregate_proof_size_bytes,%.2f\n", agg_proof_size / agg_count >> summary
      printf "avg_aggregation_compression_ratio,%.4f\n", compression / agg_count >> summary
    }
  ' summary="$summary_csv" "$aggregation_raw_csv"

  log_status "Benchmark raw CSVs saved to $proof_raw_csv and $aggregation_raw_csv"
  log_status "Benchmark summary saved to $summary_csv"
}

archive_outputs() {
  local proof_archive="proof_data_${ARCHIVE_SUFFIX}"
  local logs_archive="logs_${ARCHIVE_SUFFIX}"

  rm -rf "$proof_archive" "$logs_archive"
  mkdir -p "$proof_archive" "$logs_archive"
  cp -r proof_data "$proof_archive/"
  cp -r logs "$logs_archive/"

  log_status "Archived outputs to $proof_archive/ and $logs_archive/"
}

create_directories
find_witness_files
validate_inputs
build_binaries
run_local_mpc_simulation
run_aggregation_if_possible
generate_benchmark_csvs

SCRIPT_END_TIME=$(date +%s%3N)
TOTAL_EXECUTION_TIME=$((SCRIPT_END_TIME - SCRIPT_START_TIME))
generate_performance_summary "$TOTAL_EXECUTION_TIME"
archive_outputs

log_status "Completed $LABEL local MPC simulation"
