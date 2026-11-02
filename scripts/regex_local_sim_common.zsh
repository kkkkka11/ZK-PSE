#!/usr/bin/env bash
set -euo pipefail

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
AGGREGATION_RAYON_NUM_THREADS="${AGGREGATION_RAYON_NUM_THREADS:-$(nproc)}"
NETWORK_CONFIG_DIR="${NETWORK_CONFIG_DIR:-./network-address}"
PROOF_BIN="./target/release/examples/regex"
AGGREGATION_BIN="./target/release/aggregation_server"

log_status() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

get_metric_from_csv() {
  local csv_file="$1"
  local metric_name="$2"
  local missing_value="${3-0}"

  if [ -f "$csv_file" ]; then
    local value
    # A resumed task may append a complete record. Reset at each record so a
    # missing new field cannot silently inherit an older record's measurement.
    value="$(awk -F, -v key="$metric_name" '
      $1 == "task_id" || $1 == "num_proofs_input" { value = "" }
      $1 == key { value = $2 }
      END { if (value != "") print value }
    ' "$csv_file")"
    echo "${value:-$missing_value}"
  else
    echo "$missing_value"
  fi
}

add_decimal() {
  local left="$1"
  local right="$2"

  if command -v bc >/dev/null 2>&1; then
    echo "$left + $right" | bc
  else
    awk -v left="$left" -v right="$right" 'BEGIN { printf "%.9f\n", left + right }'
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
    awk -v total="$total" -v count="$count" 'BEGIN { printf "%.2f\n", total / count }'
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
    if ! RUST_BACKTRACE=1 RUST_LOG=info "$PROOF_BIN" \
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
      2>&1 | tee "$log_file"; then
      log_status "Task $task_id failed. See $log_file; stopping before aggregation."
      exit 1
    fi
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
  local total_online_computation=0
  local total_mpc_execution=0
  local online_computation_samples=0
  local total_witness_generation=0
  local total_witness_sharing=0
  local total_qap_sharing=0
  local qap_sharing_samples=0
  local timing_scope_version=""
  local total_proof_size=0
  local constraint_count=0
  local aggregation_total=0
  local compression_ratio=0
  local throughput=0
  local i

  for i in $(seq 0 $((NUM_TASKS - 1))); do
    local task_csv="$METRICS_DIR/task_${i}_metrics.csv"
    if [ -f "$task_csv" ]; then
      local task_scope="$(get_metric_from_csv "$task_csv" "timing_scope_version" "1")"
      if [ -n "$timing_scope_version" ] && [ "$task_scope" != "$timing_scope_version" ]; then
        echo "Error: mixed timing scopes in $METRICS_DIR; keep old and new runs separate" >&2
        return 1
      fi
      timing_scope_version="$task_scope"
      if [ "$task_scope" = "2" ]; then
        local qap_sharing="$(get_metric_from_csv "$task_csv" "qap_sharing_ms" "")"
        if [ -z "$qap_sharing" ]; then
          echo "Error: scope 2 task is missing qap_sharing_ms: $task_csv" >&2
          return 1
        fi
        total_qap_sharing="$(add_decimal "$total_qap_sharing" "$qap_sharing")"
        qap_sharing_samples=$((qap_sharing_samples + 1))
      elif [ "$task_scope" != "1" ]; then
        echo "Error: unsupported timing_scope_version=$task_scope: $task_csv" >&2
        return 1
      fi
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
      local online_computation="$(get_metric_from_csv "$task_csv" "online_computation_ms" "")"
      local mpc_execution="$(get_metric_from_csv "$task_csv" "mpc_execution_ms" "")"
      if [ -n "$online_computation" ] && [ -n "$mpc_execution" ]; then
        total_online_computation="$(add_decimal "$total_online_computation" "$online_computation")"
        total_mpc_execution="$(add_decimal "$total_mpc_execution" "$mpc_execution")"
        online_computation_samples=$((online_computation_samples + 1))
      fi

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
online_computation_samples,$online_computation_samples
timing_scope_version,$timing_scope_version
qap_sharing_samples,$qap_sharing_samples
EOF
  if [ "$qap_sharing_samples" -eq "$NUM_TASKS" ] && [ "$qap_sharing_samples" -gt 0 ]; then
    cat >> "$summary_csv" <<EOF
total_qap_sharing_ms,$total_qap_sharing
avg_qap_sharing_ms,$(average_decimal "$total_qap_sharing" "$NUM_TASKS")
EOF
  else
    printf 'total_qap_sharing_ms,\navg_qap_sharing_ms,\n' >> "$summary_csv"
  fi
  if [ "$online_computation_samples" -eq "$NUM_TASKS" ] && [ "$online_computation_samples" -gt 0 ]; then
    cat >> "$summary_csv" <<EOF
total_online_computation_ms,$total_online_computation
avg_online_computation_ms,$(average_decimal "$total_online_computation" "$NUM_TASKS")
total_mpc_execution_ms,$total_mpc_execution
avg_mpc_execution_ms,$(average_decimal "$total_mpc_execution" "$NUM_TASKS")
EOF
  else
    # Legacy/mixed batches have no complete measurement of this new scope.
    cat >> "$summary_csv" <<EOF
total_online_computation_ms,
avg_online_computation_ms,
total_mpc_execution_ms,
avg_mpc_execution_ms,
EOF
  fi

  log_status "Performance summary saved to $summary_csv"
}

run_aggregation_if_possible() {
  local proof_count
  local run_id

  if [ "${SKIP_AGGREGATION:-0}" = "1" ]; then
    log_status "Skipping aggregation because SKIP_AGGREGATION=1"
    return
  fi

  proof_count="$(find proof_data -maxdepth 1 -name 'regex_proof_*.json' | wc -l | tr -d ' ')"
  if [ "$proof_count" -eq 0 ]; then
    echo "Error: no proof_data/regex_proof_*.json files were generated"
    exit 1
  fi
  if [ "$proof_count" -ne "$NUM_TASKS" ]; then
    echo "Error: expected $NUM_TASKS proof files, found $proof_count; refusing incomplete aggregation"
    exit 1
  fi

  if [ ! -f "proof_data/verification_key.bin" ]; then
    echo "Error: proof_data/verification_key.bin was not generated"
    exit 1
  fi

  log_status "Aggregating $proof_count proofs ($AGGREGATION_REPEATS repeats)"
  for run_id in $(seq 1 "$AGGREGATION_REPEATS"); do
    log_status "Aggregation run $run_id/$AGGREGATION_REPEATS"
    # aggregation_server appends to this path. Start each repeat with a fresh
    # file so aggregation_run_N_metrics.csv is exactly one measurement.
    rm -f "$METRICS_DIR/aggregation_metrics.csv"
    RAYON_NUM_THREADS="$AGGREGATION_RAYON_NUM_THREADS" RUST_BACKTRACE=1 RUST_LOG=info \
      "$AGGREGATION_BIN" ./proof_data ./proof_data/verification_key.bin "$NUM_TASKS" \
      2>&1 | tee "logs/aggregation_run_${run_id}.log"
    if [ ! -f "$METRICS_DIR/aggregation_metrics.csv" ]; then
      echo "Error: aggregation run $run_id did not produce metrics"
      exit 1
    fi
    mv "$METRICS_DIR/aggregation_metrics.csv" "$METRICS_DIR/aggregation_run_${run_id}_metrics.csv"
  done
}

generate_benchmark_csvs() {
  local proof_raw_csv="$METRICS_DIR/proof_raw.csv"
  local aggregation_raw_csv="$METRICS_DIR/aggregation_raw.csv"
  local summary_csv="$METRICS_DIR/benchmark_summary.csv"
  local i
  local timing_scope_version=""

  echo "label,task_id,witness_file,expected_match,constraints,client_time_ms,witness_generation_ms,r1cs_to_qap_ms,witness_share_ms,client_share_serialization_ms,client_to_server_total_payload_bytes,client_to_server_max_share_payload_bytes,mpc_preprocessing_time_ms,mpc_total_time_ms,mpc_server_to_server_total_payload_bytes,mpc_server_to_server_max_sent_payload_bytes,mpc_server_to_server_max_received_payload_bytes,proof_size_bytes,commitment_size_bytes,public_inputs_payload_bytes,server_to_aggregator_cryptographic_payload_bytes,server_to_aggregator_json_artifact_bytes,process_peak_rss_bytes,setup_time_ms,mpc_execution_ms,online_computation_ms,qap_sharing_ms,timing_scope_version" > "$proof_raw_csv"
  for i in $(seq 0 $((NUM_TASKS - 1))); do
    local task_csv="$METRICS_DIR/task_${i}_metrics.csv"
    if [ -f "$task_csv" ]; then
      local task_scope="$(get_metric_from_csv "$task_csv" "timing_scope_version" "1")"
      if [ -n "$timing_scope_version" ] && [ "$task_scope" != "$timing_scope_version" ]; then
        echo "Error: mixed timing scopes in $METRICS_DIR; keep old and new runs separate" >&2
        return 1
      fi
      timing_scope_version="$task_scope"
      if [ "$task_scope" = "2" ] && [ -z "$(get_metric_from_csv "$task_csv" "qap_sharing_ms" "")" ]; then
        echo "Error: scope 2 task is missing qap_sharing_ms: $task_csv" >&2
        return 1
      elif [ "$task_scope" != "1" ] && [ "$task_scope" != "2" ]; then
        echo "Error: unsupported timing_scope_version=$task_scope: $task_csv" >&2
        return 1
      fi
      echo "$LABEL,$i,${WITNESS_FILES[$i]},$EXPECTED_MATCH,$(get_metric_from_csv "$task_csv" "constraint_count"),$(get_metric_from_csv "$task_csv" "client_total_time_ms"),$(get_metric_from_csv "$task_csv" "witness_generation_ms"),$(get_metric_from_csv "$task_csv" "r1cs_to_qap_ms"),$(get_metric_from_csv "$task_csv" "witness_secret_sharing_ms"),$(get_metric_from_csv "$task_csv" "client_share_serialization_ms"),$(get_metric_from_csv "$task_csv" "client_to_server_total_payload_bytes"),$(get_metric_from_csv "$task_csv" "client_to_server_max_share_payload_bytes"),$(get_metric_from_csv "$task_csv" "mpc_preprocessing_ms"),$(get_metric_from_csv "$task_csv" "mpc_total_time_ms"),$(get_metric_from_csv "$task_csv" "mpc_server_to_server_total_payload_bytes"),$(get_metric_from_csv "$task_csv" "mpc_server_to_server_max_sent_payload_bytes"),$(get_metric_from_csv "$task_csv" "mpc_server_to_server_max_received_payload_bytes"),$(get_metric_from_csv "$task_csv" "proof_size_bytes"),$(get_metric_from_csv "$task_csv" "commitment_size_bytes"),$(get_metric_from_csv "$task_csv" "public_inputs_payload_bytes"),$(get_metric_from_csv "$task_csv" "server_to_aggregator_cryptographic_payload_bytes"),$(get_metric_from_csv "$task_csv" "server_to_aggregator_json_artifact_bytes"),$(get_metric_from_csv "$task_csv" "process_peak_rss_bytes"),$(get_metric_from_csv "$task_csv" "circuit_building_ms"),$(get_metric_from_csv "$task_csv" "mpc_execution_ms" ""),$(get_metric_from_csv "$task_csv" "online_computation_ms" ""),$(get_metric_from_csv "$task_csv" "qap_sharing_ms" ""),$task_scope" >> "$proof_raw_csv"
    fi
  done

  echo "label,run_id,num_proofs,aggregation_setup_time_ms,individual_verify_total_ms,individual_verify_avg_ms,batch_verify_time_ms,batch_verify_amortized_per_proof_ms,aggregation_total_ms,aggregate_proof_size_bytes,aggregator_input_json_bytes,public_inputs_payload_bytes,aggregator_to_verifier_payload_bytes,process_peak_rss_bytes,compression_ratio" > "$aggregation_raw_csv"
  if [ "${SKIP_AGGREGATION:-0}" != "1" ]; then
    for i in $(seq 1 "$AGGREGATION_REPEATS"); do
      local agg_csv="$METRICS_DIR/aggregation_run_${i}_metrics.csv"
      if [ -f "$agg_csv" ]; then
        echo "$LABEL,$i,$(get_metric_from_csv "$agg_csv" "num_proofs_input"),$(get_metric_from_csv "$agg_csv" "srs_setup_ms"),$(get_metric_from_csv "$agg_csv" "individual_verification_total_ms"),$(get_metric_from_csv "$agg_csv" "individual_verification_avg_ms"),$(get_metric_from_csv "$agg_csv" "aggregate_verification_ms"),$(get_metric_from_csv "$agg_csv" "batch_verify_amortized_per_proof_ms"),$(get_metric_from_csv "$agg_csv" "aggregation_total_ms"),$(get_metric_from_csv "$agg_csv" "aggregate_proof_size_bytes"),$(get_metric_from_csv "$agg_csv" "aggregator_input_json_bytes"),$(get_metric_from_csv "$agg_csv" "public_inputs_payload_bytes"),$(get_metric_from_csv "$agg_csv" "aggregator_to_verifier_payload_bytes"),$(get_metric_from_csv "$agg_csv" "process_peak_rss_bytes"),$(get_metric_from_csv "$agg_csv" "compression_ratio")" >> "$aggregation_raw_csv"
      fi
    done
  fi

  awk -F, '
    NR == 1 { next }
    {
      proof_count += 1
      constraints = $5
      client += $6
      proof_size += $18
      commitment_size += $19
      if (proof_count == 1) setup_once = $24
      mpc_preprocessing += $13
      timing_scope = $28
      if ($28 == 2) { qap_samples += 1; qap += $27 }
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
      printf "timing_scope_version,%s\n", timing_scope >> summary
      printf "qap_sharing_samples,%d\n", qap_samples >> summary
      if (qap_samples == proof_count && qap_samples > 0) {
        printf "avg_qap_sharing_ms,%.6f\n", qap / proof_count >> summary
      } else {
        printf "avg_qap_sharing_ms,\n" >> summary
      }
    }
  ' label="$LABEL" expected="$EXPECTED_MATCH" summary="$summary_csv" "$proof_raw_csv"

  awk -F, '
    NR == 1 { next }
    $25 != "" && $26 != "" { samples += 1; execution += $25; online += $26 }
    END {
      printf "online_computation_samples,%d\n", samples >> summary
      if (samples == expected && samples > 0) {
        printf "avg_mpc_execution_ms,%.6f\n", execution / samples >> summary
        printf "avg_online_computation_ms,%.6f\n", online / samples >> summary
      } else {
        printf "avg_mpc_execution_ms,\navg_online_computation_ms,\n" >> summary
      }
    }
  ' expected="$NUM_TASKS" summary="$summary_csv" "$proof_raw_csv"

  awk -F, '
    NR == 1 { next }
    {
      agg_count += 1
      agg_setup += $4
      batch_verify += $7
      agg_total += $9
      agg_proof_size += $10
      compression += $15
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
