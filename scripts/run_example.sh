#!/usr/bin/env bash
set -euo pipefail

# Minimal example: two Regex 1 match proofs, then aggregation and verification.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOF_BIN="$PROJECT_ROOT/target/release/examples/regex"
AGGREGATION_BIN="$PROJECT_ROOT/target/release/aggregation_server"
R1CS="$PROJECT_ROOT/fixtures/password_policies_5_ascii/regex_1/build/GeneratedRegex1.r1cs"
WASM="${R1CS%.r1cs}_js/GeneratedRegex1.wasm"
WITNESSES="$PROJECT_ROOT/fixtures/regex/witness-good"

for binary in "$PROOF_BIN" "$AGGREGATION_BIN"; do
  if [[ ! -x "$binary" ]]; then
    echo "Missing executable: $binary. Follow the README build steps first." >&2
    exit 1
  fi
done
for input in "$R1CS" "$WASM" "$WITNESSES/party0.json" "$WITNESSES/party1.json"; do
  if [[ ! -f "$input" ]]; then
    echo "Missing input: $input. Follow the README circuit-generation steps first." >&2
    exit 1
  fi
done

mkdir -p "$PROJECT_ROOT/experiments"
RUN_DIR="$(mktemp -d "$PROJECT_ROOT/experiments/regex1_example.XXXXXX")"
mkdir -p "$RUN_DIR/logs/metrics" "$RUN_DIR/proof_data/agg"
echo "Example output: $RUN_DIR"
cd "$RUN_DIR"

for task_id in 0 1; do
  echo "Generating proof $((task_id + 1))/2"
  if ! RAYON_NUM_THREADS=1 "$PROOF_BIN" \
    0 "$task_id" "$PROJECT_ROOT/network-address/16" 2 2 32768 \
    "$R1CS" "$WITNESSES/party${task_id}.json" 1 16 \
    > "logs/task${task_id}.log" 2>&1; then
    echo "Proof generation failed; see $RUN_DIR/logs/task${task_id}.log" >&2
    exit 1
  fi
done

echo "Aggregating and verifying two proofs"
if ! RAYON_NUM_THREADS=12 "$AGGREGATION_BIN" \
  ./proof_data ./proof_data/verification_key.bin 2 > logs/aggregation.log 2>&1; then
  echo "Aggregation or verification failed; see $RUN_DIR/logs/aggregation.log" >&2
  exit 1
fi
echo "Example completed. Proofs, logs, and metrics: $RUN_DIR"
