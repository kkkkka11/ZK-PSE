#!/usr/bin/env bash
set -euo pipefail

# Single-prover arkworks Groth16 benchmark for the five password policies.
# VARIANT=all (default), G16-Enhanced, or G16-Base.
# G16-Enhanced: shared input and no substring/reveal helpers.
# G16-Base: independent DFA inputs and substring/reveal helpers.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RULES_FILE="${RULES_FILE:-regex/password_policies_5.txt}"
SI_CIRCUITS="${SI_CIRCUITS:-fixtures/password_policies_5_ascii}"
BASE_CIRCUITS="${BASE_CIRCUITS:-fixtures/password_policies_5_ascii_noshare}"
RESULTS_DIR="${RESULTS_DIR:-benchmark_results/g16_baselines}"
VARIANT="${VARIANT:-all}"
NUM_TASKS="${NUM_TASKS:-64}"
REPEATS="${REPEATS:-10}"
RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-1}"
SKIP_CIRCUIT_BUILD="${SKIP_CIRCUIT_BUILD:-0}"
CLEAN="${CLEAN:-0}"
RESUME="${RESUME:-1}"
BENCH_BIN="./target/release/examples/password_policy_arkworks_benchmark"

positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]] || { echo "Expected a positive integer, got: $1" >&2; exit 2; }
}
positive_integer "$NUM_TASKS"
positive_integer "$REPEATS"
positive_integer "$RAYON_NUM_THREADS"

case "$VARIANT" in
  all|G16-Enhanced|G16-Base) ;;
  *) echo "VARIANT must be all, G16-Enhanced, or G16-Base" >&2; exit 2 ;;
esac

if [[ "$CLEAN" == "1" ]]; then
  rm -rf "$SI_CIRCUITS" "$BASE_CIRCUITS" "$RESULTS_DIR" logs proof_data
fi
mkdir -p "$RESULTS_DIR"

cargo build --release --example password_policy_arkworks_benchmark --features parallel

if [[ "$SKIP_CIRCUIT_BUILD" != "1" ]]; then
  if [[ "$VARIANT" == "all" || "$VARIANT" == "G16-Enhanced" ]]; then
    node regex/build_lookahead_circuits.js "$RULES_FILE" "$SI_CIRCUITS" \
      --compile --shared-input true --dot ascii
  fi
  if [[ "$VARIANT" == "all" || "$VARIANT" == "G16-Base" ]]; then
    node regex/build_lookahead_circuits.js "$RULES_FILE" "$BASE_CIRCUITS" \
      --compile --shared-input false --gen-substrs --dot ascii
  fi
else
  echo "Using existing circuits (SKIP_CIRCUIT_BUILD=1)"
fi

set_count=2
[[ "$VARIANT" == "all" ]] || set_count=1
expected_rows=$((set_count * 2 * 5 * NUM_TASKS * REPEATS))

if [[ "$RESUME" == "1" && -f "$RESULTS_DIR/proof_raw.csv" ]]; then
  completed_rows=$(awk -F, '
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        sub(/\r$/, "", $i)
        column[$i] = i
      }
      next
    }
    column["status"] && column["witness_generation_ms"] && column["total_proving_time_ms"] {
      if ($(column["status"]) == "ok") count++
    }
    END { print count + 0 }
  ' "$RESULTS_DIR/proof_raw.csv")
  if [[ "$completed_rows" -ge "$expected_rows" ]]; then
    echo "[$(date '+%F %T')] benchmark already complete; skipping"
    exit 0
  fi
fi

rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"
echo "[$(date '+%F %T')] $VARIANT: ${NUM_TASKS} witnesses x ${REPEATS} proofs, 5 regexes"
env -u ARK_STD_PRINT_TRACE RAYON_NUM_THREADS="$RAYON_NUM_THREADS" \
  "$BENCH_BIN" \
    --variant "$VARIANT" \
    --optimized "$SI_CIRCUITS" \
    --noshare "$BASE_CIRCUITS" \
    --good fixtures/regex/witness-good \
    --bad fixtures/regex/witness-bad \
    --repeats "$REPEATS" \
    --setup-repeats 10 \
    --regex-count 5 \
    --max-tasks "$NUM_TASKS" \
    --out "$RESULTS_DIR"

echo "Completed. Detailed rows: $RESULTS_DIR/proof_raw.csv"
echo "Setup rows: $RESULTS_DIR/setup_raw.csv"
echo "Summary: $RESULTS_DIR/summary.csv"
