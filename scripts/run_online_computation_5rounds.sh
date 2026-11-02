#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if (( $# > 1 )); then
  echo "Usage: REGEX_IDS='1 2' bash $0 [output-directory]" >&2
  exit 1
fi
RUN_ROOT="${1:-$PROJECT_ROOT/experiments/online_computation_5rounds_$(date +%Y%m%d_%H%M%S)_$$}"
RUN_ROOT="$(realpath -m "$RUN_ROOT")"
cd "$PROJECT_ROOT"

export REGEX_IDS="${REGEX_IDS-1 2 3 4 5}"
export NUM_TASKS=64 REPEATS=5 N_PARAM=16 L_PARAM=2 T_PARAM=2 M_PARAM=32768
export RAYON_NUM_THREADS=1 AGGREGATION_RAYON_NUM_THREADS=12 SKIP_BUILD=1
read -r -a regex_ids <<< "$REGEX_IDS"

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  bash "$SCRIPT_DIR/run_e2e_regex1_5.zsh" "$RUN_ROOT"
  exit 0
fi

mkdir -p "$RUN_ROOT"
exec 8>"$RUN_ROOT/.launcher.lock"
flock -n 8 || { echo "Another launcher is using $RUN_ROOT" >&2; exit 1; }

# Keep this long experiment on the same executables even if target/ is rebuilt.
export PROOF_BIN="$RUN_ROOT/bin/regex"
export AGGREGATION_BIN="$RUN_ROOT/bin/aggregation_server"
if [[ ! -f "$RUN_ROOT/config.txt" ]]; then
  cargo build --locked --offline --release --example regex --bin aggregation_server --features parallel
  mkdir -p "$RUN_ROOT/bin" "$RUN_ROOT/provenance"
  cp target/release/examples/regex "$PROOF_BIN"
  cp target/release/aggregation_server "$AGGREGATION_BIN"
  cp groth16/examples/regex.rs "$RUN_ROOT/provenance/regex.rs"
  cp "$SCRIPT_DIR/run_e2e_regex1_5.zsh" "$SCRIPT_DIR/summarize_online_computation.py" \
    "$SCRIPT_DIR/run_online_computation_5rounds.sh" "$RUN_ROOT/provenance/"
  sha256sum "$PROOF_BIN" "$AGGREGATION_BIN" "$RUN_ROOT/provenance/regex.rs" \
    > "$RUN_ROOT/provenance/sha256.txt"
fi

echo "Output: $RUN_ROOT"
echo "Regex IDs: $REGEX_IDS; 5 rounds x 2 cases x 64 proofs per regex"
bash "$SCRIPT_DIR/run_e2e_regex1_5.zsh" "$RUN_ROOT"
python3 "$SCRIPT_DIR/summarize_online_computation.py" "$RUN_ROOT" --regex "${regex_ids[@]}"
