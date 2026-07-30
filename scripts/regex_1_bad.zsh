#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_SET_DIR="${CIRCUIT_SET_DIR:-./fixtures/password_policies_5_ascii}"
WITNESS_DIR="${WITNESS_DIR:-./fixtures/regex/witness-bad}" EXPECTED_MATCH="${EXPECTED_MATCH:-0}" \
"$SCRIPT_DIR/regex_local_sim_common.zsh" "regex_1_bad" "$CIRCUIT_SET_DIR/regex_1/build/GeneratedRegex1.r1cs" "$CIRCUIT_SET_DIR/regex_1/build/GeneratedRegex1_js" "1_bad" "${NUM_TASKS:-64}"
