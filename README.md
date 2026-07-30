# ZK-PSE

ZK-PSE is a zero-knowledge password-policy experiment. It converts password
policies written as regular expressions into Circom circuits, proves private
password witnesses with Groth16, and aggregates multiple proofs with SnarkPack.

> Research prototype. Not audited for production use.

## Layout

- `regex/`: regex policies, Circom helpers, and circuit generator.
- `fixtures/regex/`: good/bad password witnesses.
- `groth16/`: prover, verifier, metrics, and aggregation binary.
- `snarkpack/`: aggregation implementation.
- `secret-sharing/`, `dist-primitives/`, `mpc-net/`: MPC support crates.
- `scripts/`: single-policy proof and aggregation experiments.

Generated files are ignored by Git, including `target/`, `node_modules/`,
`fixtures/password_policies_5_ascii*/`, `proof_data*/`, `logs*/`, `.r1cs`,
`.wasm`, and `.sym`.

## Requirements

- Rust toolchain from `rust-toolchain.toml`
- Node.js and npm
- `circom`
- A `zk-regex` compiler that supports `decomposed --shared-input true`

The generator first checks `regex/target/release/zk-regex`. Otherwise set:

```bash
export ZK_REGEX_BIN=/path/to/zk-regex
```

Install JS dependencies and check Rust:

```bash
npm install
cargo check --workspace
```

## Regex To Circuit

Policies are in `regex/password_policies_5.txt`. The generator splits each
policy into lookahead subcircuits, combines their boolean outputs, and adds a
Poseidon binding:

```text
hash = Poseidon(k, Poseidon(msg[0..9]), Poseidon(msg[10..19]))
```

Public input: `expected_match`.
Private inputs: `msg[20]`, `k`.

Generate and compile the shared-input optimized circuits:

```bash
cd regex
node build_lookahead_circuits.js password_policies_5.txt ../fixtures/password_policies_5_ascii \
  --compile \
  --shared-input true \
  --dot ascii
cd ..
```

Generate and compile the no-share baseline circuits:

```bash
cd regex
node build_lookahead_circuits.js password_policies_5.txt ../fixtures/password_policies_5_ascii_noshare \
  --compile \
  --shared-input false \
  --gen-substrs \
  --dot ascii
cd ..
```

Outputs are created per policy, for example:

```text
fixtures/password_policies_5_ascii/regex_1/GeneratedRegex1.circom
fixtures/password_policies_5_ascii/regex_1/build/GeneratedRegex1.r1cs
fixtures/password_policies_5_ascii/regex_1/build/GeneratedRegex1_js/GeneratedRegex1.wasm
```

## Proving

Build the prover and aggregator:

```bash
cargo build --release --example regex --features parallel
cargo build --release --bin aggregation_server
```

The scripts read witnesses from:

```text
fixtures/regex/witness-good/
fixtures/regex/witness-bad/
```

Proof outputs:

```text
proof_data/regex_proof_<task_id>.json
proof_data/verification_key.bin
logs/metrics/
```

## Aggregation

Aggregation runs automatically unless `SKIP_AGGREGATION=1`.

Manual aggregation:

```bash
./target/release/aggregation_server ./proof_data ./proof_data/verification_key.bin
```

Aggregation outputs:

```text
proof_data/agg/
logs/metrics/aggregation_metrics.csv
logs/metrics/aggregation_raw.csv
```

## One Experiment

Use `regex_1_good.zsh` for Regex 1 good witnesses, or `regex_1_bad.zsh` for
bad witnesses.

Proof only:

```bash
SKIP_BUILD=1 SKIP_AGGREGATION=1 NUM_TASKS=64 \
N_PARAM=16 L_PARAM=2 T_PARAM=2 RAYON_NUM_THREADS=1 \
./scripts/regex_1_good.zsh
```

Proof plus aggregation:

```bash
SKIP_BUILD=1 NUM_TASKS=64 AGGREGATION_REPEATS=50 \
N_PARAM=16 L_PARAM=2 T_PARAM=2 RAYON_NUM_THREADS=1 \
./scripts/regex_1_good.zsh
```

Small smoke test:

```bash
node regex/build_lookahead_circuits.js regex/smoke_policy.txt fixtures/password_policies_5_ascii \
  --dot ascii \
  --compile \
  --no-shared-input
cargo build --release --example regex --features parallel
cargo build --release --bin aggregation_server
NUM_TASKS=2 AGGREGATION_REPEATS=1 SKIP_BUILD=1 ./scripts/regex_1_good.zsh
```

## Environment

```text
NUM_TASKS              number of witnesses, default 64
WITNESS_DIR            override witness directory
EXPECTED_MATCH         1 for good cases, 0 for bad cases
SKIP_BUILD             skip Rust build in scripts
SKIP_AGGREGATION       skip aggregation
AGGREGATION_REPEATS    aggregation repetitions, default 10
N_PARAM                virtual parties, default 16
L_PARAM                packing parameter, default 2
T_PARAM                threshold parameter, default 2
M_PARAM                circuit/domain parameter, default 32768
ZK_REGEX_BIN           custom zk-regex binary
```

## License

MIT
