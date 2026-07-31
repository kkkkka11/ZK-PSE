# ZK-PSE

Zero-knowledge password-policy proving and proof aggregation.

## Requirements

- Rust
- Node.js and npm
- `circom`
- `zk-regex` with `decomposed --shared-input true`

If `zk-regex` is not in `regex/target/release/zk-regex`, set:

```bash
export ZK_REGEX_BIN=/path/to/zk-regex
```

## Install

```bash
npm install
cargo check --workspace
```

## Generate Circuits

Shared-input optimized circuits:

```bash
cd regex
node build_lookahead_circuits.js password_policies_5.txt ../fixtures/password_policies_5_ascii \
  --compile \
  --shared-input true \
  --dot ascii
cd ..
```

No-share baseline circuits:

```bash
cd regex
node build_lookahead_circuits.js password_policies_5.txt ../fixtures/password_policies_5_ascii_noshare \
  --compile \
  --shared-input false \
  --gen-substrs \
  --dot ascii
cd ..
```

## Build

```bash
cargo build --release --example regex --features parallel
cargo build --release --bin aggregation_server
```

## Run One Experiment

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

Bad witnesses:

```bash
SKIP_BUILD=1 NUM_TASKS=64 \
N_PARAM=16 L_PARAM=2 T_PARAM=2 RAYON_NUM_THREADS=1 \
./scripts/regex_1_bad.zsh
```

## Smoke Test

```bash
node regex/build_lookahead_circuits.js regex/smoke_policy.txt fixtures/password_policies_5_ascii \
  --compile \
  --no-shared-input \
  --dot ascii
cargo build --release --example regex --features parallel
cargo build --release --bin aggregation_server
NUM_TASKS=2 AGGREGATION_REPEATS=1 SKIP_BUILD=1 ./scripts/regex_1_good.zsh
```

## License

MIT
