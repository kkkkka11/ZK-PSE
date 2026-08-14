# ZK-PSE

ZK-PSE is a zero-knowledge password-policy experiment. It converts password
policies written as regular expressions into Circom circuits, proves private
password witnesses with Groth16, and aggregates multiple proofs with SnarkPack.

The password itself stays private. The circuit checks the regex policy over
private password bytes and binds the password to a Poseidon hash output.

> Research prototype. Not audited for production use.

## Requirements

- Rust toolchain from `rust-toolchain.toml`
- Node.js and npm
- `circom`
- A `zk-regex` compiler that supports `decomposed --shared-input true`

The generator first checks `regex/target/release/zk-regex`. Otherwise set:

```bash
export ZK_REGEX_BIN=/path/to/zk-regex
```

## Install

```bash
npm install
cargo check --workspace
```

## Generate Circuits

Policies are defined in `regex/password_policies_5.txt`. The circuit generator
splits a policy into regex lookahead checks and wraps them with a Poseidon hash
binding over the private password bytes.

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

The shared-input version lets all regex subcircuits reuse one private byte
array. The no-share baseline keeps the original per-subcircuit input handling
and is useful for comparison.

## Build

```bash
cargo build --release --example regex --features parallel
cargo build --release --bin aggregation_server
```

## Run One Experiment

The checked-in scripts run Regex 1 with either good or bad witnesses. Set
`SKIP_AGGREGATION=1` when you only want proof generation.

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

Use this for a quick local sanity check before a longer run.

```bash
node regex/build_lookahead_circuits.js regex/smoke_policy.txt fixtures/password_policies_5_ascii \
  --compile \
  --no-shared-input \
  --dot ascii
cargo build --release --example regex --features parallel
cargo build --release --bin aggregation_server
NUM_TASKS=2 AGGREGATION_REPEATS=1 SKIP_BUILD=1 ./scripts/regex_1_good.zsh
```

## Acknowledgements

ZK-PSE builds on several open-source projects:

* [zk-regex](https://github.com/zkemail/zk-regex) provides the basis for compiling regular expressions into Circom circuits. The regex circuit-generation components included in this repository are adapted and modified from zk-regex to support the shared-input optimization used by ZK-PSE.
* [zk-SaaS](https://github.com/tangle-network/zk-SaaS) provides components that we adapt for MPC-based distributed Groth16 proof generation.
* [snarkpack](https://github.com/nikkolasg/snarkpack) provides components that we adapt for proof aggregation and batch verification.

We thank the authors and contributors of these projects for making their implementations publicly available.

## License

The original ZK-PSE implementation is released under the MIT License.

Portions of the regex circuit-generation code are derived from
[zk-regex](https://github.com/zkemail/zk-regex) and remain subject to the
GNU General Public License v3.0 (GPL-3.0).

Other third-party components remain subject to their respective licenses.
Please refer to the corresponding source files and upstream repositories for details.
