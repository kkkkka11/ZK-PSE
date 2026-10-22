# ZK-PSE

ZK-PSE is a privacy-preserving framework for zero-knowledge password policy evaluation. It enables a user to prove that a private password satisfies a public password policy without revealing the password itself.

ZK-PSE combines several zero-knowledge and secure computation techniques. Password policies expressed as regular expressions are compiled into Circom circuits based on zk-regex. The resulting circuits use Groth16 to generate zero-knowledge proofs, while Poseidon hash commitments bind proofs to the corresponding private passwords. To reduce the computation required on resource-constrained clients, ZK-PSE incorporates MPC-based distributed proving adapted from zk-SaaS. Multiple Groth16 proofs can further be aggregated using SnarkPack for efficient batch verification.

> Research prototype. Not audited for production use.

## Requirements

- Rust toolchain from `rust-toolchain.toml`
- Node.js and npm (tested with Node.js 18.19.1)
- `circom` 2.1.5
- The modified `zk-regex` compiler included in [`regex/zk-regex-compiler-v2`](regex/zk-regex-compiler-v2)

The compiler is based on upstream `zkemail/zk-regex` version `2.3.2`, commit
`4fb1bda1af71123f57f4877c29ebcb9004266fd8`, with a local patch for multiple DFA
accept states. Its source and build instructions are included in this repository.
`--shared-input` is implemented by `regex/build_lookahead_circuits.js`, which
converts the compiler's Circom output; it is not a compiler CLI option.

The Rust build was tested with `rustc 1.89.0-nightly (59aa1e873 2025-06-03)`.
The checked-in Cargo and npm lock files pin dependencies.

## Install

```bash
npm ci
cargo build --locked --release -p zk-regex-compiler --bin zk-regex \
  --manifest-path regex/zk-regex-compiler-v2/Cargo.toml
cargo check --locked --workspace
```

## Generate Circuits

Policies are defined in `regex/password_policies_5.txt`. The circuit generator
splits a policy into regex lookahead checks and wraps them with a Poseidon hash
binding over the private password bytes and the full 20-byte salt.

Shared-input optimized circuits:

```bash
node regex/build_lookahead_circuits.js regex/password_policies_5.txt fixtures/password_policies_5_ascii \
  --compile \
  --shared-input true \
  --dot ascii
```

No-share baseline circuits:

```bash
node regex/build_lookahead_circuits.js regex/password_policies_5.txt fixtures/password_policies_5_ascii_noshare \
  --compile \
  --shared-input false \
  --gen-substrs \
  --dot ascii
```

`G16-SI` uses shared input checks and disables substring/reveal helper logic.
`G16-Base` uses separate input checks in each DFA and enables substring/reveal
helpers (`--gen-substrs`). Both use the same patched compiler, policies, and
Poseidon password/salt commitment. This comparison includes both optimizations.

## G16-SI / G16-Base Comparison

After generating both circuit sets above, run the single-prover Groth16 benchmark:

```bash
cargo build --locked --release --example password_policy_arkworks_benchmark --features parallel
RAYON_NUM_THREADS=1 ./target/release/examples/password_policy_arkworks_benchmark \
  --variant all --max-tasks 64 --repeats 5 --setup-repeats 5 \
  --out benchmark_results/g16_baselines
```

This evaluates all five policies with the checked-in good and bad witnesses.
The output contains `setup_raw.csv`, `proof_raw.csv`, and `summary.csv` with
constraint counts, setup/proving/verification times, compressed proof sizes,
and success/failure counts. Setup and witness generation are outside the proof
timer. Use `--regex-id`, `--variant`, or `--help` to select a smaller run.
Timing results depend on hardware and thread settings.

## Build

```bash
cargo build --locked --release --example regex --features parallel
cargo build --locked --release --bin aggregation_server
```

## Run One Experiment

The existing scripts run Regex 1 through witness generation, MPC proving,
individual verification, proof aggregation, and aggregate verification. MPC
parties are simulated within one process using an in-memory network. The example
below uses `n=16`, packing parameter `l=2`, and threshold `t=2`.
Set `SKIP_AGGREGATION=1` when you only want proof generation.

Witnesses are in `fixtures/regex/witness-good` and `witness-bad`; `k` is a
40-character hexadecimal salt. Good/bad runs prove policy outputs 1/0 respectively.
Task and aggregation metrics are written under `logs/metrics/`; each run also
archives its logs and proofs under `logs_1_good/` / `proof_data_1_good/` (or `1_bad`).

Proof only:

```bash
SKIP_BUILD=1 SKIP_AGGREGATION=1 NUM_TASKS=64 \
N_PARAM=16 L_PARAM=2 T_PARAM=2 RAYON_NUM_THREADS=1 AGGREGATION_RAYON_NUM_THREADS=2 \
./scripts/regex_1_good.zsh
```

Proof plus aggregation:

```bash
SKIP_BUILD=1 NUM_TASKS=64 AGGREGATION_REPEATS=50 \
N_PARAM=16 L_PARAM=2 T_PARAM=2 RAYON_NUM_THREADS=1 AGGREGATION_RAYON_NUM_THREADS=2 \
./scripts/regex_1_good.zsh
```

Bad witnesses:

```bash
SKIP_BUILD=1 NUM_TASKS=64 \
N_PARAM=16 L_PARAM=2 T_PARAM=2 RAYON_NUM_THREADS=1 AGGREGATION_RAYON_NUM_THREADS=2 \
./scripts/regex_1_bad.zsh
```

## Smoke Test

Use this for a quick local sanity check before a longer run.

```bash
node regex/build_lookahead_circuits.js regex/smoke_policy.txt fixtures/smoke_policy \
  --compile \
  --no-shared-input \
  --dot ascii
cargo build --locked --release --example regex --features parallel
cargo build --locked --release --bin aggregation_server
CIRCUIT_SET_DIR=./fixtures/smoke_policy NUM_TASKS=2 AGGREGATION_REPEATS=1 \
SKIP_BUILD=1 RAYON_NUM_THREADS=1 AGGREGATION_RAYON_NUM_THREADS=2 ./scripts/regex_1_good.zsh
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
