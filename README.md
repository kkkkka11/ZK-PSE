# ZK-PSE

Research prototype for zero-knowledge password policy evaluation using
regex circuits, MPC-based Groth16 proving, and proof aggregation.
The MPC parties are simulated within one process on a single machine.

## Requirements

Linux, the Rust toolchain in `rust-toolchain.toml`, Node.js 18 with npm,
and Circom 2.1.5. The patched regex compiler is included in
`regex/zk-regex-compiler-v2/`.

## Build and generate circuits

```bash
npm ci
cargo build --locked --release -p zk-regex-compiler --bin zk-regex \
  --manifest-path regex/zk-regex-compiler-v2/Cargo.toml
cargo build --locked --release --example regex \
  --example password_policy_arkworks_benchmark --bin aggregation_server --features parallel
npm run generate:circuits
npm run generate:circuits:noshare
```

## Run experiments

G16-Base and G16-Enhanced:

```bash
REPEATS=5 NUM_TASKS=64 RAYON_NUM_THREADS=12 SKIP_CIRCUIT_BUILD=1 \
  bash scripts/run_g16_baselines.zsh
```

ZK-PSE, Regex 1--5, match and non-match, five rounds:

```bash
REGEX_IDS='1 2 3 4 5' REPEATS=5 NUM_TASKS=64 \
  RAYON_NUM_THREADS=1 AGGREGATION_RAYON_NUM_THREADS=12 \
  bash scripts/run_e2e_regex1_5.zsh experiments/review_run
```

Sample inputs are in `fixtures/regex/`. Benchmark CSVs are written to
`benchmark_results/`; MPC logs, proofs, metrics, and batch timings are
written to the selected experiment directory.

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
