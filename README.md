# ZK-PSE

ZK-PSE is a research prototype for privacy-preserving password policy
evaluation. It lets a password owner prove whether a private password
satisfies a public policy without revealing the password. Policies are
expressed as regular expressions and compiled into arithmetic circuits.
Poseidon commitments bind the private password and salt to the public
statement checked by the circuit.

The implementation combines Groth16 proofs, MPC-based delegated proving,
and SnarkPack proof aggregation. The client prepares the witness and
related data and their secret shares. The proving parties jointly
produce a proof, and an aggregator combines multiple proofs for batch
verification. The included policies cover character composition, length
requirements, date-pattern filtering, and sequential-character restrictions.

This repository contains the core implementation and the main experiment
runners. The experiments simulate the MPC parties within one process on
a single machine, with messages exchanged over local channels. Their
runtime and communication measurements characterize this local setup.
The prototype has not been audited for production use.

## Workflow

1. **Compile a policy.** The regex generator constructs a Circom circuit
   for policy evaluation and the Poseidon commitment check.
2. **Prepare offline materials.** The implementation prepares reusable
   CRS shares and fresh random shares and masks for proving.
3. **Delegate proof generation.** The client generates the witness,
   computes the required QAP evaluations, and prepares secret shares of
   the witness-dependent data. The proving parties use these shares and
   the offline materials to compute and reconstruct a Groth16 proof.
4. **Aggregate and verify.** The aggregator combines a batch of proofs
   into an aggregate proof, which is checked together with the public
   statements.

## Repository structure

| Path | Contents |
| --- | --- |
| [`regex/`](regex/) | Five password policies, circuit generator, and patched zk-regex compiler |
| [`groth16/`](groth16/) | Delegated proving, single-prover benchmarks, and aggregation executable |
| [`secret-sharing/`](secret-sharing/) | Packed secret-sharing operations |
| [`dist-primitives/`](dist-primitives/) | Distributed polynomial and multi-scalar multiplication operations |
| [`mpc-net/`](mpc-net/) | Communication interfaces and local simulation support |
| [`snarkpack/`](snarkpack/) | Proof aggregation and aggregate verification |
| [`fixtures/`](fixtures/) | Sample password inputs and compiled circuits for library tests |
| [`scripts/`](scripts/) | Two main experiment runners |

## Requirements

Linux, the Rust toolchain in [`rust-toolchain.toml`](rust-toolchain.toml),
Node.js 18 with npm, and Circom 2.1.5. The patched regex compiler is
included in [`regex/zk-regex-compiler-v2/`](regex/zk-regex-compiler-v2/).
Cargo and npm lock files are included to pin dependency versions.

## Build and generate circuits

Run the following commands from the repository root:

```bash
npm ci
cargo build --locked --release -p zk-regex-compiler --bin zk-regex \
  --manifest-path regex/zk-regex-compiler-v2/Cargo.toml
cargo build --locked --release --example regex \
  --example password_policy_arkworks_benchmark --bin aggregation_server --features parallel
npm run generate:circuits
npm run generate:circuits:noshare
```

Policies are defined in [`regex/password_policies_5.txt`](regex/password_policies_5.txt).
The two generation commands produce the circuit sets used by G16-Enhanced
and G16-Base, respectively. G16-Enhanced shares input checks across DFAs
and omits substring/reveal helpers. G16-Base uses separate input checks
and includes these helpers. Both configurations use the same policies
and password commitment.

## Run experiments

### Single-prover Groth16 baselines

Run G16-Base and G16-Enhanced for all five policies, with 64 inputs per
scenario and five proof-generation repetitions per input:

```bash
REPEATS=5 NUM_TASKS=64 RAYON_NUM_THREADS=12 SKIP_CIRCUIT_BUILD=1 \
  bash scripts/run_g16_baselines.zsh
```

The benchmark records witness generation, proof generation, verification,
and setup separately. Its total proving time adds witness generation
and proof generation. Results are written to `benchmark_results/g16_baselines/`
as `proof_raw.csv`, `setup_raw.csv`, and `summary.csv`.

### ZK-PSE delegated proving and aggregation

Run Regex 1--5 for match and non-match scenarios, with five rounds of
64 sequential proofs per scenario. Each batch is then aggregated and
verified:

```bash
REGEX_IDS='1 2 3 4 5' REPEATS=5 NUM_TASKS=64 \
  RAYON_NUM_THREADS=1 AGGREGATION_RAYON_NUM_THREADS=12 \
  bash scripts/run_e2e_regex1_5.zsh experiments/review_run
```

The default MPC configuration uses 16 simulated parties. The two thread
settings control the Rayon pools used during proving and aggregation.
Sample inputs are in [`fixtures/regex/`](fixtures/regex/), with 64 inputs
in each of `witness-good/` and `witness-bad/`. Each input supplies a
password and a salt through the `password` and `k` fields.

The selected experiment directory contains proof files, per-task and
aggregation metrics, logs, and `e2e_raw.csv` / `e2e_summary.csv` batch
wall-clock measurements. Client preparation, offline preprocessing,
and server online computation have separate timers. Online computation
runs from input shares and offline materials being ready through
construction of the complete proof. QAP evaluation and sharing are
counted in client preparation.

## Library tests

Run the library tests in release mode:

```bash
cargo test --locked --release --workspace --lib --features parallel
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
