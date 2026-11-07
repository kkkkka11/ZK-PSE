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

This repository contains the core implementation, step-by-step commands,
and a minimal runnable example. The experiments simulate the MPC parties
within one process on a single machine, with messages exchanged over
local channels. Their
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
| [`scripts/run_example.sh`](scripts/run_example.sh) | Minimal proving, aggregation, and verification example |

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

## Run a small Groth16 benchmark

Run both Groth16 configurations for Regex 1 with one input per scenario:

```bash
./target/release/examples/password_policy_arkworks_benchmark \
  --regex-id 1 --max-tasks 1 --repeats 1
```

Results are written to `benchmark_results/g16_baselines/`.

## Generate, aggregate, and verify proofs

The following commands demonstrate Regex 1 with two matching inputs and
16 simulated MPC parties. Run them after building the programs and
generating the circuits above.

### 1. Create a fresh working directory

Start from the repository root. Each example uses a separate directory
so its proof files and cached keys stay together.

```bash
PROJECT_ROOT="$PWD"
mkdir -p "$PROJECT_ROOT/experiments"
RUN_DIR="$(mktemp -d "$PROJECT_ROOT/experiments/regex1_manual.XXXXXX")"
mkdir -p "$RUN_DIR/logs/metrics" "$RUN_DIR/proof_data/agg"
cd "$RUN_DIR"
```

### 2. Generate and verify two individual proofs

Run the prover once for each of the two inputs:

```bash
for task_id in 0 1; do
  RAYON_NUM_THREADS=1 "$PROJECT_ROOT/target/release/examples/regex" \
    0 "$task_id" "$PROJECT_ROOT/network-address/16" 2 2 32768 \
    "$PROJECT_ROOT/fixtures/password_policies_5_ascii/regex_1/build/GeneratedRegex1.r1cs" \
    "$PROJECT_ROOT/fixtures/regex/witness-good/party${task_id}.json" 1 16
done
```

The arguments specify the task ID, MPC configuration, circuit, input,
expected policy result (`1` for a match), and number of parties.
Individual proof verification is performed by the prover program.
Both proofs use the same circuit and cached proving/verification keys.
Sample JSON inputs provide the password and salt through the `password`
and `k` fields.

### 3. Aggregate and verify the batch

The final argument specifies the expected number of proof files:

```bash
RAYON_NUM_THREADS=12 "$PROJECT_ROOT/target/release/aggregation_server" \
  ./proof_data ./proof_data/verification_key.bin 2
cd "$PROJECT_ROOT"
```

The aggregator checks the individual proofs, combines them, and verifies
the aggregate proof. Proofs and aggregate outputs are under
`$RUN_DIR/proof_data/`; per-task and aggregation metrics are under
`$RUN_DIR/logs/metrics/`. The two thread settings control the Rayon pools
used during proving and aggregation.

Client preparation, offline preprocessing, and server online computation
have separate timers. Online computation runs from input shares and
offline materials being ready through construction of the complete proof.
QAP evaluation and sharing are counted in client preparation.

### Minimal example shortcut

From any working directory, invoke the example by its path. From the
repository root:

```bash
bash scripts/run_example.sh
```

This performs the same two-proof workflow in a fresh directory and prints
the location of its proof files, metrics, and logs. The example demonstrates
the basic workflow; it does not automate the full paper evaluation.

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
