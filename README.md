# ZK-PSE

This repository contains the implementation of ZK-PSE for privacy-preserving
password policy evaluation. It combines regex circuits, MPC-based delegated
Groth16 proving, and proof aggregation for batch verification.

## Requirements

Linux, Node.js 18 with npm, Circom 2.1.5, and the Rust toolchain specified
in [`rust-toolchain.toml`](rust-toolchain.toml). The patched regex compiler
and dependency lock files are included.

## Quick start

The example demonstrates the ZK-PSE proving workflow using Regex 1 and
two matching password inputs. The 16 proving parties run within a single
process and exchange data over local channels. The sample inputs are
provided in `fixtures/regex/witness-good/`, and the five password policies
are defined in `regex/password_policies_5.txt`.

First, install the dependencies, build the programs, and generate the
circuits. Run these commands from the repository root:

```bash
npm ci
npm run build
npm run circuits
```

The build command compiles the patched regex compiler, the Groth16
benchmark, the delegated prover, and the aggregation program. Circuit
generation produces both G16-Enhanced and G16-Base configurations for
all five policies. The ZK-PSE example uses the G16-Enhanced circuit.

Once preparation is complete, run the example:

```bash
bash scripts/run_example.sh
```

For each input, the client prepares the witness and the secret shares
of the data required for proving, including the QAP evaluations. The
proving parties use these shares and the offline preprocessing materials
to generate a complete Groth16 proof. The program checks both proofs,
combines them into one aggregate proof, and verifies the aggregate result.

The commands build the implementation, generate both circuit configurations
for the five password policies, and run a two-proof example for Regex 1.
The output directory contains individual and aggregate proofs, execution
logs, and CSV metrics for client preparation, offline preprocessing,
online computation, aggregation, verification, peak memory, and data
exchanged over local channels. Its location is printed on completion.

## Library tests

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
