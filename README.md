# ZK-PSE

This repository contains the implementation of ZK-PSE for privacy-preserving
password policy evaluation.

> This implementation is a research prototype and has not undergone a rigorous
> security audit. It is not intended for production use.

## Requirements

Linux, Node.js 18 with npm, Circom 2.1.5, and the Rust toolchain specified
in [`rust-toolchain.toml`](rust-toolchain.toml). The patched regex compiler
and dependency lock files are included.

## Quick start

First, install the dependencies, build the programs, and generate the
circuits. Run these commands from the repository root:

```bash
npm ci
npm run build
npm run circuits
```

These commands build the required programs and generate the password policy circuits.

Once preparation is complete, run the example:

```bash
bash scripts/run_example.sh
```

## Library tests

```bash
cargo test --locked --release --workspace --lib --features parallel
```

## Acknowledgements

ZK-PSE builds on several open-source projects:

* [zk-regex](https://github.com/zkemail/zk-regex)
* [zk-SaaS](https://github.com/tangle-network/zk-SaaS)
* [snarkpack](https://github.com/nikkolasg/snarkpack)

We thank the authors and contributors of these projects for making their implementations publicly available.

## License

The original ZK-PSE implementation is released under the MIT License.

Portions of the regex circuit-generation code are derived from
[zk-regex](https://github.com/zkemail/zk-regex) and remain subject to the
GNU General Public License v3.0 (GPL-3.0).

Other third-party components remain subject to their respective licenses.
Please refer to the corresponding source files and upstream repositories for details.
