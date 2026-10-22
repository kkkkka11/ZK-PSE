# Patched zk-regex compiler v2

This directory vendors the compiler package from
[`zkemail/zk-regex` tag `2.3.2`](https://github.com/zkemail/zk-regex/tree/2.3.2),
upstream commit `4fb1bda1af71123f57f4877c29ebcb9004266fd8`.
The package version remains `2.3.2`; use the ZK-PSE repository commit to identify
the local patched revision. `Cargo.lock` pins the compiler dependencies.

The local patch keeps the original v2 CLI but changes the Circom backend to support DFA graphs with multiple accept states. Instead of rejecting such DFAs, the generated circuit ORs all accepting states into an `accepted_state[i]` signal at each input position. The ordinary match output and the optional substring/reveal logic both reuse this signal.

Build the compiler before regenerating circuits:

```sh
cargo build --locked --release -p zk-regex-compiler --bin zk-regex --manifest-path regex/zk-regex-compiler-v2/Cargo.toml
```

`regex/build_lookahead_circuits.js` automatically prefers the resulting binary at `regex/zk-regex-compiler-v2/target/release/zk-regex`.

Only `packages/compiler/src/circom.rs` differs from the upstream compiler package.
The workspace is reduced to this package. The upstream root license is retained
in `LICENSE`; the original package metadata is preserved.

`--shared-input` is an option of the ZK-PSE JavaScript generator, not of this
compiler CLI. The generator converts the emitted DFA inputs to a shared interface
and places the input checks in the wrapper circuit. Both G16-Optimized and G16-Base use
this same patched compiler; they differ in the generator options documented in
the root README.
