# Benchmark and local MPC measurement boundaries

Raw durations are milliseconds unless the field or column explicitly says
seconds. Aggregation and verification values apply to the actual batch size.
The local MPC simulation uses 16 parties within one process; its measurements
are not measurements of a cross-machine deployment.

## Single-prover G16-Base and G16-Enhanced

Client Time is `total_proving_time_ms = witness_generation_ms + prove_time_ms`.
The witness interval covers input preparation, witness generation, and public
input extraction. `prove_time_ms` remains the pure Groth16 proving call.
Setup, loading the witness JSON, verification, and proof serialization are
measured separately or outside this total. Summary averages use successful
proofs only; failures retain their error status and must not be counted as
zero-duration successful proofs. Historical CSVs without witness timing need
to be rerun; missing witness times cannot be recovered from proving times.

After generating both circuit sets as described in the root README:

```bash
cargo build --locked --release --example password_policy_arkworks_benchmark --features parallel
RAYON_NUM_THREADS=12 ./target/release/examples/password_policy_arkworks_benchmark \
  --variant all --regex-id 1 --max-tasks 64 --repeats 5 --setup-repeats 1 \
  --out benchmark_results/regex1_witness_and_prove
RAYON_NUM_THREADS=12 ./target/release/examples/password_policy_arkworks_benchmark \
  --variant all --regex-id 3 --max-tasks 64 --repeats 5 --setup-repeats 1 \
  --out benchmark_results/regex3_witness_and_prove
```

The thread count is explicit: these single-prover comparison runs use 12 Rayon
threads. The general-purpose `scripts/run_g16_baselines.zsh` can run all five
policies and accepts `RAYON_NUM_THREADS`, `NUM_TASKS`, and `REPEATS` overrides.

## ZK-PSE timing scope version 2

Current task records contain `timing_scope_version=2`.

| Field | Operations covered |
|---|---|
| `client_total_time_ms` | Witness generation, QAP evaluation, assignment sharing, QAP sharing, and share-size accounting. |
| `qap_sharing_ms` | Witness-dependent QAP share generation; already counted once in Client Time. |
| `mpc_preprocessing_ms` | Direct elapsed offline preparation: random materials, CRS shares, masks, and local channels. QAP sharing has already finished. |
| `mpc_execution_ms` | Full local MPC simulation call, including dispatch, input copies, communication, and waiting; ends before reconstruction. |
| `online_computation_ms` | From all input shares and offline materials being ready through reconstruction, affine conversion, and complete Groth16 proof construction. |
| `mpc_reconstruction_ms` | Reconstruction through the same complete-proof endpoint. This is part of Online Computation. |
| `mpc_total_time_ms` | Legacy slowest-party interval; narrower than the complete server online interval. |

The client total is a sum of measured preparation intervals, not the entire
client process wall time. The legacy name `client_share_serialization_ms`
refers to share-size accounting, not complete serialization or network transfer.
Do not add QAP sharing to Client Time again or subtract it from the version-2
offline field. Online Computation includes the server's reconstruction work;
client preparation, offline preparation, proof checking, encoding/file output,
and aggregation are outside it.

With the `parallel` feature, QAP sharing enters the existing Rayon pool once.
This avoids repeatedly scheduling the small FFT operations from outside the
pool without changing the sharing algorithm.

## Repeated local runs and summaries

After generating the shared-input circuits from the README, run:

```bash
REGEX_IDS='1 2 3 4 5' bash scripts/run_online_computation_5rounds.sh experiments/timing_scope_v2
python3 scripts/summarize_online_computation.py experiments/timing_scope_v2
```

This runs five rounds for each match/non-match scenario, with 64 proofs per
round, 16 MPC parties, packing 2, threshold 2, MPC Rayon=1, and aggregation
Rayon=12. Rayon=1 limits that pool; it does not make the 16-party process use
only one OS thread. The launcher freezes the executables and records their
hashes, parameters, circuit files, and witness files for resume checks.
`REGEX_IDS='1 2'` selects a subset. Build the executables first before using
`DRY_RUN=1`; the dry run validates the selected inputs without starting proofs.

Each successful case/round has `e2e_ms` and `completed_attempt`. The collector
reads only the selected attempt, checks the requested task IDs and complete
proof files, and verifies that QAP sharing is counted exactly once and that
online timing contains execution and reconstruction. Missing, nonfinite, mixed-
scope, or inconsistent measurements are errors. Historical scope-1 client and
offline values are not reinterpreted as scope 2.

`e2e_ms` is the complete sequential batch wall time, including preparation,
proof generation, aggregation/verification, and process/file overhead. The sum
of Client Time, Online Computation, aggregation, and aggregate verification is
an estimate of reported computation with offline materials already ready, not
a direct measurement of that complete wall time. Aggregation and aggregate
verification are counted once per batch; per-proof client/online times are
counted once per proof. An amortized verification value divides a measured
batch verification time by its proof count; it is not individual verification
latency.

## Regression checks

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
bash -n scripts/regex_local_sim_common.zsh scripts/run_g16_baselines.zsh \
  scripts/run_e2e_regex1_5.zsh scripts/run_online_computation_5rounds.sh
cargo check --locked -p groth16 --example regex \
  --example password_policy_arkworks_benchmark --bin aggregation_server --features parallel
```

Python tests create temporary CSVs and mock circuit assets; they do not require
archived experiment data or launch proof generation. Generated experiment
outputs and circuit artifacts are ignored by Git.
