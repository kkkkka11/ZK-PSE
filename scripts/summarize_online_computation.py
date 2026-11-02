#!/usr/bin/env python3
"""Summarize the shares-ready -> complete-proof timer from completed runs.

Read only the attempts selected by completed_attempt. Missing observations or
legacy timers are errors; they are never substituted or treated as zero.
"""

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import mean

from measurement_csv import metric_blocks, save


def collect(run_root, regex_ids=(1, 2, 3, 4, 5)):
    config_path = run_root / "config.txt"
    config = dict(item.split("=", 1) for item in config_path.read_text().splitlines()[0].split())
    rounds, proofs = int(config["REPEATS"]), int(config["NUM_TASKS"])
    if rounds < 1 or proofs < 1:
        raise ValueError("Invalid run size in config.txt")

    tasks, cases = [], []
    timing_scopes = set()
    for regex in regex_ids:
        for case in ("good", "bad"):
            for round_id in range(1, rounds + 1):
                folder = run_root / f"regex{regex}_{case}_round{round_id}"
                if not (folder / "e2e_ms").is_file():
                    raise ValueError(f"Incomplete run: {folder}")
                selected = Path((folder / "completed_attempt").read_text().strip())
                if not selected.is_absolute():
                    selected = folder / selected
                selected = selected.resolve()
                if selected.parent != folder.resolve():
                    raise ValueError(f"Attempt is outside its case directory: {selected}")
                metrics = selected / "logs/metrics"
                expected_files = {f"task_{i}_metrics.csv" for i in range(proofs)}
                if {p.name for p in metrics.glob("task_*_metrics.csv")} != expected_files:
                    raise ValueError(f"Missing or unexpected task metrics in {metrics}")
                observations = []
                for task_id in range(proofs):
                    path = metrics / f"task_{task_id}_metrics.csv"
                    blocks = metric_blocks(path, "task_id")
                    data = blocks[-1]
                    if int(data["task_id"]) != task_id:
                        raise ValueError(f"Task identity mismatch: {path}")

                    def value(key):
                        result = float(data[key])
                        if not math.isfinite(result) or result < 0:
                            raise ValueError(f"Invalid {key}: {path}")
                        return result

                    online = value("online_computation_ms")
                    execution = value("mpc_execution_ms")
                    reconstruction = value("mpc_reconstruction_ms")
                    party = value("mpc_total_time_ms")
                    if (execution + .001 < party or
                            online + .001 < execution + reconstruction or
                            value("total_task_time_ms") + 1 < online):
                        raise ValueError(f"Inconsistent timer containment: {path}")
                    if not (selected / f"proof_data/regex_proof_{task_id}.json").is_file():
                        raise ValueError(f"Missing proof artifact for {path}")
                    scope = int(data.get("timing_scope_version", "1"))
                    if scope not in (1, 2):
                        raise ValueError(f"Unsupported timing scope {scope}: {path}")
                    if scope == 1 and "qap_sharing_ms" in data:
                        raise ValueError(f"QAP sharing field requires timing scope 2: {path}")
                    timing_scopes.add(scope)
                    if len(timing_scopes) > 1:
                        raise ValueError("Mixed timing scopes: keep old and new experiments separate")
                    client = qap = offline = None
                    if scope == 2:
                        qap = value("qap_sharing_ms")
                        client = value("client_total_time_ms")
                        offline = value("mpc_preprocessing_ms")
                        client_parts = sum(value(k) for k in (
                            "witness_generation_ms", "r1cs_to_qap_ms", "witness_secret_sharing_ms",
                            "client_share_serialization_ms", "qap_sharing_ms"))
                        if not math.isclose(client, client_parts, rel_tol=0, abs_tol=1e-6):
                            raise ValueError(f"Client Time does not include QAP sharing exactly once: {path}")
                        if client + offline + online > value("total_task_time_ms") + 1:
                            raise ValueError(f"Client/offline/online intervals exceed task elapsed time: {path}")
                    observation = dict(regex=regex, case=case, round=round_id, task_id=task_id,
                                       online_computation_ms=online, mpc_execution_ms=execution,
                                       mpc_reconstruction_ms=reconstruction,
                                       party_mpc_elapsed_ms=party, record_count=len(blocks),
                                       source=str(path), timing_scope_version=scope,
                                       client_total_time_ms=client, qap_sharing_ms=qap,
                                       offline_preprocessing_ms=offline)
                    observations.append(observation)
                tasks.extend(observations)
                cases.append(dict(regex=regex, case=case, round=round_id, samples=len(observations),
                                  mean_online_computation_s=mean(t["online_computation_ms"] for t in observations) / 1000,
                                  timing_scope_version=scope,
                                  mean_client_time_s=mean(t["client_total_time_ms"] for t in observations) / 1000 if scope == 2 else None,
                                  mean_qap_sharing_s=mean(t["qap_sharing_ms"] for t in observations) / 1000 if scope == 2 else None,
                                  mean_offline_preprocessing_s=mean(t["offline_preprocessing_ms"] for t in observations) / 1000 if scope == 2 else None))

    summary = []
    for regex in regex_ids:
        match = [r for r in tasks if r["regex"] == regex and r["case"] == "good"]
        nonmatch = [r for r in tasks if r["regex"] == regex and r["case"] == "bad"]
        if len(match) != len(nonmatch) or len(match) != rounds * proofs:
            raise ValueError(f"Incomplete or unbalanced Regex {regex} samples")
        summary.append(dict(
            regex=regex, completed_rounds=rounds, proofs_per_case_round=proofs,
            match_samples=len(match), nonmatch_samples=len(nonmatch), total_samples=len(match) + len(nonmatch),
            mean_online_computation_s=mean((mean(t["online_computation_ms"] for t in match),
                                            mean(t["online_computation_ms"] for t in nonmatch))) / 1000,
            timing_scope_version=scope,
            mean_client_time_s=mean(t["client_total_time_ms"] for t in match + nonmatch) / 1000 if scope == 2 else None,
            mean_qap_sharing_s=mean(t["qap_sharing_ms"] for t in match + nonmatch) / 1000 if scope == 2 else None,
            mean_offline_preprocessing_s=mean(t["offline_preprocessing_ms"] for t in match + nonmatch) / 1000 if scope == 2 else None))
    return tasks, cases, summary, config_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_root", type=Path)
    parser.add_argument("--regex", type=int, choices=range(1, 6), nargs="+",
                        default=[1, 2, 3, 4, 5],
                        help="Extract completed regexes only; partial outputs use a separate filename.")
    args = parser.parse_args()
    root = args.run_root.resolve()
    regex_ids = tuple(sorted(set(args.regex)))
    tasks, cases, summary, config_path = collect(root, regex_ids)
    prefix = "online_computation"
    if regex_ids != (1, 2, 3, 4, 5):
        prefix += "_regex" + "_".join(str(regex) for regex in regex_ids)
    save(root / f"{prefix}_raw.csv", tasks)
    save(root / f"{prefix}_cases.csv", cases)
    save(root / f"{prefix}_summary.csv", summary)
    metadata = dict(
        scope="all witness-dependent shares and offline materials ready -> complete Groth16 Proof",
        metric="online_computation_ms", mean_unit="s/proof", tasks=len(tasks), regex_ids=regex_ids,
        record_selection="last complete record in completed_attempt only",
        config_sha256=hashlib.sha256(config_path.read_bytes()).hexdigest(),
        timing_scope_version=summary[0]["timing_scope_version"],
        client_scope="Version 2 includes QAP sharing; historical version 1 client/offline values are not reinterpreted",
        offline_scope="Version 2 measures input-independent preparation directly; do not subtract QAP sharing again",
        inputs_excluded="witness generation, QAP evaluation, a/ax and QAP sharing, offline preparation",
        outputs_excluded="verification, serialization, file output, aggregation",
        included="local dispatch/copies, MPC computation, local communication/waiting, reconstruction")
    (root / f"{prefix}_metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print("Online Computation: shares ready -> complete proof, seconds per proof")
    for row in summary:
        print(f"Regex {row['regex']}: {row['mean_online_computation_s']:.6f} s "
              f"({row['match_samples']} match + {row['nonmatch_samples']} non-match)")
    print(f"Summary: {root / (prefix + '_summary.csv')}")


if __name__ == "__main__":
    main()
