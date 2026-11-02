"""Regression checks for client/QAP, offline and full-server-online accounting."""
import csv
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

from summarize_online_computation import collect

ROOT = Path(__file__).resolve().parents[1]


def write_metrics(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as target:
        writer = csv.writer(target, lineterminator='\n')
        writer.writerow(['metric', 'value'])
        writer.writerows(data.items())


def record(task_id=0, scope=2):
    data = dict(task_id=task_id, witness_generation_ms=20, r1cs_to_qap_ms=3,
                witness_secret_sharing_ms=5, client_share_serialization_ms=.25,
                client_total_time_ms=98.25, qap_sharing_ms=70,
                timing_scope_version=scope, mpc_preprocessing_ms=100,
                online_computation_ms=200, mpc_execution_ms=190,
                mpc_reconstruction_ms=10, mpc_total_time_ms=180,
                total_task_time_ms=500, constraint_count=10, proof_size_bytes=128,
                commitment_size_bytes=32, circuit_building_ms=1)
    if scope == 1:
        del data['qap_sharing_ms'], data['timing_scope_version']
        data['client_total_time_ms'] = 28.25
    return data


class TimingScopes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'config.txt').write_text('NUM_TASKS=1 REPEATS=1\n')
        self.paths = []
        for case in ('good', 'bad'):
            folder = self.root / f'regex1_{case}_round1'
            attempt = folder / 'attempt'
            path = attempt / 'logs/metrics/task_0_metrics.csv'
            write_metrics(path, record())
            self.paths.append(path)
            (attempt / 'proof_data').mkdir()
            (attempt / 'proof_data/regex_proof_0.json').write_text('{}')
            (folder / 'e2e_ms').write_text('1000\n')
            (folder / 'completed_attempt').write_text('attempt\n')

    def collect(self):
        return collect(self.root, (1,))

    def test_scope2_client_includes_qap_and_offline_is_direct(self):
        _, cases, summary, _ = self.collect()
        row = summary[0]
        self.assertAlmostEqual(row['mean_client_time_s'], .09825)
        self.assertAlmostEqual(row['mean_qap_sharing_s'], .070)
        self.assertAlmostEqual(row['mean_offline_preprocessing_s'], .100)
        self.assertAlmostEqual(row['mean_online_computation_s'], .200)
        self.assertEqual(row['timing_scope_version'], 2)
        self.assertEqual(len(cases), 2)

    def test_legacy_is_not_reinterpreted_as_new_client_or_offline(self):
        for p in self.paths:
            write_metrics(p, record(scope=1))
        _, _, summary, _ = self.collect()
        self.assertIsNone(summary[0]['mean_client_time_s'])
        self.assertIsNone(summary[0]['mean_offline_preprocessing_s'])
        self.assertAlmostEqual(summary[0]['mean_online_computation_s'], .2)

    def test_mixed_versions_rejected(self):
        write_metrics(self.paths[0], record(scope=1))
        with self.assertRaisesRegex(ValueError, 'Mixed timing scopes'):
            self.collect()

    def test_client_omitting_qap_rejected(self):
        d = record()
        d['client_total_time_ms'] -= d['qap_sharing_ms']
        write_metrics(self.paths[0], d)
        with self.assertRaisesRegex(ValueError, 'exactly once'):
            self.collect()

    def test_client_double_counting_qap_rejected(self):
        d = record()
        d['client_total_time_ms'] += d['qap_sharing_ms']
        write_metrics(self.paths[0], d)
        with self.assertRaisesRegex(ValueError, 'exactly once'):
            self.collect()

    def test_client_accounting_uses_absolute_tolerance(self):
        d = record()
        d['witness_generation_ms'] = 1e6
        d['client_total_time_ms'] = 1e6 + 78.25 + .0002
        d['total_task_time_ms'] = 2e6
        write_metrics(self.paths[0], d)
        with self.assertRaisesRegex(ValueError, 'exactly once'):
            self.collect()

    def test_new_qap_field_without_version_rejected(self):
        d = record()
        del d['timing_scope_version']
        for p in self.paths:
            write_metrics(p, d)
        with self.assertRaisesRegex(ValueError, 'scope'):
            self.collect()

    def test_missing_qap_rejected(self):
        d = record()
        del d['qap_sharing_ms']
        write_metrics(self.paths[0], d)
        with self.assertRaises((ValueError, KeyError)):
            self.collect()

    def test_nonfinite_qap_rejected(self):
        d = record()
        d['qap_sharing_ms'] = 'nan'
        write_metrics(self.paths[0], d)
        with self.assertRaises(ValueError):
            self.collect()

    def test_online_must_include_reconstruction(self):
        d = record()
        d['online_computation_ms'] = 195
        write_metrics(self.paths[0], d)
        with self.assertRaisesRegex(ValueError, 'containment'):
            self.collect()

    def test_combined_intervals_cannot_exceed_task(self):
        d = record()
        d['total_task_time_ms'] = 300
        write_metrics(self.paths[0], d)
        with self.assertRaisesRegex(ValueError, 'exceed'):
            self.collect()

    def shell_export(self, records, function=None):
        script = (ROOT / 'scripts/regex_local_sim_common.zsh').read_text()
        names = ['log_status', 'get_metric_from_csv', 'add_decimal', 'average_decimal',
                 'generate_performance_summary', 'generate_benchmark_csvs']
        functions = [re.search(r'(?ms)^' + name + r'\(\) \{\n.*?^\}\n', script)[0]
                     for name in names]
        metrics = self.root / 'export'
        for i, data in enumerate(records):
            write_metrics(metrics / f'task_{i}_metrics.csv', data)
        body = ('set -euo pipefail\n' + '\n'.join(functions) + '\n' +
                f'METRICS_DIR={shlex.quote(str(metrics))}\n' +
                f'NUM_TASKS={len(records)}\n' +
                'LABEL=test\nL_PARAM=2\nT_PARAM=2\nN_PARAM=16\nEXPECTED_MATCH=0\n'
                'SKIP_AGGREGATION=1\nAGGREGATION_REPEATS=0\nWITNESS_FILES=(a b)\n' +
                ((function + (' 1000' if function == 'generate_performance_summary' else '') + '\n')
                 if function else 'generate_performance_summary 1000\ngenerate_benchmark_csvs\n'))
        result = subprocess.run(['bash'], input=body, text=True, capture_output=True)
        return result, metrics

    def test_shell_exports_all_three_scopes_and_qap(self):
        result, metrics = self.shell_export([record(0), record(1)])
        self.assertEqual(result.returncode, 0, result.stderr)
        for filename in ('performance_summary.csv', 'benchmark_summary.csv'):
            d = dict(csv.reader((metrics / filename).read_text().splitlines()))
            self.assertEqual(d['timing_scope_version'], '2')
            self.assertAlmostEqual(float(d['avg_client_time_ms']), 98.25)
            self.assertAlmostEqual(float(d['avg_qap_sharing_ms']), 70)
            self.assertAlmostEqual(float(d['avg_online_computation_ms']), 200)
        raw = list(csv.DictReader((metrics / 'proof_raw.csv').read_text().splitlines()))
        self.assertEqual(list(raw[0])[-2:], ['qap_sharing_ms', 'timing_scope_version'])
        self.assertAlmostEqual(float(raw[0]['mpc_preprocessing_time_ms']), 100)

    def test_shell_legacy_qap_average_is_empty(self):
        result, metrics = self.shell_export([record(0, 1), record(1, 1)])
        self.assertEqual(result.returncode, 0, result.stderr)
        d = dict(csv.reader((metrics / 'benchmark_summary.csv').read_text().splitlines()))
        self.assertEqual(d['timing_scope_version'], '1')
        self.assertEqual(d['avg_qap_sharing_ms'], '')

    def test_both_shell_exporters_reject_mixed_scopes(self):
        for function in ('generate_performance_summary', 'generate_benchmark_csvs'):
            with self.subTest(function=function):
                result, _ = self.shell_export([record(0, 1), record(1)], function)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('mixed timing scopes', result.stderr)

    def test_both_shell_exporters_reject_missing_qap(self):
        d = record(0)
        del d['qap_sharing_ms']
        for function in ('generate_performance_summary', 'generate_benchmark_csvs'):
            with self.subTest(function=function):
                result, _ = self.shell_export([d, record(1)], function)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('missing qap_sharing_ms', result.stderr)





if __name__ == '__main__':
    unittest.main()
