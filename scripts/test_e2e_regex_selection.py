"""Protect selected-only benchmark runs and their resume configuration."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'scripts/run_e2e_regex1_5.zsh'


class RegexSelection(unittest.TestCase):
    def setUp(self):
        fixtures = tempfile.TemporaryDirectory()
        self.addCleanup(fixtures.cleanup)
        circuits = Path(fixtures.name)
        for regex in range(1, 6):
            build = circuits / f'regex_{regex}/build'
            (build / f'GeneratedRegex{regex}_js').mkdir(parents=True)
            (build / f'GeneratedRegex{regex}.r1cs').touch()
            (build / f'GeneratedRegex{regex}_js/GeneratedRegex{regex}.wasm').touch()
        patcher = patch.dict(os.environ, CIRCUIT_SET_DIR=str(circuits),
                             PROOF_BIN='/bin/true', AGGREGATION_BIN='/bin/true')
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_driver(self, root, selection, dry=True):
        env = dict(os.environ, REGEX_IDS=selection, REPEATS='5', NUM_TASKS='64',
                   SKIP_BUILD='1', DRY_RUN='1' if dry else '0',
                   RAYON_NUM_THREADS='1', AGGREGATION_RAYON_NUM_THREADS='12')
        return subprocess.run(['bash', str(DRIVER), str(root)], env=env,
                              text=True, capture_output=True, timeout=15)

    def test_dry_run_selects_only_two_regexes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'run'
            result = self.run_driver(root, '1 2')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('2 regexes x 2 cases x 5 rounds x 64 proofs', result.stdout)
            self.assertFalse(root.exists())

    def test_rejects_invalid_or_duplicate_selection_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            for selection in ('', '1 1', '0', '6', '1 2;3'):
                with self.subTest(selection=selection):
                    root = Path(directory) / 'run'
                    result = self.run_driver(root, selection)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertFalse(root.exists())

    def test_resume_skips_exactly_selected_cases_and_records_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for regex in (1, 2):
                for case in ('good', 'bad'):
                    for round_id in range(1, 6):
                        folder = root / f'regex{regex}_{case}_round{round_id}'
                        folder.mkdir()
                        (folder / 'e2e_ms').write_text('1000\n')
            # A forbidden proof binary makes accidental Regex 3--5 execution
            # fail immediately, without doing any expensive cryptography.
            forbidden = root / 'forbidden-proof'
            forbidden.write_text('#!/usr/bin/env bash\nexit 99\n')
            forbidden.chmod(0o755)
            env = dict(os.environ, PROOF_BIN=str(forbidden))
            with patch.dict(os.environ, env):
                result = self.run_driver(root, '1 2', dry=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.count('Skipping completed Regex'), 20)
            self.assertFalse(any(root.glob('regex[345]_*')))
            self.assertIn('REGEX_IDS=1,2', (root / 'config.txt').read_text())
            self.assertEqual(len((root / 'e2e_raw.csv').read_text().splitlines()), 21)
            # A changed selection must fail before starting any proof.
            result = self.run_driver(root, '1', dry=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('configuration or input files changed', result.stderr)


if __name__ == '__main__':
    unittest.main()
