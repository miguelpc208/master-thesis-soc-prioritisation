import json
import tempfile
import unittest
from pathlib import Path

from thesis_pipeline.run import run_experiment

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "configs/scenarios/smoke.yaml"
E1 = ROOT / "configs/experiments/e1_cvss.yaml"
E2 = ROOT / "configs/experiments/e2_threat_intel.yaml"


class SmokeRunTests(unittest.TestCase):
    def test_e1_e2_share_inputs_and_emit_complete_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            e1_path = run_experiment(E1, SCENARIO, directory, ["test-e1"])
            e2_path = run_experiment(E2, SCENARIO, directory, ["test-e2"])
            required = {
                "manifest.json",
                "metrics.json",
                "metrics.csv",
                "events.csv",
                "logs.jsonl",
                "validation_summary.json",
                "README.md",
            }
            self.assertEqual(required, {path.name for path in e1_path.iterdir()})
            first_manifest = json.loads((e1_path / "manifest.json").read_text())
            second_manifest = json.loads((e2_path / "manifest.json").read_text())
            self.assertEqual(
                first_manifest["inputs"]["fingerprint_sha256"],
                second_manifest["inputs"]["fingerprint_sha256"],
            )
            self.assertEqual(
                first_manifest["research_status"], "engineering_smoke_not_dissertation_result"
            )
            validation = json.loads((e2_path / "validation_summary.json").read_text())
            self.assertEqual(validation["status"], "passed")
            self.assertTrue(validation["look_ahead_guard_applied"])

    def test_fixed_seed_repeats_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = run_experiment(E1, SCENARIO, directory, ["repeat-1"])
            second = run_experiment(E1, SCENARIO, directory, ["repeat-2"])
            self.assertEqual(
                json.loads((first / "metrics.json").read_text()),
                json.loads((second / "metrics.json").read_text()),
            )


if __name__ == "__main__":
    unittest.main()
