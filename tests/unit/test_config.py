import tempfile
import unittest
from pathlib import Path

import yaml

from thesis_pipeline.config import ConfigurationError, load_experiment, load_scenario

ROOT = Path(__file__).resolve().parents[2]


class ConfigurationTests(unittest.TestCase):
    def test_smoke_scenario_parses(self) -> None:
        scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
        self.assertEqual(scenario.scenario_id, "smoke")
        self.assertEqual(scenario.findings, 240)

    def test_invalid_duplicate_rate_fails_clearly(self) -> None:
        source = yaml.safe_load((ROOT / "configs/scenarios/smoke.yaml").read_text())
        source["scenario"]["workload"]["duplicate_rate"] = 1.5
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.yaml"
            path.write_text(yaml.safe_dump(source), encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "duplicate_rate"):
                load_scenario(path)

    def test_e3_weights_are_validated(self) -> None:
        experiment = load_experiment(ROOT / "configs/experiments/e3_business_context.yaml")
        self.assertEqual(experiment.policy, "business_context")
        self.assertFalse(experiment.enabled)


if __name__ == "__main__":
    unittest.main()
