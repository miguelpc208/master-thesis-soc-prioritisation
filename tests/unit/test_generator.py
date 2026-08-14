import unittest
from pathlib import Path

from thesis_pipeline.config import load_scenario
from thesis_pipeline.synthetic_org import generate_dataset

ROOT = Path(__file__).resolve().parents[2]


class GeneratorTests(unittest.TestCase):
    def test_fixed_seed_is_repeatable(self) -> None:
        scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
        first = generate_dataset(scenario)
        second = generate_dataset(scenario)
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.findings, second.findings)

    def test_fixture_uses_only_synthetic_cve_identifiers(self) -> None:
        scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
        dataset = generate_dataset(scenario)
        self.assertTrue(all(item.cve_id.startswith("CVE-SYNTH-") for item in dataset.findings))


if __name__ == "__main__":
    unittest.main()
