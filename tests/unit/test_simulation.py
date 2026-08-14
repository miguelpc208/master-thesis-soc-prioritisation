import unittest
from itertools import pairwise
from pathlib import Path

from thesis_pipeline.config import load_scenario
from thesis_pipeline.prioritisation.strategies import CvssStrategy
from thesis_pipeline.simulation import simulate_workflow
from thesis_pipeline.synthetic_org import generate_dataset

ROOT = Path(__file__).resolve().parents[2]


class SimulationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
        self.dataset = generate_dataset(self.scenario)
        self.result = simulate_workflow(self.dataset.findings, self.scenario, CvssStrategy())

    def test_correlation_reduces_volume(self) -> None:
        self.assertLess(self.result.correlated_case_count, self.result.raw_finding_count)

    def test_timestamps_never_go_backwards(self) -> None:
        for record in self.result.records:
            lifecycle = record.lifecycle()
            self.assertTrue(all(right >= left for left, right in pairwise(lifecycle)))

    def test_finite_capacity_creates_queueing(self) -> None:
        waits = [record.triage_started - record.assigned for record in self.result.records]
        self.assertTrue(any(wait.total_seconds() > 0 for wait in waits))


if __name__ == "__main__":
    unittest.main()
