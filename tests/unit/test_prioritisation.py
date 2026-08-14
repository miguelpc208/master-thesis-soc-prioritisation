import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from thesis_pipeline.config import load_scenario
from thesis_pipeline.prioritisation.strategies import CvssStrategy, ThreatIntelStrategy
from thesis_pipeline.quality.temporal import LookAheadError
from thesis_pipeline.synthetic_org import generate_dataset

ROOT = Path(__file__).resolve().parents[2]


class PrioritisationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = load_scenario(ROOT / "configs/scenarios/smoke.yaml")
        self.dataset = generate_dataset(self.scenario)

    def test_e1_is_cvss_descending_with_stable_tie_break(self) -> None:
        decisions = CvssStrategy().rank(self.dataset.findings, self.scenario.start_time_utc)
        by_id = {item.finding_id: item for item in self.dataset.findings}
        ordered = [by_id[item.finding_id] for item in decisions]
        expected = sorted(ordered, key=lambda item: (-item.cvss, item.finding_id))
        self.assertEqual(ordered, expected)

    def test_e2_places_all_kev_before_non_kev(self) -> None:
        decisions = ThreatIntelStrategy().rank(self.dataset.findings, self.scenario.start_time_utc)
        by_id = {item.finding_id: item for item in self.dataset.findings}
        kev_sequence = [by_id[item.finding_id].kev for item in decisions]
        first_false = kev_sequence.index(False) if False in kev_sequence else len(kev_sequence)
        self.assertTrue(all(kev_sequence[:first_false]))
        self.assertTrue(not any(kev_sequence[first_false:]))

    def test_future_evidence_is_rejected(self) -> None:
        finding = replace(
            self.dataset.findings[0],
            epss_observed_at=self.scenario.start_time_utc + timedelta(days=1),
        )
        with self.assertRaises(LookAheadError):
            ThreatIntelStrategy().rank([finding], self.scenario.start_time_utc)


if __name__ == "__main__":
    unittest.main()
