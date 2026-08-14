from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import datetime

from thesis_pipeline.models import Finding, PriorityDecision
from thesis_pipeline.quality.temporal import validate_evidence_as_of


class PrioritisationStrategy(ABC):
    policy_name: str

    @abstractmethod
    def rank(self, findings: Iterable[Finding], decision_time: datetime) -> list[PriorityDecision]:
        raise NotImplementedError


class CvssStrategy(PrioritisationStrategy):
    policy_name = "cvss"

    def rank(self, findings: Iterable[Finding], decision_time: datetime) -> list[PriorityDecision]:
        del decision_time
        ordered = sorted(findings, key=lambda item: (-item.cvss, item.finding_id))
        return [
            PriorityDecision(
                finding_id=finding.finding_id,
                rank=index,
                policy=self.policy_name,
                score_components={"cvss": finding.cvss},
                explanation="CVSS descending; finding ID ascending tie-break.",
            )
            for index, finding in enumerate(ordered, start=1)
        ]


class ThreatIntelStrategy(PrioritisationStrategy):
    policy_name = "threat_intel"

    def rank(self, findings: Iterable[Finding], decision_time: datetime) -> list[PriorityDecision]:
        items = list(findings)
        for finding in items:
            validate_evidence_as_of(finding, decision_time)
        ordered = sorted(
            items,
            key=lambda item: (-int(item.kev), -item.epss_probability, -item.cvss, item.finding_id),
        )
        return [
            PriorityDecision(
                finding_id=finding.finding_id,
                rank=index,
                policy=self.policy_name,
                score_components={
                    "kev": finding.kev,
                    "epss_probability": finding.epss_probability,
                    "cvss": finding.cvss,
                },
                explanation="KEV first, then EPSS probability, then CVSS; finding ID tie-break.",
            )
            for index, finding in enumerate(ordered, start=1)
        ]


def build_strategy(policy: str) -> PrioritisationStrategy:
    strategies: dict[str, type[PrioritisationStrategy]] = {
        "cvss": CvssStrategy,
        "threat_intel": ThreatIntelStrategy,
    }
    try:
        return strategies[policy]()
    except KeyError as exc:
        raise ValueError(f"Policy '{policy}' is scaffolded but not implemented in the MVP") from exc
