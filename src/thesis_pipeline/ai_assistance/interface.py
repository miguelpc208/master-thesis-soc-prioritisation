from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class AiRecommendation:
    summary: str
    evidence_references: tuple[str, ...]
    uncertainty_note: str


class AiAssistant(ABC):
    @abstractmethod
    def recommend(self, evidence: dict[str, object]) -> AiRecommendation:
        raise NotImplementedError


class DisabledAiAssistant(AiAssistant):
    """Deterministic fallback that cannot introduce unverified facts."""

    def recommend(self, evidence: dict[str, object]) -> AiRecommendation:
        references = tuple(sorted(str(key) for key in evidence))
        return AiRecommendation(
            summary="AI assistance disabled; human analyst reviews structured evidence.",
            evidence_references=references,
            uncertainty_note="No model output was generated.",
        )
