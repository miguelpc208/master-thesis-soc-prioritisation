from datetime import datetime

from thesis_pipeline.models import Finding


class LookAheadError(ValueError):
    """Raised when a policy can see evidence that did not yet exist."""


def validate_evidence_as_of(finding: Finding, decision_time: datetime) -> None:
    dated_evidence = {
        "EPSS": finding.epss_observed_at,
        "KEV": finding.kev_observed_at,
    }
    for label, observed_at in dated_evidence.items():
        if observed_at > decision_time:
            raise LookAheadError(
                f"{label} evidence for {finding.finding_id} is dated {observed_at.isoformat()}, "
                f"after decision cutoff {decision_time.isoformat()}"
            )
