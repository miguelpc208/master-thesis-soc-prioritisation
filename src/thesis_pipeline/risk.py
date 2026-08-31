from __future__ import annotations


def calculate_risk_weight(
    *,
    cvss: float,
    asset_criticality: int,
    service_criticality: int,
    internet_exposed: bool,
    compensating_control: bool,
) -> float:
    """Apply the versioned deterministic risk-weight policy to one occurrence."""
    control_multiplier = 0.75 if compensating_control else 1.0
    return round(
        float(cvss)
        * (1 + int(asset_criticality) / 5)
        * (1 + int(service_criticality) / 5)
        * (1.25 if internet_exposed else 1)
        * control_multiplier,
        4,
    )
