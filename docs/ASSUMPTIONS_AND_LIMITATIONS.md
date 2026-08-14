# Assumptions and limitations register

## Classification

| Class | Meaning | Current example |
| --- | --- | --- |
| Source-backed | Directly supported and cited | VulZoo source URL and processed snapshot date |
| Calibrated | Estimated from defensible observations/expert elicitation | None yet |
| Engineering default | Used only to prove plumbing | Smoke assets, findings, service times, capacities |
| Sensitivity range | Intentionally varied to test robustness | Baseline/stress workload and capacity (pending validation) |

## Current limitations

- No real organisation, Qualys feed, or enterprise SOC measurement is included.
- Synthetic CVSS/EPSS/KEV/actionability are engineering fixtures.
- The Phase 2 scheduler is a simplified deterministic batch queue.
- No external-data ingestion, temporal snapshot panel, E3 optimisation, or E4 scheduler is complete.
- Smoke metrics are not research results and cannot estimate actual business impact.
- Runtime distributions and SLA thresholds require literature/expert calibration.
- E5/E6 add governance, ethics, validity, and scope risk; both are disabled.

## Required sensitivity dimensions

Workload intensity, duplicate rate, team capacity, service-time distributions, business criticality,
internet exposure, patch windows/freezes, risk acceptance, scenario horizon, weighting choices, and
label prevalence.

