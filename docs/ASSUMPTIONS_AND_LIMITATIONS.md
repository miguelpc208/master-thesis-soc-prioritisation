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
- VulZoo, DiverseVul and the 15-day FIRST EPSS panel are complete for their approved snapshots and
  scenario window; exact historical NVD/KEV version panels remain unavailable.
- The active March-April 2025 EPSS panel and retained January 2026 archive were acquired locally in
  August 2026 and therefore support source-effective reconstruction, not strict historical local
  availability or ground-truth claims. Scenario alignment reduces NVD/KEV snapshot staleness without
  recreating complete historical NVD/KEV versions.
- None of the 76,615 legacy-only canonical CVEs has a safely recoverable source publication date;
  one offset-free timestamp remains ambiguous and must not be silently interpreted as UTC.
- The as-of view prevents look-ahead under its declared mode; source-effective reconstruction from
  one retained snapshot is not exact historical ground truth.
- GitHub advisory metadata is one locally acquired retained version, not a complete historical
  advisory panel. Authoritative publication and modification timestamps may be non-monotonic;
  reconstruction therefore uses their conservative maximum without claiming earlier versions.
  Withdrawn, conflicting and future-timestamped records remain excluded.
- Advisory fixed-version events and corroborated commit references are remediation context only:
  they do not establish asset applicability, vendor deployment or actual remediation. Commits
  without an exact authoritative advisory URL remain undated and historically ineligible.
- Advisory descriptions, patch bodies, proof-of-concept links and exploit payloads are excluded;
  no operational exploit capability can be inferred from this technical dataset.
- The real technical SQLite observations are not yet wired into the synthetic experiment runner.
- E3 optimisation and the full E4 scheduler are not complete.
- Smoke metrics are not research results and cannot estimate actual business impact.
- Runtime distributions and SLA thresholds require literature/expert calibration.
- E5/E6 add governance, ethics, validity, and scope risk; both are disabled.

## Required sensitivity dimensions

Workload intensity, duplicate rate, team capacity, service-time distributions, business criticality,
internet exposure, patch windows/freezes, risk acceptance, scenario horizon, weighting choices, and
label prevalence.
