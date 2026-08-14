# Working research design

All wording, thresholds, distributions, and weights remain working assumptions until supported by
literature, calibration evidence, or supervisor approval.

## Research questions

- **RQ1:** How much do threat intelligence and organisational/business context improve ranking
  usefulness compared with CVSS-only prioritisation?
- **RQ2:** How do finite capacity, maintenance windows, SLAs, risk acceptance, compliance scope,
  and freezes change operational outcomes and remediation order?
- **RQ3:** What incremental effect does human-reviewed AI assistance have on alert volume, effort,
  cycle time, and consistency?
- **RQ4:** Are benefits directionally robust across structures, workloads, capacities, and risk
  appetites?
- **RQ5:** Which governance, traceability, and human-oversight controls make the approach
  defensible?
- **Exploratory:** Does isolated honeypot-derived evidence add value beyond CVSS, EPSS, KEV,
  exploit availability, and business context?

## Hypotheses

- **H1:** Backlog and cycle times increase non-linearly once workload exceeds capacity.
- **H2:** Correlation, threat intelligence, and business context improve ranking usefulness and SLA
  outcomes over CVSS-only prioritisation.
- **H3:** Human-reviewed assistance reduces cycle time without unacceptable omission of relevant
  cases.
- **H4:** Gains remain directionally robust while effect magnitude varies by scenario.
- **H5:** Governance and organisational constraints materially change the technical-score order.

## Design logic

This is a simulation experiment with common random numbers: compared treatments use the same input
snapshot and seeds. Human triage/remediation exists in all arms. E1/E2 establish transparent
ranking baselines; E3 adds business context; E4 performs constraint-aware scheduling. E5 and E6 are
incremental and optional.

Actual research runs require a pre-registered scenario grid, several replications per cell,
uncertainty intervals, effect sizes, sensitivity analysis, and robustness checks. The bundled smoke
scenario tests plumbing only.

## Validity controls

- Temporal joins use information available at the decision timestamp.
- Current KEV cannot be both an input and the sole contemporaneous outcome.
- Source snapshots, model versions, checksums, seeds, and code revisions are retained.
- Synthetic labels and timings are clearly separated from observed data.
- Parameter choices are classified as source-backed, calibrated, engineering defaults, or
  sensitivity ranges.

