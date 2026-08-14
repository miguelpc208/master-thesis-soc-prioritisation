# Experiment protocol

## Common-input comparison

Each treatment comparison must pin the vulnerability snapshot, organisational scenario, workload,
random seed, and simulation horizon. The manifest's synthetic input fingerprint verifies the E1/E2
common-input contract.

## Ladder

- **E1:** CVSS descending, finding-ID tie-break; existing human workflow remains.
- **E2:** KEV status, then EPSS probability, then CVSS; time-aware evidence only.
- **E3:** Versioned technical/business weights; validate sum and run sensitivity analysis.
- **E4:** Constraint-aware scheduling for capacity, ownership, patch windows, freezes, dependencies,
  risk acceptance, and remediation duration.
- **E5:** Local assistance, deterministic fallback, evidence links, and mandatory logged review.
- **E6:** Synthetic/authorised replay evidence only unless a separate lab/ethics plan is approved.

## Research-run requirements

1. Freeze the protocol, outcome definitions, scenario grid, seeds, and exclusions before results.
2. Use several replications and common random numbers across treatments.
3. Report distributions, uncertainty intervals, effect sizes, and sensitivity.
4. Distinguish ranking outcomes, operational outcomes, and business-risk proxies.
5. Analyse omitted/actionable cases, not only volume reduction.
6. Keep configuration, manifests, validation summaries, and source checksums.

## Core outcomes

Ranking metrics apply only when defensible labels exist. Operational metrics include reduction,
queue wait, backlog/age, throughput, cycle times, SLA rates, capacity utilisation, rework, and
risk-weighted exposure. Every presentation of synthetic timing repeats that it estimates relative
scenario effects rather than actual enterprise MTTM/MTTR.

