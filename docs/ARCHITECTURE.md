# Architecture

## Logical flow

1. Snapshot and inventory public vulnerability intelligence outside the repository.
2. Apply time-aware quality gates and normalise around CVE.
3. Generate a seeded fictional organisation, asset inventory, ownership, and constraints.
4. Create/correlate findings and preserve the evidence available at each decision.
5. Apply a versioned prioritisation strategy.
6. Schedule human triage and remediation under finite capacity.
7. Calculate metrics, uncertainty, and sensitivity across repeated runs.
8. Export traceable tables/figures with manifests and limitations.

The CLI orchestrates reusable modules; notebooks remain thin exploration/reporting layers. SQLite is
the canonical MVP relational store after external-data ingestion, while CSV/Parquet are controlled
exchange formats. Generated databases and outputs are ignored by Git.

## Trust boundaries

- External data are read-only inputs beneath `THESIS_DATA_ROOT`.
- Synthetic organisation data never represent a named employer.
- AI output is evidence-linked advice subject to logged human review.
- Honeypot evidence is synthetic or authorised replay by default; the code cannot deploy sensors.

## Current implementation boundary

The Phase 2 scheduler is a deterministic finite-capacity batch queue built with the standard
library. It validates lifecycle, prioritisation, queueing, and metric contracts without making SimPy
a bootstrap runtime blocker. SimPy is included in the research environment for the richer arrival,
shift, interruption, rework, and patch-window model planned in Phase 5.

