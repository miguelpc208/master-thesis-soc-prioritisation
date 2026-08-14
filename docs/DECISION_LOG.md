# Decision log

| Date | Decision | Alternatives | Reason/evidence | Impact | Revisit trigger |
| --- | --- | --- | --- | --- | --- |
| 2026-08-03 | Keep both title candidates; official title pending | Select one silently | Supervisor confirmation absent | Avoids mislabelling dissertation | Supervisor decision |
| 2026-08-03 | Keep heavy data outside Git/OneDrive | Store under repository | VulZoo storage scale and reproducibility | Requires approved `THESIS_DATA_ROOT` | Data checkpoint |
| 2026-08-03 | Implement E1/E2 synthetic smoke first | Download all sources first | Validates contracts cheaply and safely | No research claims yet | Phase 3 approval |
| 2026-08-03 | Use dependency-light scheduler for Phase 2 and SimPy for richer research model | Make SimPy a bootstrap blocker | Validation runtime lacks SimPy; scheduling contract can be tested independently | Full arrival/shift model remains pending | Phase 5 modelling |
| 2026-08-03 | Disable E5/E6 | Include both in MVP | Scope, validity, ethics, and operational risk | Core remains E1–E4 | Supervisor/scope decision |
| 2026-08-14 | Use `C:\Users\Ricardo\ThesisData\master-thesis-soc` as `THESIS_DATA_ROOT` | Repository/OneDrive storage or another local drive | Preflight confirmed that the path is outside OneDrive with 112,74 GB free | Heavy datasets, databases and research runs remain outside Git and OneDrive | Free space falls below 30 GB or storage is migrated |
| 2026-08-14 | Acquire VulZoo processed-first through a shallow partial sparse clone without submodules | Full recursive clone and raw-data rebuild | Upstream quick start supports using the existing processed dataset without recursively cloning submodules | Phase 3 starts from the dated processed snapshot; raw-source synchronisation remains deferred | Required variables, lineage or freshness cannot be obtained from the processed snapshot |
| 2026-08-14 | Host code and configuration in private repository `miguelpc208/master-thesis-soc-prioritisation` | Public GitHub repository or local-only history | Initial GitHub Actions run `31791972990` passed on `main` | Enables remote versioning and CI without publishing datasets or local configuration | Supervisor approves public release or repository governance changes |
| 2026-08-14 | Use `C:\Users\Ricardo\ThesisData\master-thesis-soc` as `THESIS_DATA_ROOT` | Repository/OneDrive storage or another local drive | Preflight confirmed that the path is outside OneDrive with 112.74 GB free | Heavy datasets, databases and research runs remain outside Git and OneDrive | Free space falls below 30 GB or storage is migrated |
| 2026-08-14 | Acquire VulZoo processed-first through a shallow partial sparse clone without submodules | Full recursive clone and raw-data rebuild | Upstream supports use of the processed dataset without recursively cloning submodules | Phase 3 starts from a pinned processed snapshot; raw-source synchronisation remains deferred | Required variables, lineage or freshness cannot be obtained from the processed snapshot |
| 2026-08-14 | Host code and configuration in private repository `miguelpc208/master-thesis-soc-prioritisation` | Public GitHub repository or local-only history | Initial GitHub Actions run `31791972990` passed on `main` | Enables remote versioning and CI without publishing datasets or local configuration | Supervisor approves public release or repository governance changes |

New entries must state decision, alternatives, evidence, impact, and a concrete revisit trigger.

