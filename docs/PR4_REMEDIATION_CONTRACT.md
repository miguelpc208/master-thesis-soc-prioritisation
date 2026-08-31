# PR #4 remediation and provenance contract

This contract closes the six technical-review findings without authorising ready-for-review,
auto-merge or merge. It distinguishes code-level remediation from empirical replay: CI can prove
the fail-closed mechanisms, but only the frozen local source snapshots can produce and approve the
new derived fingerprints.

## Closed code findings

| Finding | Remediation | Fail-closed evidence |
| --- | --- | --- |
| Stale risk weight after public binding | One versioned risk policy is shared by generation and binding; binding recalculates after public CVSS replacement | Unit test compares every bound weight with the shared policy |
| Unauthenticated GHSA bodies | Manifest v2 enumerates every body by path, size and SHA-256; an independent audit approves the collection fingerprint; ingestion authenticates the exact bytes it parses | Body tampering and collection drift are rejected before accepted rows |
| Unversioned CMDBuild execution | CLI commands rebuild preview, business ingestion, operational ingestion and metadata-only evidence export from versioned contracts | Exact fingerprint gates and existing rollback writers remain mandatory |
| Count-only canonical CVE gate | DiverseVul profile v2 and EPSS manifest v2 approve a SHA-256 over sorted, newline-delimited CVE IDs | Same-count identity substitution is rejected |
| Incomplete public-binding fingerprint | Fingerprint now covers CVE/CVSS/EPSS/KEV/DiverseVul metadata and bound risk weights | A metadata-only evidence change changes the fingerprint |
| Partial EPSS panel selection | Migration 010 records parent/day completion and exact daily source snapshots | Failed, running or incomplete panels are ineligible |

## Invariants and invalidated derived values

The remediation must preserve these upstream-independent values:

- source dataset fingerprint:
  `f2f4889ae4431e88d1c169598d0d357dd97dc176783b6c5d4fcc70904f9e65ca`;
- business payload fingerprint:
  `862dfe848a8d566adb4e896bad5906f91e6bb123ebfe383fc343366c6988c4ef`;
- 240 raw findings, 201 unique occurrences, 39 duplicates and 55 actionable occurrences;
- 234 business cards plus 260 business relations.

The pre-remediation public-binding fingerprint
`2c0dffaae41a991136ab8abdf30ccbf19b4a235f2898fdf3d8ef822061740650`
and operational fingerprint
`729d0cce36258287740ac61738170e3857cedf66c253a9e98b3f9dcbe7d36276`
are historical values. They must not be asserted after this change: corrected risk weights and the
expanded binding material intentionally produce new values.

## Required external replay

1. Back up the canonical SQLite database and the approved external manifests.
2. Apply migration 010 with `init-db`.
3. Upgrade the DiverseVul profile to `diversevul-profile-v2` by adding the canonical CVE identity
   digest, without changing its pinned commit or the two approved source-file SHA-256 values.
4. Upgrade the EPSS acquisition manifest to `first-epss-acquisition-v2`, add the same canonical CVE
   identity digest, and replay every approved day. Accept only a succeeded parent with all days.
5. Upgrade the GHSA manifest to `vulzoo-github-advisory-acquisition-v2`; enumerate all retained body
   paths, sizes and SHA-256 values; independently approve the resulting collection fingerprint in
   the audit; replay advisory ingestion.
6. Run `cmdbuild-preview --phase all`, then `cmdbuild-export-evidence` to a new path outside Git.
7. Approve the new public and operational fingerprints only if the frozen source commits/trees,
   file SHA-256 values and expected counts all reconcile.

Until that replay is complete, provenance remains **not fully verifiable**. No code path may copy
the old public or operational fingerprint into a new evidence package. CMDBuild ingestion remains a
separate explicitly fingerprint-authorised action and is not required to validate this PR.

## PR gate

The draft may advance only after Ruff and the complete Python 3.11/3.12 test matrix succeed on the
new head, the external replay evidence is reviewed, and no unresolved review thread remains. None
of these conditions authorises merge.
