# Operating rules for coding assistants

1. Do not fabricate findings, citations, source statistics, API access, or test outcomes.
2. Do not download large data into this repository or OneDrive. Obtain approval for
   `THESIS_DATA_ROOT` first.
3. Never commit raw datasets, databases, generated outputs, secrets, LLM responses, or honeypot
   payloads.
4. Preserve time-aware evidence. Reject EPSS, KEV, exploit, or other evidence dated after the
   simulated decision.
5. Use deterministic seeds, versioned configurations, input checksums, and identical scenarios for
   experiment comparisons.
6. Human triage and remediation exist in every baseline. AI assistance never becomes ground truth
   or removes mandatory human review.
7. E5 and E6 are disabled by default. Do not deploy exposed honeypots or vulnerable services.
8. Run tests and quality checks before making claims. Label smoke outputs as engineering validation.
9. Use British English in documentation and retain official product/source names.
10. Do not create a remote, push, or change repository visibility without Ricardo's approval.

