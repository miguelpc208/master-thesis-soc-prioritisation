# Ricardo's actions to complete the thesis project

The repository bootstrap, E1/E2 synthetic pipeline, configs, tests, CI, manifests, and documentation
are already prepared. The actions below require your Windows machine, accounts, academic judgement,
or supervisor approval.

## A. Install and validate locally

1. Back up the current `thesis` folder. Extract the delivered project to a temporary folder, then
   copy its **contents** into your existing thesis root. Do not replace or rename the four existing
   `research` folders; merge their README files.
2. Open PowerShell in the thesis root and run:

   ```powershell
   Get-Location
   Get-ChildItem -Force
   git --version
   conda --version
   python --version
   gh --version
   ```

3. If Git is missing, install it, restart PowerShell, and rerun the check:

   ```powershell
   winget install --id Git.Git -e --source winget
   ```

4. Create the dedicated environment; never modify Conda `base`:

   ```powershell
   conda env create -f environment.yml
   conda activate thesis-soc
   python -m pip install -e .
   python -m thesis_pipeline.cli doctor
   python -m pytest
   ruff check .
   .\scripts\run_smoke_test.ps1
   ```

5. Compare the two new smoke manifests. Their `inputs.fingerprint_sha256` must match. Treat every
   generated number as an engineering check, not a thesis result.

## B. Make the five checkpoint decisions

Record each answer in `docs/DECISION_LOG.md` before Phase 3:

1. **Data root:** choose an absolute non-OneDrive path with at least 30 GB free. Create `.env` from
   `.env.example` and set `THESIS_DATA_ROOT` there.
2. **VulZoo:** approve or reject a shallow, non-recursive, processed-first clone.
3. **GitHub:** confirm owner, repository name (recommended
   `master-thesis-soc-prioritisation`), and private/public visibility.
4. **Academic:** confirm the current dissertation deadline and official title with the supervisor.
5. **Scope:** decide whether E5/Ollama and E6/honeypots remain final-scope, stretch goals, or are
   removed. Recommended: core E1–E4; E5 stretch; E6 exploratory/future work unless approvals and time
   are strong.

## C. Create the local and remote Git history

The delivered archive excludes its build-time `.git` metadata. In the merged thesis root:

```powershell
git init -b main
git add .
git status
git commit -m "chore: bootstrap reproducible thesis pipeline"
git switch -c chore/phase-3-data-ingestion
```

Only after confirming owner/name/visibility, create or connect the private GitHub repository. Do not
push data or `.env`. If using GitHub CLI:

```powershell
gh repo create master-thesis-soc-prioritisation --private --source . --remote origin --push
```

Replace the command if the approved name/visibility differs.

## D. Build the evidence base

1. Agree the exact RQs, hypotheses, constructs, and primary outcomes with the supervisor.
2. Define a reproducible search protocol per research axis; log every query in
   `research/search_log.csv`.
3. Screen and quality-assess papers; add only verified sources to
   `research/literature_matrix.csv`.
4. Write the literature synthesis around alert fatigue, vulnerability prioritisation, temporal
   threat intelligence, finite SOC capacity, organisational constraints, human-in-the-loop
   automation, and simulation validity.
5. Obtain supervisor/ethics guidance before any expert interviews, user study, organisation-specific
   data, AI evaluation with people, or live honeypot activity.

## E. Execute the research phases

1. **Phase 3:** clone/inventory VulZoo only under the approved data root; capture commit, sizes,
   schemas, encodings, nulls, and join keys before ingestion.
2. **Phase 4:** acquire date-pinned EPSS and KEV snapshots, record checksums/model/catalogue dates,
   build temporal joins, and test look-ahead guards.
3. **Calibration:** justify arrival/service distributions, workload, capacity, SLA, business
   criticality, and risk-appetite assumptions using literature, public benchmarks, or documented
   expert elicitation. Do not present guesses as organisational facts.
4. **E3/E4:** finalise business-context weights and constraint-aware scheduling; predefine
   sensitivity ranges.
5. **Freeze the protocol:** scenarios, seeds, outcomes, exclusions, replications, statistical tests,
   and robustness checks before looking at final comparative results.
6. **Run study:** use common inputs/seeds, multiple replications, uncertainty intervals and effect
   sizes. Retain manifests and validation summaries.
7. **Optional E5/E6:** proceed only under the approved scope and governance/ethics plan. Keep human
   review mandatory; default honeypot work to authorised replay.

## F. Finish and defend the dissertation

1. Convert validated outputs into reproducible tables/figures and, if useful, Power BI-ready CSVs.
2. Write Methods before interpreting Results; separate synthetic estimates from observed source
   facts.
3. Answer each RQ directly, report null/negative findings, uncertainty, omissions, and sensitivity.
4. Complete validity threats, governance, ethics, reproducibility, and practical business
   implications.
5. Ask the supervisor to review the protocol before final runs and the claims before submission.
6. Run citation, plagiarism, formatting, language, table/figure, appendix, and archive checks.
7. Create a clean reproducibility release containing code/configs/small fixtures only—never raw
   heavy data, credentials, model-sensitive output, or honeypot payloads.

