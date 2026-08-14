[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

python -m pytest
if ($LASTEXITCODE -ne 0) { throw "Pytest failed; smoke experiments were not started." }

ruff check .
if ($LASTEXITCODE -ne 0) { throw "Ruff failed; smoke experiments were not started." }

$Scenario = "configs/scenarios/smoke.yaml"
python -m thesis_pipeline.cli run-experiment --experiment configs/experiments/e1_cvss.yaml --scenario $Scenario
if ($LASTEXITCODE -ne 0) { throw "E1 smoke run failed." }

python -m thesis_pipeline.cli run-experiment --experiment configs/experiments/e2_threat_intel.yaml --scenario $Scenario
if ($LASTEXITCODE -ne 0) { throw "E2 smoke run failed." }

Write-Host "E1/E2 smoke runs completed. Compare manifest input fingerprints before metrics."
Write-Host "These are engineering checks, not dissertation research results."

