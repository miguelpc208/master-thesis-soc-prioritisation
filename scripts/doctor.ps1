[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is unavailable. Activate the thesis-soc Conda environment first."
}

python -m thesis_pipeline.cli doctor
if ($LASTEXITCODE -ne 0) {
    throw "Environment doctor failed. Review the JSON output above."
}

