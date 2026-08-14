[CmdletBinding()]
param(
    [switch]$CreateEnvironment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is missing. With approval, run: winget install --id Git.Git -e --source winget"
}
if (-not (Get-Command conda -ErrorAction SilentlyContinue)) {
    throw "Conda is missing. Install Miniconda/Anaconda or agree an alternative before continuing."
}

if ($CreateEnvironment) {
    conda env create -f environment.yml
    if ($LASTEXITCODE -ne 0) {
        throw "Conda environment creation failed. If it exists, update it explicitly instead."
    }
    Write-Host "Environment created. Run: conda activate thesis-soc"
    exit 0
}

Write-Host "Safe preflight passed. No software, data, remote, AI model, or honeypot was installed."
Write-Host "To create the environment explicitly: .\scripts\bootstrap.ps1 -CreateEnvironment"

