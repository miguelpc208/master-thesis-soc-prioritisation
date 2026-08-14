from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SMOKE_SCENARIO = PROJECT_ROOT / "configs/scenarios/smoke.yaml"
E1_EXPERIMENT = PROJECT_ROOT / "configs/experiments/e1_cvss.yaml"
E2_EXPERIMENT = PROJECT_ROOT / "configs/experiments/e2_threat_intel.yaml"
