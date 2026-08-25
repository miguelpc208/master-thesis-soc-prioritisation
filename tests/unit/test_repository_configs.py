from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_repository_yaml_configs_parse() -> None:
    config_paths = sorted((PROJECT_ROOT / "configs").rglob("*.yaml"))
    assert config_paths

    for config_path in config_paths:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert document is not None, f"{config_path} is empty"


def test_approved_epss_panel_covers_all_aligned_scenarios() -> None:
    paths = (
        PROJECT_ROOT / "configs" / "scenarios" / "baseline.yaml",
        PROJECT_ROOT / "configs" / "scenarios" / "stress.yaml",
        PROJECT_ROOT / "configs" / "scenarios" / "smoke.yaml",
    )
    starts = set()
    horizons = []

    for path in paths:
        scenario = yaml.safe_load(path.read_text(encoding="utf-8"))["scenario"]
        starts_at = datetime.fromisoformat(scenario["start_time_utc"])
        assert starts_at.tzinfo is not None
        starts.add(starts_at.astimezone(UTC))
        horizons.append(int(scenario["horizon_hours"]))

    approved_start = datetime(2025, 3, 22, 9, tzinfo=UTC)
    assert starts == {approved_start}
    assert max(horizons) == 336

    source_path = PROJECT_ROOT / "configs" / "data_sources.yaml"
    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))["sources"]["epss"]
    first_score_date = approved_start.date() - timedelta(days=1)
    last_score_date = (approved_start + timedelta(hours=max(horizons))).date() - timedelta(
        days=1
    )

    assert date.fromisoformat(source["panel_start_date"]) == first_score_date
    assert date.fromisoformat(source["panel_end_date"]) == last_score_date
    assert source["panel_relative_path"] == (
        f"panels/{first_score_date.isoformat()}_to_{last_score_date.isoformat()}"
    )
    assert source["model_version"] == "v2025.03.14"
