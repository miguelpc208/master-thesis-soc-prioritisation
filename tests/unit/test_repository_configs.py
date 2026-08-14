from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_repository_yaml_configs_parse() -> None:
    config_paths = sorted((PROJECT_ROOT / "configs").rglob("*.yaml"))
    assert config_paths

    for config_path in config_paths:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert document is not None, f"{config_path} is empty"
