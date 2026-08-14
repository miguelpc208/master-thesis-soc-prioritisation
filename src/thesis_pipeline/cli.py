from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import subprocess
import sys

from thesis_pipeline.config import ConfigurationError, load_experiment, load_scenario
from thesis_pipeline.ingestion.inventory import inventory_vulzoo
from thesis_pipeline.run import project_root, run_experiment
from thesis_pipeline.storage.schema import initialise_database
from thesis_pipeline.synthetic_org.generator import generate_dataset


def _command_available(command: str) -> bool:
    try:
        subprocess.run([command, "--version"], check=False, capture_output=True)
        return True
    except FileNotFoundError:
        return False


def doctor() -> int:
    root = project_root()
    checks: dict[str, object] = {
        "project_root": str(root),
        "python": platform.python_version(),
        "python_supported": sys.version_info[:2] in {(3, 11), (3, 12)},
        "git_available": _command_available("git"),
        "conda_environment": os.environ.get("CONDA_DEFAULT_ENV"),
        "thesis_data_root_configured": bool(os.environ.get("THESIS_DATA_ROOT")),
        "pyyaml_available": importlib.util.find_spec("yaml") is not None,
        "simpy_available": importlib.util.find_spec("simpy") is not None,
        "external_data_downloaded": False,
    }
    try:
        load_scenario(root / "configs/scenarios/smoke.yaml")
        load_experiment(root / "configs/experiments/e1_cvss.yaml")
        load_experiment(root / "configs/experiments/e2_threat_intel.yaml")
        checks["configurations_valid"] = True
    except ConfigurationError as exc:
        checks["configurations_valid"] = False
        checks["configuration_error"] = str(exc)
    checks["ready_for_synthetic_smoke"] = bool(
        checks["python_supported"]
        and checks["pyyaml_available"]
        and checks.get("configurations_valid")
    )
    checks["note"] = (
        "THESIS_DATA_ROOT and SimPy are required for later data/research phases; the bootstrap "
        "uses a dependency-light deterministic scheduler for validation."
    )
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0 if checks["ready_for_synthetic_smoke"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Master thesis SOC research pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="Inspect the local synthetic-pipeline environment")

    generate = subparsers.add_parser("generate-synthetic", help="Generate seeded input summary")
    generate.add_argument("--config", required=True)

    inventory = subparsers.add_parser(
        "inventory-vulzoo", help="Inventory an approved existing local VulZoo clone"
    )
    inventory.add_argument("--config", required=True)

    database = subparsers.add_parser(
        "init-db", help="Initialise the versioned SQLite schema outside the repository"
    )
    database.add_argument("--path", required=True)

    run = subparsers.add_parser("run-experiment", help="Run an enabled experiment")
    run.add_argument("--experiment", required=True)
    run.add_argument("--scenario", required=True)
    run.add_argument("--output-root")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        if args.command == "doctor":
            return doctor()
        if args.command == "generate-synthetic":
            config = load_scenario(args.config)
            dataset = generate_dataset(config)
            print(
                json.dumps(
                    {
                        "scenario": config.scenario_id,
                        "seed": config.seed,
                        "services": len(dataset.services),
                        "assets": len(dataset.assets),
                        "findings": len(dataset.findings),
                        "fingerprint_sha256": dataset.fingerprint,
                        "research_status": "synthetic_engineering_fixture",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "inventory-vulzoo":
            print(json.dumps(inventory_vulzoo(args.config), indent=2, sort_keys=True))
            return 0
        if args.command == "init-db":
            print(initialise_database(args.path))
            return 0
        if args.command == "run-experiment":
            path = run_experiment(
                args.experiment,
                args.scenario,
                args.output_root,
                cli_arguments=arguments,
            )
            print(path)
            return 0
    except (ConfigurationError, RuntimeError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
