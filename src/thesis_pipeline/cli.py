from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import subprocess
import sys

from thesis_pipeline.config import ConfigurationError, load_experiment, load_scenario
from thesis_pipeline.ingestion.coverage import scan_vulzoo_coverage
from thesis_pipeline.ingestion.diversevul import ingest_diversevul
from thesis_pipeline.ingestion.inventory import inventory_vulzoo
from thesis_pipeline.ingestion.normalise import ingest_vulzoo
from thesis_pipeline.ingestion.profiling import profile_vulzoo
from thesis_pipeline.quality.evidence_as_of import AS_OF_MODES, audit_technical_evidence_as_of
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

    profile = subparsers.add_parser(
        "profile-vulzoo",
        help="Profile approved VulZoo collections without exporting raw content",
    )
    profile.add_argument("--config", required=True)
    profile.add_argument("--sample-limit", type=int, default=2)
    profile.add_argument("--max-json-mib", type=int, default=50)

    coverage = subparsers.add_parser(
        "scan-vulzoo-coverage",
        help="Scan complete NVD/CVE/KEV metadata without exporting raw records",
    )
    coverage.add_argument("--config", required=True)
    coverage.add_argument("--max-json-mib", type=int, default=5)
    coverage.add_argument("--rejection-sample-limit", type=int, default=20)

    ingest = subparsers.add_parser(
        "ingest-vulzoo",
        help="Normalise approved local NVD, legacy CVE, and KEV records into SQLite",
    )
    ingest.add_argument("--config", required=True)
    ingest.add_argument("--database", required=True)
    ingest.add_argument("--coverage-report", required=True)
    ingest.add_argument("--progress-every", type=int, default=10000)

    diversevul = subparsers.add_parser(
        "ingest-diversevul",
        help="Integrate approved DiverseVul function metadata with existing VulZoo CVEs",
    )
    diversevul.add_argument("--config", required=True)
    diversevul.add_argument("--database", required=True)
    diversevul.add_argument("--acquisition-manifest", required=True)
    diversevul.add_argument("--profile-report", required=True)
    diversevul.add_argument("--progress-every", type=int, default=25000)

    temporal = subparsers.add_parser(
        "audit-technical-as-of",
        help="Audit technical evidence available at a UTC decision cutoff without mutation",
    )
    temporal.add_argument("--database", required=True)
    temporal.add_argument("--decision-at", required=True)
    temporal.add_argument("--mode", choices=AS_OF_MODES, default="strict_snapshot")

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
        if args.command == "profile-vulzoo":
            profile = profile_vulzoo(
                args.config,
                sample_limit=args.sample_limit,
                max_json_bytes=args.max_json_mib * 1024 * 1024,
            )
            print(json.dumps(profile, indent=2, sort_keys=True))
            return 0
        if args.command == "scan-vulzoo-coverage":
            coverage = scan_vulzoo_coverage(
                args.config,
                max_json_bytes=args.max_json_mib * 1024 * 1024,
                rejection_sample_limit=args.rejection_sample_limit,
            )
            print(json.dumps(coverage, indent=2, sort_keys=True))
            return 0
        if args.command == "ingest-vulzoo":
            ingestion = ingest_vulzoo(
                args.config,
                args.database,
                args.coverage_report,
                progress_every=args.progress_every,
            )
            print(json.dumps(ingestion, indent=2, sort_keys=True))
            return 0
        if args.command == "ingest-diversevul":
            ingestion = ingest_diversevul(
                args.config,
                args.database,
                args.acquisition_manifest,
                args.profile_report,
                progress_every=args.progress_every,
            )
            print(json.dumps(ingestion, indent=2, sort_keys=True))
            return 0
        if args.command == "audit-technical-as-of":
            audit = audit_technical_evidence_as_of(
                args.database,
                args.decision_at,
                mode=args.mode,
            )
            print(json.dumps(audit, indent=2, sort_keys=True))
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
