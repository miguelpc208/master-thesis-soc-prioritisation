"""Read-only, secret-safe smoke checks for the installed READY2USE instance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from thesis_pipeline.cmdbuild.client import (
    CMDBuildClient,
    CMDBuildConfigurationError,
    CMDBuildResponseError,
    CMDBuildSettings,
)


def main(argv: list[str] | None = None) -> int:
    """Verify login, stable lookup codes and discovered workflow activities."""

    parser = argparse.ArgumentParser(description="Run read-only CMDBuild smoke checks")
    parser.add_argument("--env-file", default="config/.env")
    parser.add_argument("--mapping-file", default="config/cmdbuild_fields.json")
    arguments = parser.parse_args(argv)

    mapping_path = Path(arguments.mapping_file)
    if not mapping_path.is_file():
        raise CMDBuildConfigurationError("CMDBuild mapping file does not exist")
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    if mapping.get("discovery_status") != "confirmed":
        raise CMDBuildConfigurationError("CMDBuild mapping has not been confirmed")

    settings = CMDBuildSettings.from_env_file(arguments.env_file)
    checks = (
        ("sla_object", "triage"),
        ("sla_object", "resolution"),
        ("sla_threshold_type", "minutes"),
        ("workflow", "incident"),
        ("workflow", "change"),
        ("service_category_state", "active"),
    )

    with CMDBuildClient(settings) as client:
        print("Authentication: successful; authorization token not displayed")

        for lookup_name, logical_code in checks:
            lookup = mapping["lookups"][lookup_name]
            client.resolve_lookup(lookup["type"], lookup["codes"][logical_code])
            print(f"Lookup {lookup_name}.{logical_code}: resolved by stable code")

        for logical_name in ("incident", "change"):
            entity = mapping["entities"][logical_name]
            activities = client.start_activities(entity["cmdbuild_id"])
            expected = entity["start_activity"]
            matches = [activity for activity in activities if activity.get("_id") == expected]
            if len(matches) != 1:
                raise CMDBuildResponseError(
                    f"Expected start activity '{expected}' for process '{entity['cmdbuild_id']}'"
                )
            print(f"Workflow {logical_name}: start activity {expected} confirmed")

        print("Business cards created: 0")
        print("Process instances created or advanced: 0")

    print("Authenticated session: closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
