import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "infra" / "cmdbuild" / "compose.yaml"
LOCK_PATH = ROOT / "infra" / "cmdbuild" / "image-lock.json"
EXAMPLE_PATH = ROOT / "config" / ".env.example"


def test_compose_uses_immutable_locked_images() -> None:
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    image_lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))

    assert set(image_lock["images"]) == {"cmdbuild", "postgres"}

    for image in image_lock["images"].values():
        assert image["digest"].startswith("sha256:")
        assert image["pinned_reference"] in compose
        assert image["os"] == "linux"
        assert image["architecture"] == "amd64"


def test_compose_does_not_pull_or_expose_network_services() -> None:
    compose = COMPOSE_PATH.read_text(encoding="utf-8")

    assert compose.count("pull_policy: never") == 2
    assert '127.0.0.1:${POSTGRES_PORT:-55432}:5432' in compose
    assert '127.0.0.1:${CMDBUILD_HTTP_PORT:-8090}:8080' in compose


def test_compose_requires_external_database_credentials() -> None:
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    example = EXAMPLE_PATH.read_text(encoding="utf-8")

    assert "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}" in compose
    assert "POSTGRES_PASSWORD=\n" in example


def test_ready2use_starts_with_empty_dataset_and_utc() -> None:
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    example = EXAMPLE_PATH.read_text(encoding="utf-8")

    assert "CMDBUILD_DUMP=empty.dump.xz" in example
    assert "${CMDBUILD_DUMP:-empty.dump.xz}" in compose
    assert "-Duser.timezone=UTC" in compose
