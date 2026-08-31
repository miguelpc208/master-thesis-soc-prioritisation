from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import requests

from thesis_pipeline.cmdbuild import (
    CMDBuildAuthenticationError,
    CMDBuildClient,
    CMDBuildConfigurationError,
    CMDBuildResponseError,
    CMDBuildSettings,
)


@dataclass
class FakeResponse:
    payload: Any
    status_code: int = 200
    content: bytes = b"present"

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError("HTTP request failed", response=self)

    def json(self) -> Any:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


@dataclass
class FakeSession:
    responses: list[FakeResponse | requests.RequestException]
    headers: dict[str, str] = field(default_factory=dict)
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    closed: bool = False

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("Unexpected outgoing HTTP request")
        response = self.responses.pop(0)
        if isinstance(response, requests.RequestException):
            raise response
        return response

    def close(self) -> None:
        self.closed = True


def successful(data: Any) -> FakeResponse:
    return FakeResponse({"success": True, "data": data})


def settings() -> CMDBuildSettings:
    return CMDBuildSettings(
        base_url="http://127.0.0.1:8090/cmdbuild",
        username="admin",
        password="test-password-kept-private",
    )


def authenticated_client(*responses: FakeResponse) -> tuple[CMDBuildClient, FakeSession]:
    session = FakeSession([successful({"_id": "unit-test-token"}), *responses])
    client = CMDBuildClient(settings(), session=session)
    client.authenticate()
    return client, session


def test_settings_read_literal_env_values_without_disclosing_password(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "CMDBUILD_BASE_URL=http://127.0.0.1:8090/cmdbuild\n"
        "CMDBUILD_USERNAME=admin\n"
        "CMDBUILD_PASSWORD=secret#literal=value\n"
        "CMDBUILD_API_VERSION=v3\n"
        "POSTGRES_PASSWORD=unrelated-secret\n",
        encoding="utf-8",
    )

    configuration = CMDBuildSettings.from_env_file(path)

    assert configuration.password == "secret#literal=value"
    assert "secret#literal=value" not in repr(configuration)


@pytest.mark.parametrize(
    "base_url",
    (
        "http://example.com/cmdbuild",
        "https://192.168.1.20/cmdbuild",
        "ftp://127.0.0.1/cmdbuild",
        "http://admin:secret@127.0.0.1/cmdbuild",
    ),
)
def test_settings_reject_non_loopback_or_unsafe_urls(base_url: str) -> None:
    with pytest.raises(CMDBuildConfigurationError):
        CMDBuildSettings(base_url=base_url, username="admin", password="private")


def test_settings_reject_duplicate_application_credentials(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "CMDBUILD_BASE_URL=http://127.0.0.1:8090/cmdbuild\n"
        "CMDBUILD_USERNAME=admin\n"
        "CMDBUILD_PASSWORD=first\n"
        "CMDBUILD_PASSWORD=second\n",
        encoding="utf-8",
    )

    with pytest.raises(CMDBuildConfigurationError, match="Duplicate CMDBuild setting"):
        CMDBuildSettings.from_env_file(path)


def test_session_authentication_uses_service_scope_and_hides_token() -> None:
    client, session = authenticated_client()

    method, url, options = session.calls[0]
    assert method == "POST"
    assert url.endswith("/services/rest/v3/sessions")
    assert options["params"] == {"scope": "service", "returnId": "true"}
    assert options["json"]["username"] == "admin"
    assert options["allow_redirects"] is False
    assert session.trust_env is False
    assert client.authenticated
    assert session.headers["Cmdbuild-Authorization"] == "unit-test-token"


def test_requests_require_an_authenticated_session() -> None:
    session = FakeSession([])
    client = CMDBuildClient(settings(), session=session)

    with pytest.raises(CMDBuildAuthenticationError, match="not been authenticated"):
        client.lookup_values("SLA - Object")

    assert session.calls == []


def test_lookup_resolves_by_code_and_caches_without_persisting_ids() -> None:
    client, session = authenticated_client(
        successful([{"_id": 101, "code": "charge", "active": True}])
    )

    assert client.resolve_lookup("SLA - Object", "charge") == 101
    assert client.resolve_lookup("SLA - Object", "charge") == 101

    assert len(session.calls) == 2
    method, url, options = session.calls[1]
    assert method == "GET"
    assert url.endswith("/lookup_types/SLA%20-%20Object/values")
    assert options["params"] == {"active": "true"}


def test_lookup_rejects_missing_or_ambiguous_codes() -> None:
    client, _ = authenticated_client(
        successful(
            [
                {"_id": 1, "code": "charge", "active": True},
                {"_id": 2, "code": "charge", "active": True},
            ]
        )
    )

    with pytest.raises(CMDBuildResponseError, match="Expected one active lookup"):
        client.resolve_lookup("SLA - Object", "charge")


@pytest.mark.parametrize(
    "response_data",
    (
        {"_id": "IM02-HDOpening", "description": "Helpdesk opening"},
        [{"_id": "IM02-HDOpening", "description": "Helpdesk opening"}],
    ),
)
def test_start_activity_normalizes_object_and_list(response_data: Any) -> None:
    client, _ = authenticated_client(successful(response_data))

    activities = client.start_activities("IncidentMgt")

    assert activities == [{"_id": "IM02-HDOpening", "description": "Helpdesk opening"}]


def test_http_failures_do_not_disclose_password() -> None:
    session = FakeSession([requests.ConnectionError("connection unavailable")])
    client = CMDBuildClient(settings(), session=session)

    with pytest.raises(CMDBuildAuthenticationError) as error:
        client.authenticate()

    assert "test-password-kept-private" not in str(error.value)


def test_invalid_api_response_is_rejected() -> None:
    client, _ = authenticated_client(FakeResponse({"success": False, "data": []}))

    with pytest.raises(CMDBuildResponseError, match="successful API response"):
        client.lookup_values("SLA - Object")


def test_session_close_revokes_authorization_and_clears_local_state() -> None:
    client, session = authenticated_client(successful(None))

    client.close()

    assert session.calls[-1][0] == "DELETE"
    assert session.calls[-1][1].endswith("/sessions/current")
    assert "Cmdbuild-Authorization" not in session.headers
    assert session.closed
    assert not client.authenticated


@pytest.mark.parametrize(
    "logout_response",
    (
        FakeResponse({"success": True}),
        FakeResponse(None, status_code=204),
        FakeResponse(None, content=b""),
    ),
)
def test_session_close_accepts_documented_empty_responses(logout_response: FakeResponse) -> None:
    client, session = authenticated_client(logout_response)

    client.close()

    assert not client.authenticated
    assert session.closed
