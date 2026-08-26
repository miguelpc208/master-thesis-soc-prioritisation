"""Authenticated, loopback-only CMDBuild REST v3 client."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import requests

AUTHORIZATION_HEADER = "Cmdbuild-Authorization"


class CMDBuildError(RuntimeError):
    """Raised when the CMDBuild integration cannot operate safely."""


class CMDBuildConfigurationError(CMDBuildError):
    """Raised when local CMDBuild configuration is invalid."""


class CMDBuildAuthenticationError(CMDBuildError):
    """Raised when a valid authenticated session cannot be established."""


class CMDBuildResponseError(CMDBuildError):
    """Raised when the REST API returns an unusable response."""


def _is_loopback(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class CMDBuildSettings:
    """Connection settings; passwords never appear in object representations."""

    base_url: str
    username: str
    password: str = field(repr=False)
    api_version: str = "v3"
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not _is_loopback(parsed.hostname):
            raise CMDBuildConfigurationError("CMDBuild base URL must point to localhost")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise CMDBuildConfigurationError("CMDBuild base URL contains unsupported components")
        if not self.username.strip() or not self.password:
            raise CMDBuildConfigurationError("CMDBuild username and password are required")
        if self.api_version != "v3":
            raise CMDBuildConfigurationError("Only CMDBuild REST API v3 is supported")
        if isinstance(self.timeout_seconds, bool) or self.timeout_seconds <= 0:
            raise CMDBuildConfigurationError("CMDBuild request timeout must be positive")

    @classmethod
    def from_env_file(cls, path: str | Path) -> CMDBuildSettings:
        """Read the existing literal KEY=value secret file without new dependencies."""

        environment_path = Path(path)
        if not environment_path.is_file():
            raise CMDBuildConfigurationError("CMDBuild environment file does not exist")

        values: dict[str, str] = {}
        supported = {
            "CMDBUILD_BASE_URL",
            "CMDBUILD_USERNAME",
            "CMDBUILD_PASSWORD",
            "CMDBUILD_API_VERSION",
        }
        for line_number, line in enumerate(
            environment_path.read_text(encoding="utf-8-sig").splitlines(),
            start=1,
        ):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator:
                continue
            key = key.strip()
            if key not in supported:
                continue
            if key in values:
                raise CMDBuildConfigurationError(
                    f"Duplicate CMDBuild setting at line {line_number}: {key}"
                )
            values[key] = value

        required = {"CMDBUILD_BASE_URL", "CMDBUILD_USERNAME", "CMDBUILD_PASSWORD"}
        missing = sorted(key for key in required if not values.get(key))
        if missing:
            raise CMDBuildConfigurationError(
                "Missing required CMDBuild settings: " + ", ".join(missing)
            )

        return cls(
            base_url=values["CMDBUILD_BASE_URL"].strip().rstrip("/"),
            username=values["CMDBUILD_USERNAME"].strip(),
            password=values["CMDBUILD_PASSWORD"],
            api_version=values.get("CMDBUILD_API_VERSION", "v3").strip(),
        )


class CMDBuildClient:
    """Authenticated REST client with explicit metadata and business operations."""

    def __init__(
        self,
        settings: CMDBuildSettings,
        *,
        session: requests.Session | None = None,
    ) -> None:
        self.settings = settings
        self._session = session or requests.Session()
        self._session.trust_env = False
        self._token: str | None = None
        self._lookup_cache: dict[tuple[str, str], int] = {}

    @property
    def authenticated(self) -> bool:
        """Expose session state without exposing the authorization token."""

        return self._token is not None

    @staticmethod
    def _segment(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise CMDBuildResponseError("REST resource identifiers must not be empty")
        return quote(value, safe="")

    def _url(self, path: str) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise CMDBuildResponseError("REST endpoint must be an absolute local API path")
        if "?" in path or "#" in path or ".." in path.split("/"):
            raise CMDBuildResponseError("REST endpoint contains unsupported path components")
        return (
            f"{self.settings.base_url.rstrip('/')}"
            f"/services/rest/{self.settings.api_version}{path}"
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool = True,
        allow_empty: bool = False,
        **kwargs: Any,
    ) -> Any:
        if authenticated and not self.authenticated:
            raise CMDBuildAuthenticationError("CMDBuild session has not been authenticated")

        try:
            response = self._session.request(
                method,
                self._url(path),
                timeout=self.settings.timeout_seconds,
                allow_redirects=False,
                **kwargs,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            error_type = (
                CMDBuildAuthenticationError
                if not authenticated or getattr(exc.response, "status_code", None) in {401, 403}
                else CMDBuildResponseError
            )
            raise error_type(f"CMDBuild {method} request failed for {path}") from exc

        if allow_empty and (
            response.status_code == 204 or not getattr(response, "content", b"present")
        ):
            return None

        try:
            payload = response.json()
        except ValueError as exc:
            raise CMDBuildResponseError("CMDBuild returned an invalid JSON response") from exc

        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise CMDBuildResponseError("CMDBuild did not confirm a successful API response")
        if "data" not in payload:
            if allow_empty:
                return None
            raise CMDBuildResponseError("CMDBuild response is missing its data payload")
        return payload["data"]

    def authenticate(self) -> None:
        """Authenticate without returning or printing the service-session token."""

        if self.authenticated:
            raise CMDBuildAuthenticationError("CMDBuild session is already authenticated")

        data = self._request(
            "POST",
            "/sessions",
            authenticated=False,
            params={"scope": "service", "returnId": "true"},
            json={"username": self.settings.username, "password": self.settings.password},
        )
        token = data.get("_id") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token.strip() or token == "current":
            raise CMDBuildAuthenticationError("CMDBuild did not return a valid session token")

        self._token = token
        self._session.headers[AUTHORIZATION_HEADER] = token

    def close(self) -> None:
        """Close the authenticated server-side session and erase its local header."""

        try:
            if self.authenticated:
                self._request("DELETE", "/sessions/current", allow_empty=True)
        finally:
            self._token = None
            self._lookup_cache.clear()
            self._session.headers.pop(AUTHORIZATION_HEADER, None)
            self._session.close()

    def __enter__(self) -> CMDBuildClient:
        self.authenticate()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def class_attributes(self, class_id: str) -> list[dict[str, Any]]:
        """Return the attributes of one concrete READY2USE class."""

        data = self._request("GET", f"/classes/{self._segment(class_id)}/attributes")
        return self._require_list(data, "class attributes")

    def process_attributes(self, process_id: str) -> list[dict[str, Any]]:
        """Return the attributes of one workflow definition."""

        data = self._request("GET", f"/processes/{self._segment(process_id)}/attributes")
        return self._require_list(data, "process attributes")

    @staticmethod
    def _require_list(data: Any, resource: str) -> list[dict[str, Any]]:
        if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
            raise CMDBuildResponseError(f"CMDBuild {resource} response must contain a list")
        return data

    def lookup_values(self, lookup_type: str) -> list[dict[str, Any]]:
        """Read active lookup values without persisting installation-specific IDs."""

        path = f"/lookup_types/{self._segment(lookup_type)}/values"
        data = self._request("GET", path, params={"active": "true"})
        return self._require_list(data, "lookup values")

    def resolve_lookup(self, lookup_type: str, code: str) -> int:
        """Resolve a stable lookup code to this installation's ephemeral numeric ID."""

        if not isinstance(code, str) or not code.strip():
            raise CMDBuildResponseError("Lookup codes must not be empty")
        cache_key = (lookup_type, code)
        if cache_key in self._lookup_cache:
            return self._lookup_cache[cache_key]

        matches = [
            entry
            for entry in self.lookup_values(lookup_type)
            if entry.get("code") == code and entry.get("active", True) is not False
        ]
        if len(matches) != 1:
            raise CMDBuildResponseError(
                f"Expected one active lookup value for type '{lookup_type}' and code '{code}'"
            )

        identifier = matches[0].get("_id")
        if isinstance(identifier, str) and identifier.isdecimal():
            identifier = int(identifier)
        if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier <= 0:
            raise CMDBuildResponseError("Resolved lookup value has an invalid numeric identifier")

        self._lookup_cache[cache_key] = identifier
        return identifier

    def start_activities(self, process_id: str) -> list[dict[str, Any]]:
        """Normalize READY2USE start activities returned as either an object or a list."""

        data = self._request("GET", f"/processes/{self._segment(process_id)}/start_activities")
        if isinstance(data, dict):
            return [data]
        return self._require_list(data, "process start activities")

    @staticmethod
    def _require_identifier(data: Any, resource: str) -> int:
        candidate = data.get("_id") if isinstance(data, dict) else data
        if isinstance(candidate, str) and candidate.isdecimal():
            candidate = int(candidate)
        if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate <= 0:
            raise CMDBuildResponseError(
                f"CMDBuild {resource} response has an invalid numeric identifier"
            )
        return candidate

    def cards(self, class_id: str) -> list[dict[str, Any]]:
        """Return all cards required by the bounded synthetic population."""

        data = self._request(
            "GET",
            f"/classes/{self._segment(class_id)}/cards",
            params={"detailed": "true", "limit": 100000},
        )
        return self._require_list(data, "cards")

    def domain_relations(self, domain_id: str) -> list[dict[str, Any]]:
        """Return all relations for one configured domain."""

        data = self._request(
            "GET",
            f"/domains/{self._segment(domain_id)}/relations",
            params={"detailed": "true", "limit": 100000},
        )
        return self._require_list(data, "domain relations")

    def create_card(self, class_id: str, attributes: Mapping[str, Any]) -> int:
        """Create one card and return its installation-specific identifier."""

        data = self._request(
            "POST",
            f"/classes/{self._segment(class_id)}/cards",
            json=dict(attributes),
        )
        return self._require_identifier(data, "card creation")

    def delete_card(self, class_id: str, card_id: int) -> None:
        """Delete one card, used only by bounded rollback."""

        self._request(
            "DELETE",
            f"/classes/{self._segment(class_id)}/cards/{card_id}",
            allow_empty=True,
        )

    def create_relation(
        self,
        domain_id: str,
        source_type: str,
        source_id: int,
        destination_type: str,
        destination_id: int,
    ) -> int:
        """Create one relation using the physical domain direction."""

        data = self._request(
            "POST",
            f"/domains/{self._segment(domain_id)}/relations",
            json={
                "_type": domain_id,
                "_sourceType": source_type,
                "_sourceId": source_id,
                "_destinationType": destination_type,
                "_destinationId": destination_id,
            },
        )
        return self._require_identifier(data, "relation creation")

    def delete_relation(self, domain_id: str, relation_id: int) -> None:
        """Delete one relation, used only by bounded rollback."""

        self._request(
            "DELETE",
            f"/domains/{self._segment(domain_id)}/relations/{relation_id}",
            allow_empty=True,
        )
