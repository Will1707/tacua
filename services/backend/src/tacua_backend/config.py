"""Mounted-file configuration for the self-hosted Tacua backend."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import unicodedata
from typing import Any
from urllib.parse import urlsplit


ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
BUNDLE_ID_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62})+$"
)
DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
TRANSPORT_POLICY_VERSION = "tacua.sdk-transport@1.0.0"


class ConfigError(ValueError):
    """Raised when mounted runtime configuration is invalid."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def normalize_backend_origin(value: str) -> str:
    """Return the exact normalized origin required by the V1 transport ADR."""

    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ConfigError("backend_origin must be a non-empty origin")
    if unicodedata.normalize("NFC", value) != value:
        raise ConfigError("backend_origin must be NFC-normalized")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("backend_origin is invalid") from exc
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else ""
    if scheme not in {"http", "https"} or not host:
        raise ConfigError("backend_origin must use http or https and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("backend_origin must not contain user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ConfigError("backend_origin must not contain a path, query, or fragment")
    if scheme == "http" and host not in {"127.0.0.1", "::1", "localhost"}:
        raise ConfigError("http backend_origin is allowed only for loopback development")
    try:
        host.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ConfigError("backend_origin host must use ASCII or punycode") from exc
    if "%" in host:
        raise ConfigError("backend_origin host must not contain percent escapes")
    if ":" in host and not host.startswith("["):
        authority = f"[{host}]"
    else:
        authority = host
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        authority = f"{authority}:{port}"
    return f"{scheme}://{authority}"


@dataclass(frozen=True)
class PilotConfig:
    organization_id: str
    project_id: str
    application_id: str
    build_identity: dict[str, Any]
    consent_contract: str
    backend_origin: str
    state_directory: Path
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    launch_code_ttl_seconds: int = 300
    credential_ttl_seconds: int = 2_592_000
    max_segment_bytes: int = 268_435_456
    max_diagnostic_bytes: int = 16_777_216
    max_completion_bytes: int = 16_777_216
    raw_retention_days: int = 30
    derived_retention_days: int = 30
    tombstone_retention_days: int = 30
    retention_sweep_interval_seconds: int = 300
    transport_policy_version: str = TRANSPORT_POLICY_VERSION

    @property
    def bundle_identifier(self) -> str:
        value = self.build_identity.get("bundle_identifier")
        return value if isinstance(value, str) else ""

    @property
    def build_id(self) -> str:
        value = self.build_identity.get("build_id")
        return value if isinstance(value, str) else ""

    @property
    def build_identity_digest(self) -> str:
        value = self.build_identity.get("build_identity_digest")
        return value if isinstance(value, str) else ""

    @property
    def transport_configuration(self) -> dict[str, str]:
        return {
            "backend_origin": self.backend_origin,
            "transport_policy_version": self.transport_policy_version,
        }

    @property
    def transport_configuration_digest(self) -> str:
        return _digest(self.transport_configuration)

    @property
    def deployment_pin(self) -> dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "project_id": self.project_id,
            "application_id": self.application_id,
            "bundle_identifier": self.bundle_identifier,
            "build_id": self.build_id,
            "build_identity_digest": self.build_identity_digest,
            "build_identity": self.build_identity,
            "consent_contract": self.consent_contract,
            "raw_retention_days": self.raw_retention_days,
            "derived_retention_days": self.derived_retention_days,
            "transport_configuration": self.transport_configuration,
            "transport_configuration_digest": self.transport_configuration_digest,
        }


def _bounded_int(data: dict[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{key} must be an integer from {low} through {high}")
    return value


def _required_text(data: dict[str, Any], key: str, maximum: int = 128) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ConfigError(f"{key} must be non-empty text no longer than {maximum} characters")
    if unicodedata.normalize("NFC", value) != value:
        raise ConfigError(f"{key} must be NFC-normalized")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("config file contains a duplicate object key")
        result[key] = value
    return result


def load_config(config_file: Path, admin_secret_file: Path) -> tuple[PilotConfig, bytes]:
    """Load public configuration and the administrator/verifier root secret."""

    try:
        raw = json.loads(
            config_file.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ConfigError("non-finite numbers are forbidden")),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot load config file: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config file root must be an object")
    allowed_keys = {
        "organization_id",
        "project_id",
        "application_id",
        "build_identity",
        "consent_contract",
        "backend_origin",
        "transport_policy_version",
        "state_directory",
        "listen_host",
        "listen_port",
        "launch_code_ttl_seconds",
        "credential_ttl_seconds",
        "max_segment_bytes",
        "max_diagnostic_bytes",
        "max_completion_bytes",
        "raw_retention_days",
        "derived_retention_days",
        "tombstone_retention_days",
        "retention_sweep_interval_seconds",
    }
    if sorted(set(raw) - allowed_keys):
        raise ConfigError("config file contains unknown keys")

    ids: dict[str, str] = {}
    for key in ("organization_id", "project_id", "application_id"):
        value = _required_text(raw, key, 64)
        if not ID_PATTERN.fullmatch(value):
            raise ConfigError(f"{key} does not match the Tacua identifier format")
        ids[key] = value
    build_identity = raw.get("build_identity")
    if not isinstance(build_identity, dict):
        raise ConfigError("build_identity must be the full sealed SDK protocol artifact")
    policy = str(raw.get("transport_policy_version", TRANSPORT_POLICY_VERSION))
    if policy != TRANSPORT_POLICY_VERSION:
        raise ConfigError(f"transport_policy_version must be {TRANSPORT_POLICY_VERSION}")

    state_directory = Path(_required_text(raw, "state_directory", 4096))
    if not state_directory.is_absolute() or state_directory == Path(state_directory.anchor):
        raise ConfigError("state_directory must be an absolute non-root path")

    raw_days = _bounded_int(raw, "raw_retention_days", 30, 1, 30)
    derived_days = _bounded_int(raw, "derived_retention_days", 30, 1, 30)
    config = PilotConfig(
        **ids,
        build_identity=json.loads(_canonical_json(build_identity)),
        consent_contract=_required_text(raw, "consent_contract", 128),
        backend_origin=normalize_backend_origin(_required_text(raw, "backend_origin", 2048)),
        state_directory=state_directory,
        listen_host=str(raw.get("listen_host", "127.0.0.1")),
        listen_port=_bounded_int(raw, "listen_port", 8080, 1, 65535),
        launch_code_ttl_seconds=_bounded_int(raw, "launch_code_ttl_seconds", 300, 30, 3600),
        credential_ttl_seconds=_bounded_int(raw, "credential_ttl_seconds", 2_592_000, 300, 2_592_000),
        max_segment_bytes=_bounded_int(raw, "max_segment_bytes", 268_435_456, 1, 1_073_741_824),
        max_diagnostic_bytes=_bounded_int(raw, "max_diagnostic_bytes", 16_777_216, 1024, 16_777_216),
        max_completion_bytes=_bounded_int(raw, "max_completion_bytes", 16_777_216, 1024, 67_108_864),
        raw_retention_days=raw_days,
        derived_retention_days=derived_days,
        tombstone_retention_days=_bounded_int(raw, "tombstone_retention_days", 30, 1, 30),
        retention_sweep_interval_seconds=_bounded_int(raw, "retention_sweep_interval_seconds", 300, 30, 3600),
        transport_policy_version=policy,
    )

    try:
        secret = admin_secret_file.read_bytes().rstrip(b"\r\n")
    except OSError as exc:
        raise ConfigError(f"cannot load admin secret file: {exc}") from exc
    if not 32 <= len(secret) <= 4096:
        raise ConfigError("admin secret must contain from 32 through 4096 bytes")
    try:
        secret_text = secret.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError("admin secret must be a UTF-8 bearer token") from exc
    if any(character.isspace() for character in secret_text):
        raise ConfigError("admin secret must not contain whitespace")
    return config, secret
