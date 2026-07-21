"""Mounted-file configuration for the Tacua pilot backend."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any


ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
BUNDLE_ID_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62})+$"
)
DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


class ConfigError(ValueError):
    """Raised when mounted runtime configuration is invalid."""


@dataclass(frozen=True)
class PilotConfig:
    organization_id: str
    project_id: str
    application_id: str
    bundle_identifier: str
    build_id: str
    build_identity_digest: str
    consent_contract: str
    state_directory: Path
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    launch_code_ttl_seconds: int = 300
    upload_token_ttl_seconds: int = 3600
    max_segment_bytes: int = 268_435_456
    max_diagnostic_bytes: int = 1_048_576
    raw_retention_days: int = 30

    @property
    def scope(self) -> dict[str, str]:
        return {
            "organization_id": self.organization_id,
            "project_id": self.project_id,
            "application_id": self.application_id,
            "bundle_identifier": self.bundle_identifier,
            "build_id": self.build_id,
            "build_identity_digest": self.build_identity_digest,
            "consent_contract": self.consent_contract,
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
    return value


def load_config(config_file: Path, admin_secret_file: Path) -> tuple[PilotConfig, bytes]:
    """Load all runtime configuration from mounted files.

    Environment variables are deliberately not used for credentials.  The
    secret file may contain one trailing line ending, which is discarded.
    """

    try:
        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ConfigError("config file contains a duplicate object key")
                result[key] = value
            return result

        raw = json.loads(
            config_file.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot load config file: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config file root must be an object")
    allowed_keys = {
        "organization_id",
        "project_id",
        "application_id",
        "bundle_identifier",
        "build_id",
        "build_identity_digest",
        "consent_contract",
        "state_directory",
        "listen_host",
        "listen_port",
        "launch_code_ttl_seconds",
        "upload_token_ttl_seconds",
        "max_segment_bytes",
        "max_diagnostic_bytes",
        "raw_retention_days",
    }
    unknown = sorted(set(raw) - allowed_keys)
    if unknown:
        raise ConfigError("config file contains unknown keys")

    ids: dict[str, str] = {}
    for key in ("organization_id", "project_id", "application_id", "build_id"):
        value = _required_text(raw, key, 64)
        if not ID_PATTERN.fullmatch(value):
            raise ConfigError(f"{key} does not match the Tacua identifier format")
        ids[key] = value
    bundle_identifier = _required_text(raw, "bundle_identifier", 255)
    if not BUNDLE_ID_PATTERN.fullmatch(bundle_identifier):
        raise ConfigError("bundle_identifier must be a reverse-DNS application identifier")
    build_identity_digest = _required_text(raw, "build_identity_digest", 71)
    if not DIGEST_PATTERN.fullmatch(build_identity_digest):
        raise ConfigError("build_identity_digest must be a lowercase SHA-256 digest")

    state_text = _required_text(raw, "state_directory", 4096)
    state_directory = Path(state_text)
    if not state_directory.is_absolute():
        raise ConfigError("state_directory must be absolute")
    if state_directory == Path(state_directory.anchor):
        raise ConfigError("state_directory must not be a filesystem root")

    retention_days = _bounded_int(raw, "raw_retention_days", 30, 1, 30)
    config = PilotConfig(
        **ids,
        bundle_identifier=bundle_identifier,
        build_identity_digest=build_identity_digest,
        consent_contract=_required_text(raw, "consent_contract", 128),
        state_directory=state_directory,
        listen_host=str(raw.get("listen_host", "127.0.0.1")),
        listen_port=_bounded_int(raw, "listen_port", 8080, 1, 65535),
        launch_code_ttl_seconds=_bounded_int(raw, "launch_code_ttl_seconds", 300, 30, 3600),
        upload_token_ttl_seconds=_bounded_int(raw, "upload_token_ttl_seconds", 3600, 300, 86400),
        max_segment_bytes=_bounded_int(raw, "max_segment_bytes", 268_435_456, 1, 1_073_741_824),
        max_diagnostic_bytes=_bounded_int(raw, "max_diagnostic_bytes", 1_048_576, 1024, 16_777_216),
        raw_retention_days=retention_days,
    )

    try:
        secret = admin_secret_file.read_bytes().rstrip(b"\r\n")
    except OSError as exc:
        raise ConfigError(f"cannot load admin secret file: {exc}") from exc
    if len(secret) < 32:
        raise ConfigError("admin secret must contain at least 32 bytes")
    if len(secret) > 4096:
        raise ConfigError("admin secret is unexpectedly large")
    return config, secret
