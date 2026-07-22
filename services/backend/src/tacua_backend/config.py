# SPDX-License-Identifier: Apache-2.0

"""Mounted-file configuration for the self-hosted Tacua backend."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from types import ModuleType
import unicodedata
from typing import Any
from urllib.parse import urlsplit

from .contracts import ContractError as SDKContractError, validate as validate_sdk_artifact


ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
BUNDLE_ID_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62})+$"
)
DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
TRANSPORT_POLICY_VERSION = "tacua.sdk-transport@1.0.0"
MAX_CONFIG_BYTES = 2_097_152
MAX_CONFIG_JSON_NESTING_DEPTH = 64
MAX_ADMIN_SECRET_FILE_BYTES = 4_098
MAX_SAFE_INTEGER = 9_007_199_254_740_991
APPROVED_HANDOFF_KEYS = frozenset(
    {"build_identity", "authority", "registry_revision"}
)


def _load_approved_handoff_contract() -> ModuleType:
    repository_root = Path(__file__).resolve().parents[4]
    module_path = (
        repository_root
        / "contracts"
        / "approved-handoff"
        / "src"
        / "handoff_contract.py"
    )
    if not module_path.is_file():
        raise RuntimeError("Tacua approved-handoff validator is unavailable")
    specification = importlib.util.spec_from_file_location(
        "tacua_config_approved_handoff_contract", module_path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Tacua approved-handoff validator cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


APPROVED_HANDOFF_CONTRACT = _load_approved_handoff_contract()


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
    reviewer_id: str = "reviewer_owner"
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
    approved_handoff: dict[str, Any] | None = None

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
            "reviewer_id": self.reviewer_id,
            "bundle_identifier": self.bundle_identifier,
            "build_id": self.build_id,
            "build_identity_digest": self.build_identity_digest,
            "build_identity": self.build_identity,
            "approved_handoff": self.approved_handoff,
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


def _reject_json_float(_value: str) -> None:
    raise ConfigError("config file contains a floating-point number")


def _parse_json_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 16:
        raise ConfigError("config file contains an unsafe integer")
    result = int(value)
    if abs(result) > MAX_SAFE_INTEGER:
        raise ConfigError("config file contains an unsafe integer")
    return result


def _contains_unicode_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_json_strings(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        child, depth = stack.pop()
        if depth > MAX_CONFIG_JSON_NESTING_DEPTH:
            raise ConfigError("config file exceeds the safe JSON nesting depth")
        if isinstance(child, str):
            if _contains_unicode_surrogate(child):
                raise ConfigError("config file contains an invalid Unicode surrogate")
            if unicodedata.normalize("NFC", child) != child:
                raise ConfigError("config file contains non-NFC text")
        elif isinstance(child, list):
            stack.extend((item, depth + 1) for item in child)
        elif isinstance(child, dict):
            for key, item in child.items():
                if _contains_unicode_surrogate(key):
                    raise ConfigError(
                        "config file contains an invalid Unicode surrogate in an object key"
                    )
                if unicodedata.normalize("NFC", key) != key:
                    raise ConfigError("config file contains a non-NFC object key")
                stack.append((item, depth + 1))


def _parse_config_json(serialized: str) -> dict[str, Any]:
    if serialized.startswith("\ufeff"):
        raise ConfigError("config file must not contain a UTF-8 BOM")
    if _contains_unicode_surrogate(serialized):
        raise ConfigError("config file contains an invalid Unicode surrogate")
    if len(serialized.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ConfigError("config file exceeds the 2 MiB limit")
    try:
        raw = json.loads(
            serialized,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ConfigError("non-finite numbers are forbidden")
            ),
            parse_float=_reject_json_float,
            parse_int=_parse_json_integer,
        )
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file is not valid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise ConfigError("config file exceeds the safe JSON nesting depth") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config file root must be an object")
    _validate_json_strings(raw)
    return raw


def validate_approved_handoff_config(config: PilotConfig) -> None:
    approved_handoff = config.approved_handoff
    if not isinstance(approved_handoff, dict):
        raise ConfigError("approved_handoff must be an object")
    if set(approved_handoff) != APPROVED_HANDOFF_KEYS:
        raise ConfigError(
            "approved_handoff must contain exactly build_identity, authority, and registry_revision"
        )

    build_identity = approved_handoff["build_identity"]
    authority = approved_handoff["authority"]
    registry_revision = approved_handoff["registry_revision"]
    if not isinstance(registry_revision, str) or not ID_PATTERN.fullmatch(
        registry_revision
    ):
        raise ConfigError("approved_handoff.registry_revision is not a Tacua identifier")
    if unicodedata.normalize("NFC", registry_revision) != registry_revision:
        raise ConfigError("approved_handoff.registry_revision must be NFC-normalized")

    try:
        validate_sdk_artifact(config.build_identity)
        if config.build_identity.get("message_type") != "build_identity":
            raise ConfigError("build_identity must have message_type build_identity")
        APPROVED_HANDOFF_CONTRACT.validate_build_identity(build_identity)
        APPROVED_HANDOFF_CONTRACT.validate_authority(authority)
    except (SDKContractError, APPROVED_HANDOFF_CONTRACT.ContractError) as exc:
        raise ConfigError(
            "approved_handoff must contain a valid sealed build identity and authority"
        ) from exc

    sdk_build = config.build_identity
    distribution = {
        "local": "local-development",
        "internal": "internal",
        "testflight": "testflight",
    }.get(sdk_build["distribution"])
    mobile = build_identity["mobile"]
    if (
        distribution is None
        or sdk_build["source"]["working_tree_dirty"] is not False
        or build_identity["organization_id"] != config.organization_id
        or build_identity["project_id"] != config.project_id
        or build_identity["build_id"] != sdk_build["build_id"]
        or mobile["platform"] != sdk_build["platform"]
        or mobile["application_id"] != sdk_build["bundle_identifier"]
        or mobile["app_version"] != sdk_build["native_version"]
        or mobile["build_number"] != sdk_build["native_build"]
        or mobile["distribution"] != distribution
        or mobile["source"]["revision"] != sdk_build["source"]["git_revision"]
        or mobile["source"]["dirty"] is not False
        or sdk_build["transport_configuration_digest"]
        != config.transport_configuration_digest
        or build_identity["sdk"]["configuration_digest"]
        != config.transport_configuration_digest
    ):
        raise ConfigError(
            "approved_handoff build identity does not match the configured SDK build and transport"
        )

    source_repositories = {mobile["source"]["repository_id"]}
    if build_identity["backend"]["availability"] == "available":
        source_repositories.update(
            source["repository_id"] for source in build_identity["backend"]["sources"]
        )
    if not source_repositories <= set(authority["allowed_repositories"]):
        raise ConfigError(
            "approved_handoff authority does not cover every configured source repository"
        )


def _config_from_document(raw: dict[str, Any]) -> PilotConfig:
    """Validate one already strict-decoded public configuration document."""

    allowed_keys = {
        "organization_id",
        "project_id",
        "application_id",
        "reviewer_id",
        "build_identity",
        "approved_handoff",
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
    reviewer_id = _required_text(raw, "reviewer_id", 64)
    if not ID_PATTERN.fullmatch(reviewer_id):
        raise ConfigError("reviewer_id does not match the Tacua identifier format")
    build_identity = raw.get("build_identity")
    if not isinstance(build_identity, dict):
        raise ConfigError("build_identity must be the full sealed SDK protocol artifact")
    approved_handoff = raw.get("approved_handoff")
    if not isinstance(approved_handoff, dict):
        raise ConfigError("approved_handoff must be an object")
    policy = str(raw.get("transport_policy_version", TRANSPORT_POLICY_VERSION))
    if policy != TRANSPORT_POLICY_VERSION:
        raise ConfigError(f"transport_policy_version must be {TRANSPORT_POLICY_VERSION}")

    state_directory = Path(_required_text(raw, "state_directory", 4096))
    if not state_directory.is_absolute() or state_directory == Path(state_directory.anchor):
        raise ConfigError("state_directory must be an absolute non-root path")

    raw_days = _bounded_int(raw, "raw_retention_days", 30, 1, 30)
    derived_days = _bounded_int(raw, "derived_retention_days", 30, 1, 30)
    if raw_days != derived_days:
        raise ConfigError(
            "V1 raw and derived retention periods must use one session boundary"
        )
    config = PilotConfig(
        **ids,
        reviewer_id=reviewer_id,
        build_identity=json.loads(_canonical_json(build_identity)),
        approved_handoff=json.loads(_canonical_json(approved_handoff)),
        consent_contract=_required_text(raw, "consent_contract", 128),
        backend_origin=normalize_backend_origin(_required_text(raw, "backend_origin", 2048)),
        state_directory=state_directory,
        listen_host=_required_text(
            {"listen_host": raw.get("listen_host", "127.0.0.1")},
            "listen_host",
            255,
        ),
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
    validate_approved_handoff_config(config)
    return config


def parse_config_text(serialized: str) -> PilotConfig:
    """Parse public config with the exact validation used by backend startup."""

    if not isinstance(serialized, str):
        raise ConfigError("config file must be UTF-8 text")
    return _config_from_document(_parse_config_json(serialized))


def load_public_config(config_file: Path) -> PilotConfig:
    """Load only public configuration; this never reads secrets or opens state."""

    try:
        with config_file.open("rb") as stream:
            payload = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot load config file: {exc}") from exc
    if len(payload) > MAX_CONFIG_BYTES:
        raise ConfigError("config file exceeds the 2 MiB limit")
    try:
        serialized = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ConfigError("config file must be strict UTF-8") from exc
    return parse_config_text(serialized)


def parse_admin_secret(payload: bytes) -> bytes:
    """Validate one bounded mounted administrator secret payload."""

    if not isinstance(payload, bytes) or len(payload) > MAX_ADMIN_SECRET_FILE_BYTES:
        raise ConfigError("admin secret file exceeds the 4098-byte limit")
    secret = payload.rstrip(b"\r\n")
    if not 32 <= len(secret) <= 4096:
        raise ConfigError("admin secret must contain from 32 through 4096 bytes")
    try:
        secret_text = secret.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConfigError("admin secret must be an ASCII RFC 7235 token68 value") from exc
    if re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", secret_text) is None:
        raise ConfigError(
            "admin secret must be an ASCII RFC 7235 token68 value with padding only at the end"
        )
    return secret


def load_admin_secret(admin_secret_file: Path) -> bytes:
    """Read the mounted administrator secret without an unbounded allocation."""

    try:
        with admin_secret_file.open("rb") as stream:
            payload = stream.read(MAX_ADMIN_SECRET_FILE_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot load admin secret file: {exc}") from exc
    return parse_admin_secret(payload)


def load_config(config_file: Path, admin_secret_file: Path) -> tuple[PilotConfig, bytes]:
    """Load public configuration and the administrator/verifier root secret."""

    config = load_public_config(config_file)

    return config, load_admin_secret(admin_secret_file)
