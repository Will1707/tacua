# SPDX-License-Identifier: Apache-2.0

"""Compile a secret-free operator template into sealed Tacua backend config."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Sequence

from .config import (
    APPROVED_HANDOFF_CONTRACT,
    MAX_CONFIG_BYTES,
    TRANSPORT_POLICY_VERSION,
    ConfigError,
    _parse_config_json,
    normalize_backend_origin,
    parse_config_text,
)
from .contracts import ContractError, canonical_json, digest, seal


DERIVE_MARKER = "__TACUA_DERIVE_SHA256__"
SDK_PROFILE_CONTRACT = "tacua.sdk-profile@1.0.0"
SCOPE_POLICY_CONTRACT = "tacua.capture-scope-policy@1.0.0"
RETENTION_POLICY_VERSION = "tacua.retention-v1"
DERIVED_PATHS = (
    ("build_identity", "transport_configuration_digest"),
    ("build_identity", "build_identity_digest"),
    ("approved_handoff", "build_identity", "sdk", "configuration_digest"),
    ("approved_handoff", "build_identity", "build_identity_digest"),
)
FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "access_token",
        "admin_secret",
        "api_key",
        "authorization",
        "client_secret",
        "cookie",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "session_cookie",
        "token",
    }
)


class ConfigToolError(ConfigError):
    """Stable content-free operator-tool failure."""


def _walk_forbidden_keys(value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _walk_forbidden_keys(item)
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        if key.casefold().replace("-", "_") in FORBIDDEN_SECRET_KEYS:
            raise ConfigToolError("configuration templates must not contain secrets")
        _walk_forbidden_keys(item)


def _object_at(document: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    current: Any = document
    for component in path:
        if not isinstance(current, dict) or component not in current:
            raise ConfigToolError("configuration template is missing a derived field marker")
        current = current[component]
    if not isinstance(current, dict):
        raise ConfigToolError("configuration template has an invalid derived field parent")
    return current


def _require_derive_markers(document: dict[str, Any]) -> None:
    for path in DERIVED_PATHS:
        parent = _object_at(document, path[:-1])
        if parent.get(path[-1]) != DERIVE_MARKER:
            raise ConfigToolError(
                "every derived digest field must contain the Tacua derive marker"
            )


def _reject_remaining_markers(value: Any) -> None:
    if value == DERIVE_MARKER:
        raise ConfigToolError("configuration template contains an unexpected derive marker")
    if isinstance(value, list):
        for item in value:
            _reject_remaining_markers(item)
    elif isinstance(value, dict):
        for item in value.values():
            _reject_remaining_markers(item)


def render_config(document: dict[str, Any]) -> str:
    """Render stable public JSON; digest sealing itself always uses canonical JSON."""

    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
    ) + "\n"


def render_sdk_profile(document: dict[str, Any]) -> str:
    """Render the exact UTF-8 bytes consumed by the Expo config plugin."""

    # Unlike the operator-facing config, this artifact is deliberately one
    # canonical line. That makes duplicate keys, alternate whitespace, stale
    # field order, and post-generation edits detectable by every consumer.
    return canonical_json(document) + "\n"


def derive_sdk_profile(config: Any) -> dict[str, Any]:
    """Project one validated backend deployment pin into public SDK data."""

    scope_policy = {
        "contract_version": SCOPE_POLICY_CONTRACT,
        "protocol_version": config.build_identity["protocol_version"],
        "organization_id": config.organization_id,
        "project_id": config.project_id,
        "application_id": config.application_id,
        "build_id": config.build_id,
        "build_identity_digest": config.build_identity_digest,
        "capture_scope": "app_only",
        "consent": {
            "policy_version": config.consent_contract,
            "screen_recording": "required",
            "microphone": "required",
            "diagnostics": "required",
            "raw_media_upload": "required",
        },
        "retention": {
            "policy_version": RETENTION_POLICY_VERSION,
            "raw_media_days": config.raw_retention_days,
            "derived_data_days": config.derived_retention_days,
        },
    }
    subject = {
        "contract_version": SDK_PROFILE_CONTRACT,
        "backend_origin": config.backend_origin,
        "transport_configuration": config.transport_configuration,
        "transport_configuration_digest": config.transport_configuration_digest,
        "build_identity": copy.deepcopy(config.build_identity),
        "capture_scope_policy": scope_policy,
    }
    return {**subject, "profile_digest": digest(subject)}


def compile_config_artifacts(serialized: str) -> tuple[str, str]:
    """Compile a backend config and its exact, secret-free SDK projection."""

    rendered_config = compile_config_template(serialized)
    config = parse_config_text(rendered_config)
    return rendered_config, render_sdk_profile(derive_sdk_profile(config))


def compile_config_template(serialized: str) -> str:
    """Seal all derived config digests and run the backend startup parser."""

    template = _parse_config_json(serialized)
    _walk_forbidden_keys(template)
    _require_derive_markers(template)
    document = copy.deepcopy(template)

    backend_origin = document.get("backend_origin")
    if not isinstance(backend_origin, str):
        raise ConfigToolError("backend_origin must be text")
    normalized_origin = normalize_backend_origin(backend_origin)
    document["backend_origin"] = normalized_origin
    policy = document.get("transport_policy_version", TRANSPORT_POLICY_VERSION)
    if policy != TRANSPORT_POLICY_VERSION:
        raise ConfigToolError(
            f"transport_policy_version must be {TRANSPORT_POLICY_VERSION}"
        )
    transport_digest = digest(
        {
            "backend_origin": normalized_origin,
            "transport_policy_version": policy,
        }
    )

    build_identity = document.get("build_identity")
    approved_handoff = document.get("approved_handoff")
    if not isinstance(build_identity, dict) or not isinstance(approved_handoff, dict):
        raise ConfigToolError("configuration template is missing build identity data")
    handoff_build = approved_handoff.get("build_identity")
    if not isinstance(handoff_build, dict) or not isinstance(handoff_build.get("sdk"), dict):
        raise ConfigToolError("configuration template is missing handoff build identity data")

    build_identity["transport_configuration_digest"] = transport_digest
    handoff_build["sdk"]["configuration_digest"] = transport_digest
    try:
        document["build_identity"] = seal(build_identity)
        approved_handoff["build_identity"] = (
            APPROVED_HANDOFF_CONTRACT.seal_build_identity(handoff_build)
        )
    except (ContractError, APPROVED_HANDOFF_CONTRACT.ContractError) as exc:
        raise ConfigToolError("configuration template cannot be sealed") from exc

    _reject_remaining_markers(document)
    rendered = render_config(document)
    # This is the same public parser called by backend startup. It validates
    # the complete cross-artifact pin without reading a secret or opening state.
    parse_config_text(rendered)
    return rendered


def _read_bounded_utf8(path: Path, label: str) -> str:
    try:
        with path.open("rb") as stream:
            payload = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigToolError(f"cannot read {label}") from exc
    if len(payload) > MAX_CONFIG_BYTES:
        raise ConfigToolError(f"{label} exceeds the 2 MiB limit")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ConfigToolError(f"{label} must be strict UTF-8") from exc


def _write_public_artifact(path: Path, rendered: str, label: str) -> None:
    parent = path.parent
    if not parent.is_dir():
        raise ConfigToolError("output directory does not exist")
    temporary_path: Path | None = None
    replaced = False
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            dir=parent,
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(rendered.encode("utf-8"))
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        replaced = True
        directory_descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        if replaced:
            raise ConfigToolError(
                f"cannot durably publish {label}"
            ) from exc
        raise ConfigToolError(f"cannot write {label}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _write_public_config(path: Path, rendered: str) -> None:
    _write_public_artifact(path, rendered, "sealed config output")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compile a secret-free Tacua backend config template",
    )
    parser.add_argument("template", type=Path, help="human-editable public template JSON")
    parser.add_argument("--output", type=Path, help="sealed public config path (stdout when omitted)")
    parser.add_argument(
        "--sdk-profile-output",
        type=Path,
        help="canonical public SDK profile path (requires --output)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate only; with --output, require exact generated bytes without writing",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.sdk_profile_output is not None and args.output is None:
            raise ConfigToolError("--sdk-profile-output requires --output")
        paths = [args.template]
        if args.output is not None:
            paths.append(args.output)
        if args.sdk_profile_output is not None:
            paths.append(args.sdk_profile_output)
        for index, left in enumerate(paths):
            for right in paths[index + 1 :]:
                same_path = left.resolve(strict=False) == right.resolve(strict=False)
                if not same_path and left.exists() and right.exists():
                    try:
                        same_path = left.samefile(right)
                    except OSError:
                        same_path = False
                if same_path:
                    raise ConfigToolError("template and generated outputs must use different files")
        rendered, sdk_profile = compile_config_artifacts(
            _read_bounded_utf8(args.template, "template")
        )
        if args.check:
            if args.output is not None:
                current = _read_bounded_utf8(args.output, "sealed config")
                if current != rendered:
                    raise ConfigToolError("sealed config is not up to date with its template")
            if args.sdk_profile_output is not None:
                current_profile = _read_bounded_utf8(
                    args.sdk_profile_output,
                    "SDK profile",
                )
                if current_profile != sdk_profile:
                    raise ConfigToolError("SDK profile is not up to date with its template")
            print("Tacua backend configuration is valid and up to date.", file=sys.stderr)
            return 0
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            _write_public_config(args.output, rendered)
            if args.sdk_profile_output is not None:
                _write_public_artifact(
                    args.sdk_profile_output,
                    sdk_profile,
                    "SDK profile output",
                )
        return 0
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
