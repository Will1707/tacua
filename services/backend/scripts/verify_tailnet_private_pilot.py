#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the closed single-owner Tailscale Serve private-pilot topology."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Sequence


BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from tacua_backend.config import ConfigError, load_public_config  # noqa: E402
from tacua_backend.operator_tool import (  # noqa: E402
    OperatorError,
    deployment_preflight,
    validate_compose_document,
)


MAX_STATUS_BYTES = 2 * 1024 * 1024
EXPECTED_PROXY = "http://127.0.0.1:8080"
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class TailnetPilotError(ValueError):
    """Stable, content-free private-pilot validation failure."""


def _require(condition: bool, detail: str) -> None:
    if not condition:
        raise TailnetPilotError(detail)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TailnetPilotError("status JSON contains a duplicate object key")
        value[key] = item
    return value


def _validate_private_input_directory(directory: Path, label: str) -> None:
    try:
        resolved = directory.resolve(strict=True)
    except OSError as exc:
        raise TailnetPilotError(f"cannot inspect {label} parent") from exc

    lexical = Path(os.path.abspath(directory))
    current = Path(lexical.anchor)
    lexical_parts = lexical.parts[1:]
    for index, part in enumerate(lexical_parts):
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise TailnetPilotError(f"cannot inspect {label} parent") from exc
        leaf = index == len(lexical_parts) - 1
        permissions = stat.S_IMODE(metadata.st_mode)
        owner_allowed = metadata.st_uid in {0, os.geteuid()}
        sticky_writable = (
            permissions & 0o022
            and permissions & stat.S_ISVTX
            and owner_allowed
        )
        if stat.S_ISLNK(metadata.st_mode):
            _require(
                not leaf and metadata.st_uid == 0,
                f"{label} parent contains an unsafe lexical symlink",
            )
            continue
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and owner_allowed
            and (
                permissions == 0o700
                if leaf
                else not (permissions & 0o022 and not sticky_writable)
            ),
            f"{label} parent has an unsafe lexical ancestor",
        )

    current = resolved
    leaf = True
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise TailnetPilotError(f"cannot inspect {label} parent") from exc
        permissions = stat.S_IMODE(metadata.st_mode)
        owner_allowed = metadata.st_uid in {0, os.geteuid()}
        sticky_writable = (
            permissions & 0o022
            and permissions & stat.S_ISVTX
            and owner_allowed
        )
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and owner_allowed
            and (
                permissions == 0o700
                if leaf
                else not (permissions & 0o022 and not sticky_writable)
            ),
            f"{label} parent has an unsafe resolved ancestor",
        )
        if current.parent == current:
            break
        current = current.parent
        leaf = False


def _load_status_json(path: Path, label: str) -> dict[str, Any]:
    _validate_private_input_directory(path.parent, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        flags |= no_follow
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TailnetPilotError(f"cannot read {label}") from exc
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_uid in {0, os.geteuid()},
            f"{label} must be one private operator-owned regular file",
        )
        chunks: list[bytes] = []
        remaining = MAX_STATUS_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
        _require(
            (
                final_metadata.st_dev,
                final_metadata.st_ino,
                final_metadata.st_size,
                final_metadata.st_mtime_ns,
                final_metadata.st_nlink,
                stat.S_IMODE(final_metadata.st_mode),
                final_metadata.st_uid,
            )
            == (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_nlink,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_uid,
            ),
            f"{label} changed while it was read",
        )
    finally:
        os.close(descriptor)
    if len(payload) > MAX_STATUS_BYTES:
        raise TailnetPilotError(f"{label} exceeds the 2 MiB limit")
    try:
        decoded = payload.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                TailnetPilotError("status JSON contains a non-finite number")
            ),
        )
    except UnicodeDecodeError as exc:
        raise TailnetPilotError(f"{label} must be strict UTF-8") from exc
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise TailnetPilotError(f"{label} must be valid JSON") from exc
    _require(isinstance(value, dict), f"{label} must contain one JSON object")
    return value


def _normalized_dns_name(value: Any, label: str, *, minimum_labels: int) -> str:
    _require(isinstance(value, str), f"{label} must be text")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TailnetPilotError(f"{label} must use ASCII DNS syntax") from exc
    normalized = value[:-1] if value.endswith(".") else value
    _require(
        normalized == normalized.lower() and len(normalized) <= 253,
        f"{label} must be a normalized lowercase DNS name",
    )
    labels = normalized.split(".")
    _require(
        len(labels) >= minimum_labels
        and all(DNS_LABEL.fullmatch(item) for item in labels),
        f"{label} must be a valid tailnet DNS name",
    )
    _require(normalized.endswith(".ts.net"), f"{label} must end in .ts.net")
    return normalized


def _validate_tailnet_status(status_document: dict[str, Any]) -> str:
    _require(
        status_document.get("BackendState") == "Running",
        "Tailscale backend must be running",
    )
    self_status = status_document.get("Self")
    _require(isinstance(self_status, dict), "Tailscale status has no Self object")
    _require(self_status.get("Online") is True, "Tailscale node must be online")
    current_tailnet = status_document.get("CurrentTailnet")
    _require(
        isinstance(current_tailnet, dict)
        and current_tailnet.get("MagicDNSEnabled") is True,
        "MagicDNS must be enabled for the active tailnet",
    )

    dns_name = _normalized_dns_name(
        self_status.get("DNSName"),
        "Tailscale DNSName",
        minimum_labels=4,
    )
    suffix = _normalized_dns_name(
        status_document.get("MagicDNSSuffix"),
        "Tailscale MagicDNSSuffix",
        minimum_labels=3,
    )
    current_suffix = _normalized_dns_name(
        current_tailnet.get("MagicDNSSuffix"),
        "active tailnet MagicDNSSuffix",
        minimum_labels=3,
    )
    _require(
        current_suffix == suffix,
        "active tailnet MagicDNS suffix must match Tailscale status",
    )
    _require(
        dns_name.endswith(f".{suffix}") and dns_name != suffix,
        "Tailscale DNSName must be inside the active MagicDNS suffix",
    )
    certificate_domains = status_document.get("CertDomains")
    _require(
        isinstance(certificate_domains, list)
        and certificate_domains
        and all(isinstance(item, str) for item in certificate_domains),
        "Tailscale HTTPS certificate domains must be available",
    )
    _require(
        dns_name in {
            _normalized_dns_name(
                item,
                "Tailscale certificate domain",
                minimum_labels=4,
            )
            for item in certificate_domains
        },
        "Tailscale HTTPS certificate does not cover the node DNS name",
    )
    return dns_name


def _validate_serve_status(
    serve_document: dict[str, Any],
    dns_name: str,
) -> None:
    if serve_document.get("AllowFunnel") is True:
        raise TailnetPilotError("Tailscale Funnel must remain disabled")
    _require(
        set(serve_document) == {"TCP", "Web"},
        "Serve must contain only the private HTTPS listener and web handler",
    )
    _require(
        serve_document.get("TCP") == {"443": {"HTTPS": True}},
        "Serve must expose one HTTPS listener on port 443",
    )
    _require(
        serve_document.get("Web")
        == {
            f"{dns_name}:443": {
                "Handlers": {
                    "/": {
                        "Proxy": EXPECTED_PROXY,
                    }
                }
            }
        },
        "Serve must proxy only the root path to Tacua on host loopback",
    )


def validate_empty_serve_status(serve_document: dict[str, Any]) -> dict[str, str]:
    """Refuse to mutate a host whose Tailscale Serve configuration is occupied."""

    _require(
        serve_document == {},
        "Serve configuration is not empty; do not replace an existing listener",
    )
    return {"serve": "empty", "status": "ok"}


def inspect_tailnet_identity(
    tailscale_status: dict[str, Any],
) -> dict[str, str]:
    """Return only the non-secret HTTPS origin needed to seal the pilot."""

    dns_name = _validate_tailnet_status(tailscale_status)
    return {"origin": f"https://{dns_name}", "status": "ok"}


def _validate_private_pilot_base(
    config: Any,
    compose_document: dict[str, Any],
    tailscale_status: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Validate identity, sealed origin, and the exact mutable Compose candidate."""

    services = compose_document.get("services")
    backend = services.get("backend") if isinstance(services, dict) else None
    _require(
        isinstance(backend, dict)
        and backend.get("image") == "tacua-backend:local"
        and isinstance(backend.get("build"), dict),
        "private-pilot backend must use the locally verified image and build",
    )
    dns_name = _validate_tailnet_status(tailscale_status)
    expected_origin = f"https://{dns_name}"
    _require(
        config.backend_origin == expected_origin,
        "sealed backend origin must exactly match the Tailscale HTTPS node origin",
    )
    _require(
        config.listen_host == "0.0.0.0" and config.listen_port == 8080,
        "container listener must retain the closed Tacua port binding",
    )
    compose = validate_compose_document(
        compose_document,
        config,
        require_immutable_image=False,
    )
    _require(
        compose.get("topology") == "loopback-ingress"
        and compose.get("publisher_service") == "ingress"
        and compose.get("published_host") == "127.0.0.1"
        and compose.get("published_port") == "8080",
        "Compose ingress must publish Tacua only at 127.0.0.1:8080",
    )
    return expected_origin, compose


def validate_tailnet_private_pilot_pre_activation(
    config: Any,
    compose_document: dict[str, Any],
    tailscale_status: dict[str, Any],
    serve_status: dict[str, Any],
) -> dict[str, Any]:
    """Prove every static binding and an empty Serve host before mutation."""

    expected_origin, _compose = _validate_private_pilot_base(
        config,
        compose_document,
        tailscale_status,
    )
    validate_empty_serve_status(serve_status)
    return {
        "origin": expected_origin,
        "serve": "empty",
        "status": "ok",
    }


def validate_tailnet_private_pilot(
    config: Any,
    compose_document: dict[str, Any],
    tailscale_status: dict[str, Any],
    serve_status: dict[str, Any],
) -> dict[str, Any]:
    """Validate the static private-pilot origin, Compose, and Serve bindings."""

    expected_origin, _compose = _validate_private_pilot_base(
        config,
        compose_document,
        tailscale_status,
    )
    dns_name = expected_origin.removeprefix("https://")
    _validate_serve_status(serve_status, dns_name)
    return {
        "origin": expected_origin,
        "proxy": EXPECTED_PROXY,
        "status": "ok",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-file", type=Path)
    parser.add_argument("--admin-secret-file", type=Path)
    parser.add_argument("--compose-json", type=Path)
    parser.add_argument("--tailscale-status-json", type=Path)
    parser.add_argument("--serve-status-json", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--expect-empty-serve", action="store_true")
    modes.add_argument("--inspect-tailnet-identity", action="store_true")
    modes.add_argument("--pre-activation", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.expect_empty_serve:
        if args.serve_status_json is None or any(
            value is not None
            for value in (
                args.config_file,
                args.admin_secret_file,
                args.compose_json,
                args.tailscale_status_json,
            )
        ):
            parser.error(
                "--expect-empty-serve accepts only --serve-status-json"
            )
    elif args.inspect_tailnet_identity:
        if args.tailscale_status_json is None or any(
            value is not None
            for value in (
                args.config_file,
                args.admin_secret_file,
                args.compose_json,
                args.serve_status_json,
            )
        ):
            parser.error(
                "--inspect-tailnet-identity accepts only "
                "--tailscale-status-json"
            )
    else:
        missing = [
            option
            for option, value in (
                ("--config-file", args.config_file),
                ("--admin-secret-file", args.admin_secret_file),
                ("--compose-json", args.compose_json),
                ("--tailscale-status-json", args.tailscale_status_json),
                ("--serve-status-json", args.serve_status_json),
            )
            if value is None
        ]
        if missing:
            parser.error(
                "normal validation requires " + ", ".join(missing)
            )
    try:
        if args.expect_empty_serve:
            serve_status = _load_status_json(
                args.serve_status_json,
                "Tailscale Serve status JSON",
            )
            result = validate_empty_serve_status(serve_status)
        elif args.inspect_tailnet_identity:
            tailscale_status = _load_status_json(
                args.tailscale_status_json,
                "Tailscale status JSON",
            )
            result = inspect_tailnet_identity(tailscale_status)
        else:
            compose = _load_status_json(
                args.compose_json,
                "resolved Compose JSON",
            )
            deployment_preflight(
                args.config_file,
                args.admin_secret_file,
                compose,
                require_immutable_image=False,
                check_state=False,
            )
            config = load_public_config(args.config_file)
            tailscale_status = _load_status_json(
                args.tailscale_status_json,
                "Tailscale status JSON",
            )
            serve_status = _load_status_json(
                args.serve_status_json,
                "Tailscale Serve status JSON",
            )
            if args.pre_activation:
                result = validate_tailnet_private_pilot_pre_activation(
                    config,
                    compose,
                    tailscale_status,
                    serve_status,
                )
            else:
                result = validate_tailnet_private_pilot(
                    config,
                    compose,
                    tailscale_status,
                    serve_status,
                )
    except (ConfigError, OperatorError, TailnetPilotError, OSError) as exc:
        print(f"tailnet private-pilot error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
