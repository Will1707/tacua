#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable EXP-007 packaging probe. It is intentionally not a Tacua backend."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import TCPServer
from typing import Any


EXPERIMENT_ID = "tacua-exp007"
STATE_FORMAT = "tacua-exp007-state"
BACKUP_FORMAT = "tacua-exp007-backup"
MAX_SCHEMA = 2
STARTED_NS = time.monotonic_ns()


class ProbeError(Exception):
    error_class = "probe_error"


class ConfigError(ProbeError):
    error_class = "config_error"


class StateError(ProbeError):
    error_class = "state_error"


class MigrationError(ProbeError):
    error_class = "migration_error"


class BackupError(ProbeError):
    error_class = "backup_error"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def elapsed_ms() -> int:
    return (time.monotonic_ns() - STARTED_NS) // 1_000_000


def log(transition: str, result: str, **fields: Any) -> None:
    record: dict[str, Any] = {
        "timestamp": now(),
        "experiment_id": EXPERIMENT_ID,
        "probe_version": os.environ.get("TACUA_PROBE_VERSION", "unknown"),
        "image_id": os.environ.get("TACUA_PROBE_IMAGE_ID", "unknown"),
        "host_class": os.environ.get("TACUA_PROBE_HOST_CLASS", "local-docker"),
        "case_id": os.environ.get("TACUA_PROBE_CASE_ID", "unspecified"),
        "state_transition": transition,
        "elapsed_ms": elapsed_ms(),
        "typed_result": result,
    }
    record.update(fields)
    print(json.dumps(record, sort_keys=True, separators=(",", ":")), file=sys.stderr, flush=True)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def checksum(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(f".{path.name}.pending-{os.getpid()}")
    try:
        with pending.open("wb") as handle:
            handle.write(canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, path)
    finally:
        try:
            pending.unlink()
        except FileNotFoundError:
            pass


def load_json(path: Path, error_type: type[ProbeError], label: str) -> Any:
    try:
        with path.open("rb") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise error_type(f"{label} not found") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise error_type(f"{label} is unreadable or invalid JSON") from exc


def load_config() -> dict[str, Any]:
    raw_path = os.environ.get("TACUA_PROBE_CONFIG")
    if not raw_path:
        raise ConfigError("TACUA_PROBE_CONFIG is required")
    path = Path(raw_path)
    if not path.is_absolute():
        raise ConfigError("TACUA_PROBE_CONFIG must be an absolute path")
    value = load_json(path, ConfigError, "configuration file")
    if not isinstance(value, dict):
        raise ConfigError("configuration must be a JSON object")
    required = {"instance_id", "listen_port", "marker", "synthetic_token"}
    if not required.issubset(value):
        raise ConfigError("configuration is missing a required key")
    if not isinstance(value["instance_id"], str) or not value["instance_id"].startswith("tacua-exp007-"):
        raise ConfigError("instance_id must start with tacua-exp007-")
    if not isinstance(value["listen_port"], int) or not 1 <= value["listen_port"] <= 65535:
        raise ConfigError("listen_port must be an integer in 1..65535")
    if not isinstance(value["marker"], str) or not 1 <= len(value["marker"]) <= 256:
        raise ConfigError("marker must contain 1..256 characters")
    if not isinstance(value["synthetic_token"], str) or len(value["synthetic_token"]) < 24:
        raise ConfigError("synthetic_token must contain at least 24 characters")
    return value


def data_dir() -> Path:
    path = Path(os.environ.get("TACUA_PROBE_DATA_DIR", "/data"))
    if not path.is_absolute():
        raise ConfigError("TACUA_PROBE_DATA_DIR must be absolute")
    return path


def state_path() -> Path:
    return data_dir() / "state.json"


def validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("format") != STATE_FORMAT:
        raise StateError("state format is incompatible")
    schema = value.get("schema_version")
    if not isinstance(schema, int) or schema < 1 or schema > MAX_SCHEMA:
        raise StateError("state schema is incompatible")
    if not isinstance(value.get("marker"), str):
        raise StateError("state marker is invalid")
    return value


def read_state() -> dict[str, Any]:
    return validate_state(load_json(state_path(), StateError, "state"))


def initialize_state(config: dict[str, Any]) -> dict[str, Any]:
    path = state_path()
    if path.exists():
        return read_state()
    value = {
        "format": STATE_FORMAT,
        "schema_version": 1,
        "marker": config["marker"],
        "created_at": now(),
        "updated_at": now(),
    }
    try:
        atomic_json(path, value)
    except OSError as exc:
        raise StateError(f"persistent state is not writable: {exc.strerror or exc.__class__.__name__}") from exc
    log("state_initialized", "ok", schema_version=1, state_checksum=checksum(value))
    return value


class ProbeHandler(BaseHTTPRequestHandler):
    state: dict[str, Any]

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            body = {
                "status": "healthy",
                "experiment_id": EXPERIMENT_ID,
                "probe_version": os.environ.get("TACUA_PROBE_VERSION", "unknown"),
                "schema_version": self.state["schema_version"],
                "state_checksum": checksum(self.state),
            }
            self._json(200, body)
        elif self.path == "/version":
            self._json(
                200,
                {
                    "experiment_id": EXPERIMENT_ID,
                    "probe_version": os.environ.get("TACUA_PROBE_VERSION", "unknown"),
                    "state_format": STATE_FORMAT,
                    "max_schema": MAX_SCHEMA,
                },
            )
        else:
            self._json(404, {"error": "not_found"})

    def _json(self, status: int, value: Any) -> None:
        payload = canonical(value) + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return


class ProbeHTTPServer(HTTPServer):
    def server_bind(self) -> None:
        # HTTPServer normally performs reverse DNS while setting a display
        # name. That is unnecessary and can add five seconds under --network
        # none, so the probe binds without the lookup.
        TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def serve(_: argparse.Namespace) -> None:
    config = load_config()
    state = initialize_state(config)
    ProbeHandler.state = state
    stopping = False

    def stop(signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True
        log("termination_requested", "ok", signal=signal.Signals(signum).name)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server = ProbeHTTPServer(("0.0.0.0", config["listen_port"]), ProbeHandler)
    except OSError as exc:
        raise ConfigError(f"listen socket unavailable: {exc.strerror or exc.__class__.__name__}") from exc
    server.timeout = 0.25
    log("healthy", "ok", schema_version=state["schema_version"], state_checksum=checksum(state))
    while not stopping:
        server.handle_request()
    server.server_close()
    log("stopped", "ok")


def print_checksum(_: argparse.Namespace) -> None:
    load_config()
    value = read_state()
    print(checksum(value))
    log("checksum_verified", "ok", schema_version=value["schema_version"], state_checksum=checksum(value))


def inspect_state(_: argparse.Namespace) -> None:
    load_config()
    value = read_state()
    print(json.dumps(value, sort_keys=True, indent=2))
    log("state_inspected", "ok", schema_version=value["schema_version"], state_checksum=checksum(value))


def migrate(args: argparse.Namespace) -> None:
    load_config()
    value = read_state()
    before = checksum(value)
    if args.to not in (1, 2):
        raise MigrationError("requested schema is incompatible")
    migrated = dict(value)
    migrated["schema_version"] = args.to
    migrated["updated_at"] = now()
    if args.to == 2:
        migrated["migration_note"] = "synthetic-v2"
    else:
        migrated.pop("migration_note", None)
    if args.simulate_failure:
        log("migration_failed_before_commit", "expected_error", from_schema=value["schema_version"], to_schema=args.to)
        raise MigrationError("synthetic migration failure before atomic commit")
    try:
        atomic_json(state_path(), migrated)
    except OSError as exc:
        raise MigrationError(f"migration write failed: {exc.strerror or exc.__class__.__name__}") from exc
    log(
        "migration_committed",
        "ok",
        from_schema=value["schema_version"],
        to_schema=args.to,
        before_checksum=before,
        after_checksum=checksum(migrated),
    )
    print(checksum(migrated))


def backup(args: argparse.Namespace) -> None:
    load_config()
    value = read_state()
    payload = canonical(value).decode("utf-8")
    envelope: dict[str, Any] = {
        "format": BACKUP_FORMAT,
        "backup_version": 1,
        "created_at": now(),
        "probe_version": os.environ.get("TACUA_PROBE_VERSION", "unknown"),
        "state_checksum": checksum(value),
        "payload": payload,
    }
    if args.pad_bytes:
        envelope["synthetic_padding"] = "x" * args.pad_bytes
    envelope["envelope_checksum"] = checksum(envelope)
    output = Path(args.output)
    if not output.is_absolute():
        raise BackupError("backup output must be absolute")
    try:
        atomic_json(output, envelope)
    except OSError as exc:
        raise BackupError(f"backup write failed: {exc.strerror or exc.__class__.__name__}") from exc
    log("backup_created", "ok", state_checksum=envelope["state_checksum"], backup_bytes=output.stat().st_size)
    print(envelope["envelope_checksum"])


def load_backup(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    envelope = load_json(path, BackupError, "backup")
    if not isinstance(envelope, dict) or envelope.get("format") != BACKUP_FORMAT:
        raise BackupError("backup format is incompatible")
    claimed = envelope.get("envelope_checksum")
    unsigned = dict(envelope)
    unsigned.pop("envelope_checksum", None)
    if not isinstance(claimed, str) or checksum(unsigned) != claimed:
        raise BackupError("backup envelope checksum mismatch")
    try:
        payload = json.loads(envelope["payload"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise BackupError("backup payload is invalid") from exc
    try:
        value = validate_state(payload)
    except StateError as exc:
        raise BackupError(str(exc)) from exc
    if checksum(value) != envelope.get("state_checksum"):
        raise BackupError("backup state checksum mismatch")
    return envelope, value


def restore(args: argparse.Namespace) -> None:
    load_config()
    envelope, value = load_backup(Path(args.input))
    path = state_path()
    if path.exists() and not args.replace:
        raise BackupError("restore target already contains state; pass --replace explicitly")
    try:
        atomic_json(path, value)
    except OSError as exc:
        raise BackupError(f"restore write failed: {exc.strerror or exc.__class__.__name__}") from exc
    log(
        "backup_restored",
        "ok",
        schema_version=value["schema_version"],
        state_checksum=envelope["state_checksum"],
    )
    print(envelope["state_checksum"])


def make_fixture(args: argparse.Namespace) -> None:
    load_config()
    source = Path(args.input)
    target = Path(args.output)
    envelope = load_json(source, BackupError, "source backup")
    if not isinstance(envelope, dict):
        raise BackupError("source backup is invalid")
    if args.kind == "corrupt":
        envelope["payload"] = str(envelope.get("payload", "")) + "!"
    elif args.kind == "incompatible":
        try:
            payload = json.loads(envelope["payload"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise BackupError("source backup payload is invalid") from exc
        payload["schema_version"] = MAX_SCHEMA + 97
        envelope["payload"] = canonical(payload).decode("utf-8")
        envelope["state_checksum"] = checksum(payload)
        unsigned = dict(envelope)
        unsigned.pop("envelope_checksum", None)
        envelope["envelope_checksum"] = checksum(unsigned)
    try:
        atomic_json(target, envelope)
    except OSError as exc:
        raise BackupError(f"fixture write failed: {exc.strerror or exc.__class__.__name__}") from exc
    log("failure_fixture_created", "ok", fixture_kind=args.kind)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("serve").set_defaults(handler=serve)
    sub.add_parser("checksum").set_defaults(handler=print_checksum)
    sub.add_parser("inspect").set_defaults(handler=inspect_state)
    migration = sub.add_parser("migrate")
    migration.add_argument("--to", type=int, required=True)
    migration.add_argument("--simulate-failure", action="store_true")
    migration.set_defaults(handler=migrate)
    backup_parser = sub.add_parser("backup")
    backup_parser.add_argument("--output", required=True)
    backup_parser.add_argument("--pad-bytes", type=int, default=0)
    backup_parser.set_defaults(handler=backup)
    restore_parser = sub.add_parser("restore")
    restore_parser.add_argument("--input", required=True)
    restore_parser.add_argument("--replace", action="store_true")
    restore_parser.set_defaults(handler=restore)
    fixture = sub.add_parser("make-fixture")
    fixture.add_argument("--kind", choices=("corrupt", "incompatible"), required=True)
    fixture.add_argument("--input", required=True)
    fixture.add_argument("--output", required=True)
    fixture.set_defaults(handler=make_fixture)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
        return 0
    except ProbeError as exc:
        log("terminal_error", exc.error_class, error_class=exc.error_class, message=str(exc))
        print(f"{exc.error_class}: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        log("terminal_error", "io_error", error_class="io_error", message=exc.strerror or exc.__class__.__name__)
        print(f"io_error: {exc.strerror or exc.__class__.__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
