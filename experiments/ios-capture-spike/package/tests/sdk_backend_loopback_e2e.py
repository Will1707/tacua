#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Real macOS loopback E2E for the production SDK transport and backend HTTP API."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from typing import Any


ROOT = Path(__file__).resolve().parents[4]
BACKEND_SOURCE = ROOT / "services" / "backend" / "src"
SDK_DIRECTORY = ROOT / "experiments" / "ios-capture-spike" / "package"
PROTOCOL_FIXTURES = ROOT / "contracts" / "sdk-backend-protocol" / "fixtures" / "positive"
HANDOFF_FIXTURES = ROOT / "contracts" / "approved-handoff" / "fixtures" / "positive"
sys.path.insert(0, str(BACKEND_SOURCE))

from tacua_backend.config import (  # noqa: E402
    APPROVED_HANDOFF_CONTRACT,
    DEFAULT_MAX_COMPLETION_BYTES,
    DEFAULT_MAX_DIAGNOSTIC_BYTES,
    DEFAULT_MAX_SEGMENT_BYTES,
    TRANSPORT_POLICY_VERSION,
    PilotConfig,
)
from tacua_backend.contracts import canonical_json, digest, seal, validate  # noqa: E402
from tacua_backend.http_api import PilotRequestHandler, create_server  # noqa: E402
from tacua_backend.service import PilotBackend  # noqa: E402


FIXED_INSTANT = datetime(2026, 7, 21, 10, 0, 0, tzinfo=timezone.utc)
FIXED_TIMESTAMP = "2026-07-21T10:00:00Z"
SEGMENT_BYTES = b"Tacua loopback SDK segment bytes\n"


def sha256_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"fixture root is not an object: {path.name}")
    return value


def approved_handoff_config(build: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    handoff_build = load_json(HANDOFF_FIXTURES / "build-identity.json")
    handoff_build["organization_id"] = scope["organization_id"]
    handoff_build["project_id"] = scope["project_id"]
    handoff_build["build_id"] = build["build_id"]
    handoff_build["mobile"].update(
        {
            "platform": build["platform"],
            "application_id": build["bundle_identifier"],
            "app_version": build["native_version"],
            "build_number": build["native_build"],
            "distribution": {
                "local": "local-development",
                "internal": "internal",
                "testflight": "testflight",
            }[build["distribution"]],
        }
    )
    handoff_build["mobile"]["source"].update(
        {
            "repository_id": "repo_mobile",
            "revision": build["source"]["git_revision"],
            "dirty": False,
        }
    )
    handoff_build["backend"] = {
        "availability": "unavailable",
        "environment": "self_hosted_qa",
        "deployment_id": None,
        "image_digest": None,
        "deployed_at": None,
        "sources": [],
        "unavailable_reason": "deployment_identity_unavailable",
    }
    handoff_build["sdk"]["configuration_digest"] = build[
        "transport_configuration_digest"
    ]
    return {
        "build_identity": APPROVED_HANDOFF_CONTRACT.seal_build_identity(handoff_build),
        "authority": {
            "purpose": "implement_approved_ticket",
            "allowed_repositories": ["repo_mobile"],
            "read_authorized_evidence": True,
            "modify_code": True,
            "run_tests": True,
            "external_writes": False,
            "merge": False,
            "deploy": False,
        },
        "registry_revision": "registry_loopback_e2e",
    }


def protocol_artifacts(origin: str) -> tuple[dict[str, Any], dict[str, Any]]:
    transport_configuration = {
        "backend_origin": origin,
        "max_completion_bytes": DEFAULT_MAX_COMPLETION_BYTES,
        "max_diagnostic_bytes": DEFAULT_MAX_DIAGNOSTIC_BYTES,
        "max_segment_bytes": DEFAULT_MAX_SEGMENT_BYTES,
        "transport_policy_version": TRANSPORT_POLICY_VERSION,
    }
    build = load_json(PROTOCOL_FIXTURES / "build-identity.json")
    build.update(
        {
            "build_id": "build_loopback_e2e",
            "build_variant": "development",
            "bundle_identifier": "dev.tacua.loopbacke2e",
            "distribution": "local",
            "expo": None,
            "native_build": "1",
            "source": {
                "git_revision": "a" * 40,
                "working_tree_dirty": False,
            },
            "transport_configuration_digest": digest(transport_configuration),
        }
    )
    build = seal(build)
    validate(build)

    scope = load_json(PROTOCOL_FIXTURES / "capture-scope.json")
    scope.update(
        {
            "build_id": build["build_id"],
            "build_identity_digest": build["build_identity_digest"],
            "consent": {
                "diagnostics": "granted",
                "granted_at": FIXED_TIMESTAMP,
                "microphone": "granted",
                "policy_version": "tacua.consent-v1",
                "raw_media_upload": "granted",
                "screen_recording": "granted",
            },
        }
    )
    scope = seal(scope)
    validate(scope)
    return build, scope


class DeferredBackend:
    """Lets the real server claim port zero before its origin-bound backend exists."""

    def __init__(self) -> None:
        self.backend: PilotBackend | None = None
        self.retention_requested = False

    def start_retention_enforcement(self) -> None:
        if self.backend is None:
            self.retention_requested = True
        else:
            self.backend.start_retention_enforcement()

    def stop_retention_enforcement(self) -> None:
        self.retention_requested = False
        if self.backend is not None:
            self.backend.stop_retention_enforcement()

    def attach(self, backend: PilotBackend) -> None:
        if self.backend is not None:
            raise RuntimeError("backend is already attached")
        self.backend = backend
        if self.retention_requested:
            backend.start_retention_enforcement()

    def __getattr__(self, name: str) -> Any:
        if self.backend is None:
            raise RuntimeError("backend request arrived before attachment")
        return getattr(self.backend, name)


class RecordingPilotRequestHandler(PilotRequestHandler):
    records: list[dict[str, Any]] = []
    records_lock = threading.Lock()

    def parse_request(self) -> bool:
        parsed = super().parse_request()
        if getattr(self, "path", "").startswith("/v1/sdk/") and hasattr(self, "headers"):
            with self.records_lock:
                self.records.append(
                    {
                        "method": getattr(self, "command", ""),
                        "path": self.path,
                        "content_length": self.headers.get_all("Content-Length") or [],
                        "expect": self.headers.get_all("Expect") or [],
                        "transfer_encoding": self.headers.get_all("Transfer-Encoding") or [],
                    }
                )
        return parsed


def compile_driver(temporary: Path) -> Path:
    compiler = shutil.which("xcrun")
    if compiler is None:
        raise AssertionError("xcrun is required for the macOS Swift loopback E2E")
    executable = temporary / "sdk-backend-loopback-e2e"
    sources = [
        SDK_DIRECTORY / "ios" / "CapturePolicy.swift",
        SDK_DIRECTORY / "ios" / "TacuaCanonicalJSON.swift",
        SDK_DIRECTORY / "ios" / "TacuaCredentialStore.swift",
        SDK_DIRECTORY / "ios" / "TacuaBackendConfiguration.swift",
        SDK_DIRECTORY / "ios" / "TacuaLaunchLink.swift",
        SDK_DIRECTORY / "ios" / "TacuaTransportQueue.swift",
        SDK_DIRECTORY / "ios" / "TacuaSDKBackendProtocol.swift",
        SDK_DIRECTORY / "ios" / "TacuaSDKBackendRequests.swift",
        SDK_DIRECTORY / "ios" / "TacuaSDKBackendClient.swift",
        Path(__file__).resolve().with_name("SDKBackendLoopbackE2EDriver.swift"),
    ]
    command = [
        compiler,
        "swiftc",
        "-module-cache-path",
        str(temporary / "module-cache"),
        "-framework",
        "Security",
        "-o",
        str(executable),
        *(str(source) for source in sources),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if completed.returncode != 0:
        raise AssertionError("Swift driver compilation failed:\n" + completed.stderr)
    return executable


def sanitized_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        environment.pop(name, None)
    environment["NO_PROXY"] = "127.0.0.1,localhost"
    environment["no_proxy"] = "127.0.0.1,localhost"
    return environment


class SDKBackendLoopbackE2ETest(unittest.TestCase):
    def test_real_start_segment_and_exact_replay(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("the production URLSession transport E2E requires macOS")

        with tempfile.TemporaryDirectory(prefix="tacua-sdk-backend-e2e-") as temporary_name:
            temporary = Path(temporary_name)
            executable = compile_driver(temporary)
            deferred = DeferredBackend()
            server = create_server(deferred, host="127.0.0.1", port=0)
            server.RequestHandlerClass = RecordingPilotRequestHandler
            RecordingPilotRequestHandler.records = []
            server_thread: threading.Thread | None = None
            try:
                assigned_host, assigned_port = server.server_address[:2]
                self.assertEqual("127.0.0.1", assigned_host)
                self.assertIsInstance(assigned_port, int)
                self.assertGreater(assigned_port, 0)
                origin = f"http://127.0.0.1:{assigned_port}"
                build, scope = protocol_artifacts(origin)
                state_directory = temporary / "backend-state"
                config = PilotConfig(
                    organization_id=scope["organization_id"],
                    project_id=scope["project_id"],
                    application_id=scope["application_id"],
                    build_identity=copy.deepcopy(build),
                    approved_handoff=approved_handoff_config(build, scope),
                    consent_contract=scope["consent"]["policy_version"],
                    backend_origin=origin,
                    state_directory=state_directory,
                    listen_host="127.0.0.1",
                    listen_port=assigned_port,
                )
                backend = PilotBackend(
                    config,
                    b"A" * 48,
                    clock=lambda: FIXED_INSTANT,
                    retention_wait=lambda stop_event, seconds: stop_event.wait(seconds),
                )
                deferred.attach(backend)
                launch = backend.create_launch_code(
                    {"exchange_kind": "start_session", "build_id": build["build_id"]}
                )

                build_path = temporary / "build-identity.json"
                scope_path = temporary / "capture-scope.json"
                build_path.write_bytes(canonical_json(build).encode("utf-8"))
                scope_path.write_bytes(canonical_json(scope).encode("utf-8"))
                session_directory = temporary / "sdk-session"
                session_directory.mkdir(mode=0o700)
                segment_path = session_directory / "segment.mov"
                segment_path.write_bytes(SEGMENT_BYTES)

                server_thread = threading.Thread(
                    target=server.serve_forever,
                    kwargs={"poll_interval": 0.01},
                    name="tacua-loopback-e2e-server",
                    daemon=True,
                )
                server_thread.start()
                completed = subprocess.run(
                    [
                        str(executable),
                        origin,
                        launch["launch_code"],
                        str(build_path),
                        str(scope_path),
                        str(session_directory),
                        str(segment_path),
                    ],
                    cwd=ROOT,
                    env=sanitized_environment(),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual("", completed.stderr)
                stdout_lines = completed.stdout.splitlines()
                self.assertEqual(1, len(stdout_lines), completed.stdout)
                summary = json.loads(stdout_lines[0])
                self.assertEqual(
                    {
                        "content_digest",
                        "receipt_bytes_equal",
                        "response_bytes_digest",
                        "segment_receipt_digest",
                        "session_id",
                        "size_bytes",
                        "status_codes",
                    },
                    set(summary),
                )
                self.assertEqual([201, 201, 200], summary["status_codes"])
                self.assertIs(True, summary["receipt_bytes_equal"])
                self.assertEqual(len(SEGMENT_BYTES), summary["size_bytes"])
                self.assertEqual(sha256_digest(SEGMENT_BYTES), summary["content_digest"])

                with sqlite3.connect(backend.db_path) as connection:
                    connection.row_factory = sqlite3.Row
                    rows = connection.execute(
                        """SELECT session_id,upload_id,sequence,segment_id,response_bytes,
                                  relative_path,size_bytes,content_digest
                             FROM segments"""
                    ).fetchall()
                self.assertEqual(1, len(rows))
                stored = rows[0]
                self.assertEqual(summary["session_id"], stored["session_id"])
                self.assertEqual("upload_loopback_e2e", stored["upload_id"])
                self.assertEqual(0, stored["sequence"])
                self.assertEqual("segment_loopback_e2e", stored["segment_id"])
                self.assertEqual(len(SEGMENT_BYTES), stored["size_bytes"])
                self.assertEqual(sha256_digest(SEGMENT_BYTES), stored["content_digest"])
                response_bytes = bytes(stored["response_bytes"])
                self.assertEqual(sha256_digest(response_bytes), summary["response_bytes_digest"])
                stored_path = backend.state_dir / stored["relative_path"]
                stored_bytes = stored_path.read_bytes()
                self.assertEqual(SEGMENT_BYTES, stored_bytes)
                self.assertEqual(sha256_digest(SEGMENT_BYTES), sha256_digest(stored_bytes))

                with RecordingPilotRequestHandler.records_lock:
                    records = copy.deepcopy(RecordingPilotRequestHandler.records)
                self.assertEqual(3, len(records), records)
                self.assertEqual("POST", records[0]["method"])
                self.assertEqual("/v1/sdk/launch-exchanges", records[0]["path"])
                for record in records:
                    self.assertEqual([], record["transfer_encoding"], record)
                    self.assertEqual([], record["expect"], record)
                    self.assertEqual(1, len(record["content_length"]), record)
                segment_records = records[1:]
                self.assertTrue(
                    all(record["method"] == "PUT" for record in segment_records),
                    segment_records,
                )
                self.assertTrue(
                    all(
                        record["path"]
                        == f"/v1/sdk/sessions/{summary['session_id']}/segments/0/segment_loopback_e2e"
                        for record in segment_records
                    ),
                    segment_records,
                )
                self.assertEqual(
                    [[str(len(SEGMENT_BYTES))], [str(len(SEGMENT_BYTES))]],
                    [record["content_length"] for record in segment_records],
                )
            finally:
                if server_thread is not None and server_thread.is_alive():
                    server.shutdown()
                    server_thread.join(timeout=5)
                    if server_thread.is_alive():
                        self.fail("loopback server did not stop within five seconds")
                server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
