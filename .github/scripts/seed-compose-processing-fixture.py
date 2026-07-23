#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seed one protocol-valid queued job for the rootless Compose bridge test."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any

from tacua_backend.config import load_config
from tacua_backend.contracts import (
    PROTOCOL_VERSION,
    canonical_json,
    digest,
    runtime_seal,
    seal,
    validate_operation_pair,
)
from tacua_backend.instance_lock import acquire_state_instance_lock
from tacua_backend.service import PilotBackend


FIXTURE_NAMES = (
    "capture-scope",
    "diagnostic-upload-request",
    "launch-exchange-request",
    "segment-upload-intent",
    "completion-request",
)


def instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_timeline() -> dict[str, str]:
    # Keep every synthetic event in the recent past so a real-clock restart
    # cannot immediately expire it and the persisted authoritative-time floor
    # never moves ahead of the host.
    initial = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
        minutes=10
    )
    capture_start = initial + timedelta(seconds=179)
    return {
        "initial": timestamp(initial),
        "capture_start": timestamp(capture_start),
        "capture_end": timestamp(capture_start + timedelta(seconds=60)),
        "segment_requested": timestamp(initial + timedelta(seconds=298)),
        "segment": timestamp(initial + timedelta(seconds=299)),
        "diagnostic_requested": timestamp(initial + timedelta(seconds=302)),
        "diagnostic": timestamp(initial + timedelta(seconds=303)),
        "completion_requested": timestamp(initial + timedelta(seconds=304)),
        "completion": timestamp(initial + timedelta(seconds=305)),
        "unavailable_evidence": timestamp(initial + timedelta(seconds=360)),
    }


class FixedClock:
    def __init__(self, initial: str) -> None:
        self._value = instant(initial)
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._value

    def set(self, value: str) -> None:
        with self._lock:
            self._value = instant(value)


def load_fixture(directory: Path, name: str) -> dict[str, Any]:
    path = directory / f"{name}.json"
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError("protocol fixture is unavailable or invalid") from error
    if not isinstance(value, dict):
        raise ValueError("protocol fixture must be an object")
    return value


def make_scope(config: Any, fixture_directory: Path) -> dict[str, Any]:
    scope = load_fixture(fixture_directory, "capture-scope")
    scope.update(
        {
            "application_id": config.application_id,
            "build_id": config.build_id,
            "build_identity_digest": config.build_identity_digest,
            "organization_id": config.organization_id,
            "project_id": config.project_id,
        }
    )
    scope["consent"]["policy_version"] = config.consent_contract
    scope["retention"].update(
        {
            "raw_media_days": config.raw_retention_days,
            "derived_data_days": config.derived_retention_days,
        }
    )
    return seal(scope)


def start_session(
    backend: PilotBackend,
    config: Any,
    scope: dict[str, Any],
    fixture_directory: Path,
    timeline: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    grant = backend.create_launch_code(
        {"exchange_kind": "start_session", "build_id": config.build_id}
    )
    scope = copy.deepcopy(scope)
    scope["consent"]["granted_at"] = timeline["initial"]
    scope = seal(scope)
    request = load_fixture(fixture_directory, "launch-exchange-request")
    request.update(
        {
            "build_identity": copy.deepcopy(config.build_identity),
            "launch_code": grant["launch_code"],
            "requested_at": timeline["initial"],
            "scope": copy.deepcopy(scope),
        }
    )
    request = seal(request)
    response = backend.exchange_launch_code(request)
    if response.status != 201:
        raise RuntimeError("synthetic launch exchange was not created")
    receipt = response.json()
    validate_operation_pair(request, receipt)
    return request, receipt, scope


def upload_segment(
    backend: PilotBackend,
    scope: dict[str, Any],
    launch_request: dict[str, Any],
    launch_receipt: dict[str, Any],
    fixture_directory: Path,
    clock: FixedClock,
    timeline: dict[str, str],
) -> dict[str, Any]:
    content = b"synthetic Compose bridge evidence\n"
    request = load_fixture(fixture_directory, "segment-upload-intent")
    request.update(
        {
            "credential_id": launch_receipt["credential"]["credential_id"],
            "scope_digest": scope["scope_digest"],
            "session_id": launch_receipt["session_id"],
            "requested_at": timeline["segment_requested"],
            "transport": {
                "content_digest": digest(content),
                "content_type": "video/quicktime",
                "size_bytes": len(content),
            },
        }
    )
    request = seal(request)
    clock.set(timeline["segment"])
    response = backend.upload_segment(
        launch_receipt["session_id"],
        request["sequence"],
        request["segment_id"],
        launch_request["credential"]["secret"],
        request,
        io.BytesIO(content),
    )
    if response.status != 201:
        raise RuntimeError("synthetic segment was not created")
    receipt = response.json()
    validate_operation_pair(request, receipt)
    return receipt


def complete_session(
    backend: PilotBackend,
    config: Any,
    scope: dict[str, Any],
    launch_request: dict[str, Any],
    launch_receipt: dict[str, Any],
    segment_receipt: dict[str, Any],
    diagnostic_receipt: dict[str, Any],
    fixture_directory: Path,
    clock: FixedClock,
    timeline: dict[str, str],
) -> dict[str, Any]:
    template = load_fixture(fixture_directory, "completion-request")
    manifest = template["capture_manifest"]
    manifest.update(
        {
            "build_id": config.build_id,
            "build_identity_digest": config.build_identity_digest,
            "organization_id": config.organization_id,
            "project_id": config.project_id,
            "session_id": launch_receipt["session_id"],
            "started_at": timeline["capture_start"],
            "ended_at": timeline["capture_end"],
        }
    )
    runtime_receipt = copy.deepcopy(segment_receipt["runtime_receipt"])
    manifest["segments"] = [
        {
            "availability": "available",
            "content": {
                "content_digest": runtime_receipt["content_digest"],
                "content_type": segment_receipt["content_type"],
                "sidecar_digest": segment_receipt["sidecar_digest"],
                "size_bytes": runtime_receipt["size_bytes"],
            },
            "finalized": True,
            "segment_id": segment_receipt["segment_id"],
            "sequence": segment_receipt["sequence"],
            "time_range": {
                "clock": "session_monotonic",
                "end_ms": 60_000,
                "start_ms": 0,
            },
            "unavailable": None,
        }
    ]
    manifest["app_audio_accounting"] = {
        "version": 1,
        "complete": True,
        "append_attempts": 1,
        "reserved_through_index": 1,
        "segments": [
            {
                "segment_id": segment_receipt["segment_id"],
                "sequence": segment_receipt["sequence"],
                "attempt_start_index": 1,
                "append_attempts": 1,
                "appended_samples": 1,
                "drops": [],
            }
        ],
        "unknown_ranges": [],
    }
    manifest["monotonic_duration_ms"] = 60_000
    manifest["upload"]["receipts"] = [runtime_receipt]
    manifest["upload"]["remote_session_id"] = launch_receipt["session_id"]
    manifest["upload"]["completed_at"] = timeline["segment"]
    session = backend.get_session(launch_receipt["session_id"])
    manifest["retention"].update(
        {
            "raw_media_expires_at": session["retention"]["raw_media_expires_at"],
            "derived_data_expires_at": session["retention"][
                "derived_data_expires_at"
            ],
        }
    )
    manifest = runtime_seal(manifest)
    request = {
        "protocol_version": PROTOCOL_VERSION,
        "message_type": "completion_request",
        "completion_id": "completion_compose_bridge",
        "session_id": launch_receipt["session_id"],
        "scope_digest": scope["scope_digest"],
        "credential_id": launch_receipt["credential"]["credential_id"],
        "capture_manifest": manifest,
        "segment_receipts": [copy.deepcopy(segment_receipt)],
        "diagnostic_receipts": [copy.deepcopy(diagnostic_receipt)],
        "requested_at": timeline["completion_requested"],
        "request_digest": "sha256:" + "0" * 64,
    }
    request = seal(request)
    clock.set(timeline["completion"])
    response = backend.complete_session(
        launch_receipt["session_id"],
        request["completion_id"],
        launch_request["credential"]["secret"],
        request,
    )
    if response.status != 201:
        raise RuntimeError("synthetic completion was not created")
    receipt = response.json()
    validate_operation_pair(request, receipt)
    return receipt


def upload_diagnostic(
    backend: PilotBackend,
    config: Any,
    scope: dict[str, Any],
    launch_request: dict[str, Any],
    launch_receipt: dict[str, Any],
    fixture_directory: Path,
    clock: FixedClock,
    timeline: dict[str, str],
) -> dict[str, Any]:
    request = load_fixture(fixture_directory, "diagnostic-upload-request")
    envelope = request["envelope"]
    envelope.update(
        {
            "build_id": config.build_id,
            "build_identity_digest": config.build_identity_digest,
            "organization_id": config.organization_id,
            "project_id": config.project_id,
            "session_id": launch_receipt["session_id"],
        }
    )
    for evidence in envelope["evidence"]:
        reference = evidence.get("reference")
        if isinstance(reference, dict):
            reference["locator"].update(
                {
                    "organization_id": config.organization_id,
                    "project_id": config.project_id,
                }
            )
        time_range = evidence.get("time_range")
        elapsed_ms = (
            time_range.get("end_ms")
            if isinstance(time_range, dict)
            else None
        )
        evidence["source"]["captured_at"] = (
            timestamp(
                instant(timeline["capture_start"])
                + timedelta(milliseconds=elapsed_ms)
            )
            if isinstance(elapsed_ms, int)
            else timeline["unavailable_evidence"]
        )
    capture_start = instant(timeline["capture_start"])
    for event in envelope["events"]:
        event["occurred_at"] = timestamp(
            capture_start + timedelta(milliseconds=event["elapsed_ms"])
        )
    envelope = runtime_seal(envelope)
    envelope_bytes = canonical_json(envelope).encode("utf-8")
    request.update(
        {
            "credential_id": launch_receipt["credential"]["credential_id"],
            "envelope": envelope,
            "scope_digest": scope["scope_digest"],
            "session_id": launch_receipt["session_id"],
            "requested_at": timeline["diagnostic_requested"],
            "transport": {
                "content_digest": digest(envelope_bytes),
                "content_type": (
                    "application/vnd.tacua.diagnostic-envelope+json;"
                    "version=1.0.0"
                ),
                "size_bytes": len(envelope_bytes),
            },
        }
    )
    request = seal(request)
    clock.set(timeline["diagnostic"])
    response = backend.upload_diagnostic(
        launch_receipt["session_id"],
        request["upload_id"],
        launch_request["credential"]["secret"],
        request,
    )
    if response.status != 201:
        raise RuntimeError("synthetic diagnostic was not created")
    receipt = response.json()
    validate_operation_pair(request, receipt)
    return receipt


def verify_processed_fixture(backend: PilotBackend) -> None:
    job_page = backend.list_jobs()
    session_page = backend.list_sessions()
    if (
        job_page["next_cursor"] is not None
        or len(job_page["jobs"]) != 1
        or session_page["next_cursor"] is not None
        or len(session_page["sessions"]) != 1
    ):
        raise RuntimeError("processed Compose fixture population is not exact")
    job = backend.get_job(job_page["jobs"][0]["job_id"])
    session = backend.get_session(session_page["sessions"][0]["session_id"])
    stages = job["pipeline"]["stages"]
    with backend._connect() as connection:
        lease_count = connection.execute(
            "SELECT COUNT(*) FROM tacua_processing_job_leases"
        ).fetchone()[0]
    if (
        job["status"] != "queued"
        or len(stages) != 5
        or stages[0]["name"] != "transcribe"
        or stages[0]["state"] != "succeeded"
        or stages[0]["attempt_count"] != 1
        or stages[0]["completed_at"] is None
        or any(
            stage["state"] != "pending"
            or stage["attempt_count"] != 0
            or stage["started_at"] is not None
            or stage["completed_at"] is not None
            for stage in stages[1:]
        )
        or lease_count != 0
        or session["state"] != "completed"
    ):
        raise RuntimeError("processed Compose fixture state is not exact")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--admin-secret-file", type=Path, required=True)
    parser.add_argument("--fixture-directory", type=Path, required=True)
    parser.add_argument("--verify-processed", action="store_true")
    args = parser.parse_args()
    if any(
        not (args.fixture_directory / f"{name}.json").is_file()
        for name in FIXTURE_NAMES
    ):
        parser.error("protocol fixture directory is incomplete")

    config, admin_secret = load_config(
        args.config_file,
        args.admin_secret_file,
    )
    with acquire_state_instance_lock(
        config.state_directory,
        create_directory=True,
    ):
        if args.verify_processed:
            backend = PilotBackend(config, admin_secret)
            verify_processed_fixture(backend)
            print(canonical_json({"status": "ok"}))
            return 0
        timeline = make_timeline()
        clock = FixedClock(timeline["initial"])
        backend = PilotBackend(config, admin_secret, clock=clock)
        if (
            backend.list_sessions()["sessions"]
            or backend.list_jobs()["jobs"]
        ):
            raise RuntimeError("Compose processing fixture state is not pristine")
        with backend._connect() as connection:
            if any(
                connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
                for table in (
                    "sessions",
                    "jobs",
                    "tombstones",
                    "launch_grants",
                    "credentials",
                )
            ):
                raise RuntimeError(
                    "Compose processing fixture state contains durable activity"
                )
        scope = make_scope(config, args.fixture_directory)
        launch_request, launch_receipt, scope = start_session(
            backend,
            config,
            scope,
            args.fixture_directory,
            timeline,
        )
        segment_receipt = upload_segment(
            backend,
            scope,
            launch_request,
            launch_receipt,
            args.fixture_directory,
            clock,
            timeline,
        )
        diagnostic_receipt = upload_diagnostic(
            backend,
            config,
            scope,
            launch_request,
            launch_receipt,
            args.fixture_directory,
            clock,
            timeline,
        )
        completion_receipt = complete_session(
            backend,
            config,
            scope,
            launch_request,
            launch_receipt,
            segment_receipt,
            diagnostic_receipt,
            args.fixture_directory,
            clock,
            timeline,
        )
        job_page = backend.list_jobs()
        if (
            job_page["next_cursor"] is not None
            or len(job_page["jobs"]) != 1
            or job_page["jobs"][0]["job_id"]
            != completion_receipt["processing_job"]["job_id"]
        ):
            raise RuntimeError("synthetic processing queue is not exact")
        persisted_job = backend.get_job(job_page["jobs"][0]["job_id"])
        session = backend.get_session(launch_receipt["session_id"])
        if (
            persisted_job != completion_receipt["processing_job"]
            or persisted_job["status"] != "queued"
            or any(
                stage["state"] != "pending"
                or stage["attempt_count"] != 0
                for stage in persisted_job["pipeline"]["stages"]
            )
            or session["state"] != "completed"
        ):
            raise RuntimeError("synthetic processing job was not persisted exactly")
    print(canonical_json({"status": "ok"}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("COMPOSE_PROCESSING_FIXTURE_FAILED", file=sys.stderr)
        raise SystemExit(1)
