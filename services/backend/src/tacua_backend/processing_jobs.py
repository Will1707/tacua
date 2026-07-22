# SPDX-License-Identifier: Apache-2.0

"""Append-only processing-job history and internal worker leases.

This module deliberately does not run a worker or select a model.  It owns the
durable state-machine boundary a later worker must use.  The public ``jobs``
row remains the verified current-head projection used by the admin API.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
import json
import re
import sqlite3
import unicodedata
from typing import Any, Callable

from .contracts import (
    ContractError,
    canonical_json,
    runtime_seal,
    runtime_validate,
    validate as protocol_validate,
    validate_operation_pair,
)


MAX_SAFE_INTEGER = 9_007_199_254_740_991
JOB_STAGES = ("transcribe", "align", "correlate", "research", "generate_tickets")
FOUNDATION_STATUSES = frozenset({"queued", "running", "succeeded", "failed"})
LEASE_SECONDS = 300
MAX_CLAIM_SCAN = 50
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
VERIFIER_PATTERN = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
FAILURE_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


class ProcessingJobStoreError(Exception):
    """Content-free internal worker/storage failure."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _map_sqlite_errors(method):
    """Keep storage-engine details behind the content-free store boundary."""

    @wraps(method)
    def mapped(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except ProcessingJobStoreError:
            raise
        except sqlite3.Error as error:
            raise self._storage_error(error) from error

    return mapped


@dataclass(frozen=True)
class ProcessingJobClaim:
    """One opaque lease and the exact processing snapshot it authorizes."""

    job: dict[str, Any]
    worker_id: str
    stage_name: str
    lease_token: str
    lease_expires_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "job": copy.deepcopy(self.job),
            "lease": {
                "worker_id": self.worker_id,
                "stage_name": self.stage_name,
                "lease_token": self.lease_token,
                "lease_expires_at": self.lease_expires_at,
                "claimed_job_version": self.job["job_version"],
            },
        }


@dataclass(frozen=True)
class ProcessingJobClaimResult:
    """One bounded claim scan result."""

    claim: ProcessingJobClaim | None
    retry_required: bool = False


@dataclass(frozen=True)
class PublicationCandidate:
    """One processor-produced candidate bundle awaiting atomic publication."""

    candidate: dict[str, Any]
    evidence_manifest: dict[str, Any]
    previews: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class ProcessingResult:
    """The closed terminal result a configured internal processor may return."""

    disposition: str
    summary: str
    candidates: tuple[PublicationCandidate, ...] = ()


SuccessfulOutputValidator = Callable[[sqlite3.Connection, dict[str, Any]], None]


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("processing-job clock must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _parse_timestamp(value: str) -> datetime:
    try:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if _timestamp(parsed) != value:
            raise ValueError
        return parsed
    except (TypeError, ValueError) as error:
        raise ValueError("processing-job timestamp is invalid") from error


def _strict_json_object(raw: str | bytes) -> dict[str, Any]:
    """Decode one canonical, duplicate-free JSON object."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if unicodedata.normalize("NFC", key) != key or key in result:
                raise ValueError("processing-job JSON has invalid object keys")
            result[key] = value
        return result

    def integer(value: str) -> int:
        result = int(value)
        if abs(result) > MAX_SAFE_INTEGER:
            raise ValueError("processing-job JSON integer exceeds the safe range")
        return result

    def forbidden(_value: str) -> None:
        raise ValueError("processing-job JSON has a forbidden numeric value")

    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if not isinstance(raw, str):
        raise ValueError("processing-job JSON is not text")
    value = json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_int=integer,
        parse_float=forbidden,
        parse_constant=forbidden,
    )
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ValueError("processing-job JSON is not canonical")
    return value


def _strict_document(raw: str | bytes) -> dict[str, Any]:
    """Decode one canonical, duplicate-free runtime artifact."""

    value = _strict_json_object(raw)
    runtime_validate(value)
    return value


def _validate_completion_anchor(
    connection: sqlite3.Connection,
    job_row: sqlite3.Row,
    initial: dict[str, Any],
) -> None:
    """Bind version one to the durable SDK completion request and receipt."""

    completion = connection.execute(
        """SELECT completion_id,request_digest,request_json,response_bytes,accepted_at
             FROM completions WHERE session_id = ?""",
        (job_row["session_id"],),
    ).fetchone()
    if completion is None:
        raise ValueError("processing-job has no durable completion anchor")
    session = connection.execute(
        """SELECT state,scope_json,created_at,completed_at,completion_id,
                  raw_media_expires_at,derived_data_expires_at,
                  EXISTS(
                      SELECT 1 FROM pending_deletions
                       WHERE pending_deletions.session_id = sessions.session_id
                  ) AS deletion_pending
             FROM sessions WHERE session_id = ?""",
        (job_row["session_id"],),
    ).fetchone()
    if session is None:
        raise ValueError("processing-job has no durable session anchor")
    request = _strict_json_object(completion["request_json"])
    receipt = _strict_json_object(bytes(completion["response_bytes"]))
    scope = _strict_json_object(session["scope_json"])
    protocol_validate(request)
    protocol_validate(receipt)
    protocol_validate(scope)
    validate_operation_pair(request, receipt)
    manifest = request["capture_manifest"]
    expected_retention = {
        "policy_version": "tacua.retention@1.0.0",
        "raw_media_expires_at": _timestamp(
            _parse_timestamp(session["created_at"])
            + timedelta(days=scope["retention"]["raw_media_days"])
        ),
        "derived_data_expires_at": _timestamp(
            _parse_timestamp(session["created_at"])
            + timedelta(days=scope["retention"]["derived_data_days"])
        ),
        "deletion_status": "active",
    }
    diagnostic_digests = [
        item["envelope_digest"] for item in request["diagnostic_receipts"]
    ]
    if (
        request.get("message_type") != "completion_request"
        or receipt.get("message_type") != "completion_receipt"
        or completion["completion_id"] != request["completion_id"]
        or completion["completion_id"] != receipt["completion_id"]
        or completion["request_digest"] != request["request_digest"]
        or completion["request_digest"] != receipt["request_digest"]
        or completion["accepted_at"] != receipt["accepted_at"]
        or completion["accepted_at"] != initial["requested_at"]
        or session["state"] != "completed"
        or session["deletion_pending"] != 0
        or session["completion_id"] != completion["completion_id"]
        or session["completed_at"] != completion["accepted_at"]
        or session["raw_media_expires_at"]
        != expected_retention["raw_media_expires_at"]
        or session["derived_data_expires_at"]
        != expected_retention["derived_data_expires_at"]
        or manifest["retention"] != expected_retention
        or request["session_id"] != job_row["session_id"]
        or receipt["session_id"] != job_row["session_id"]
        or receipt["processing_job"] != initial
        or initial["session_id"] != job_row["session_id"]
        or initial["inputs"]["capture_manifest_digest"]
        != manifest["manifest_digest"]
        or initial["inputs"]["diagnostic_envelope_digests"]
        != diagnostic_digests
        or initial["inputs"]["context_sources"] != []
        or any(
            initial[field] != manifest[field]
            for field in (
                "organization_id",
                "project_id",
                "build_id",
                "build_identity_digest",
            )
        )
    ):
        raise ValueError("processing-job version one differs from its completion anchor")


def _validate_session_job_population(
    connection: sqlite3.Connection,
    *,
    organization_id: str | None,
    project_id: str | None,
    session_id: str | None = None,
) -> None:
    """Require every live session state to have its exact job population.

    A deletion transaction deliberately removes the job before filesystem
    erasure and the final session tombstone.  That one durable
    ``deleting``+``pending_deletions`` state is the only missing-job
    exemption.
    """

    # V1 is one organization/project per database. Sessions intentionally do
    # not duplicate those columns; their sealed scope_json carries the pin.
    # Job rows are scope-checked independently by _load_chain.
    _ = organization_id, project_id
    where: list[str] = []
    parameters: list[Any] = []
    if session_id is not None:
        where.append("sessions.session_id = ?")
        parameters.append(session_id)
    prefix = (" AND ".join(where) + " AND ") if where else ""
    inconsistent = connection.execute(
        f"""SELECT sessions.session_id
              FROM sessions
              LEFT JOIN completions
                ON completions.session_id = sessions.session_id
              LEFT JOIN jobs
                ON jobs.session_id = sessions.session_id
              LEFT JOIN pending_deletions
                ON pending_deletions.session_id = sessions.session_id
             WHERE {prefix}(
                    sessions.state NOT IN ('receiving','completed','deleting')
                 OR (
                    sessions.state = 'receiving'
                    AND (
                        sessions.completed_at IS NOT NULL
                        OR sessions.completion_id IS NOT NULL
                        OR completions.session_id IS NOT NULL
                        OR jobs.job_id IS NOT NULL
                        OR pending_deletions.session_id IS NOT NULL
                    )
                 )
                 OR (
                    sessions.state = 'completed'
                    AND (
                        sessions.completed_at IS NULL
                        OR sessions.completion_id IS NULL
                        OR completions.session_id IS NULL
                        OR sessions.completion_id != completions.completion_id
                        OR jobs.job_id IS NULL
                        OR pending_deletions.session_id IS NOT NULL
                    )
                 )
                 OR (
                    sessions.state = 'deleting'
                    AND (
                        pending_deletions.session_id IS NULL
                        OR jobs.job_id IS NOT NULL
                        OR (sessions.completed_at IS NULL)
                           != (completions.session_id IS NULL)
                        OR (sessions.completion_id IS NULL)
                           != (completions.session_id IS NULL)
                    )
                 )
             )
             LIMIT 1""",
        parameters,
    ).fetchone()
    if inconsistent is not None:
        raise ValueError("session and processing-job populations differ")


def initialize_processing_job_schema(connection: sqlite3.Connection) -> None:
    """Create/backfill history for valid schema-v2 heads, failing closed.

    Before this foundation, schema-v2 only ever wrote a sealed version-one
    queued snapshot to ``jobs`` and never mutated it.  Such rows can be
    backfilled losslessly.  A later-version row without its history cannot be
    authenticated and is rejected rather than silently adopted.
    """

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS tacua_processing_job_versions (
            job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
            job_version INTEGER NOT NULL CHECK (job_version >= 1),
            previous_job_digest TEXT,
            job_digest TEXT NOT NULL,
            status TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            canonical_json TEXT NOT NULL,
            PRIMARY KEY (job_id, job_version),
            UNIQUE (job_id, job_digest)
        );
        CREATE TABLE IF NOT EXISTS tacua_processing_job_leases (
            job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
            claimed_job_version INTEGER NOT NULL,
            worker_id TEXT NOT NULL,
            stage_name TEXT NOT NULL,
            token_verifier TEXT NOT NULL,
            acquired_at TEXT NOT NULL,
            renewed_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (job_id, claimed_job_version)
                REFERENCES tacua_processing_job_versions(job_id, job_version)
                ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS tacua_processing_job_versions_digest_idx
            ON tacua_processing_job_versions(job_id, previous_job_digest);
        CREATE INDEX IF NOT EXISTS tacua_processing_job_leases_expiry_idx
            ON tacua_processing_job_leases(expires_at, job_id);
        CREATE UNIQUE INDEX IF NOT EXISTS tacua_processing_jobs_session_idx
            ON jobs(session_id);
        """
    )
    try:
        connection.execute("BEGIN IMMEDIATE")
        orphan = connection.execute(
            """SELECT versions.job_id
                 FROM tacua_processing_job_versions AS versions
                 LEFT JOIN jobs ON jobs.job_id = versions.job_id
                WHERE jobs.job_id IS NULL LIMIT 1"""
        ).fetchone()
        if orphan is not None:
            raise ValueError("processing-job history has an orphan row")

        rows = connection.execute(
            """SELECT job_id,session_id,organization_id,project_id,status,
                      requested_at,job_json
                 FROM jobs ORDER BY job_id"""
        ).fetchall()
        for row in rows:
            count = connection.execute(
                """SELECT COUNT(*) FROM tacua_processing_job_versions
                    WHERE job_id = ?""",
                (row["job_id"],),
            ).fetchone()[0]
            if count == 0:
                head = _strict_document(row["job_json"])
                _validate_head_projection(row, head)
                if head["job_version"] != 1 or head["previous_job_digest"] is not None:
                    raise ValueError(
                        "a later processing-job head cannot be backfilled without history"
                    )
                _validate_initial(head)
                _validate_completion_anchor(connection, row, head)
                connection.execute(
                    """INSERT INTO tacua_processing_job_versions
                       (job_id,job_version,previous_job_digest,job_digest,status,
                        recorded_at,canonical_json)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        head["job_id"],
                        1,
                        None,
                        head["job_digest"],
                        head["status"],
                        head["requested_at"],
                        canonical_json(head),
                    ),
                )
        store = ProcessingJobStore(
            connection,
            organization_id=None,
            project_id=None,
            now=lambda: datetime.now(timezone.utc),
            token_verifier=lambda _job_id, _version, _token: "hmac-sha256:" + "0" * 64,
            token_factory=lambda: "x" * 43,
        )
        for row in rows:
            store._load_chain(row["job_id"], enforce_scope=False)
        store.validate_population()
        store._validate_all_leases()
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _validate_head_projection(row: sqlite3.Row, head: dict[str, Any]) -> None:
    if (
        row["job_id"] != head["job_id"]
        or row["session_id"] != head["session_id"]
        or row["organization_id"] != head["organization_id"]
        or row["project_id"] != head["project_id"]
        or row["status"] != head["status"]
        or row["requested_at"] != head["requested_at"]
        or row["job_json"] != canonical_json(head)
    ):
        raise ValueError("processing-job head projection differs from its artifact")


def _pipeline_configuration(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "pipeline_version": job["pipeline"]["pipeline_version"],
        "stage_names": [stage["name"] for stage in job["pipeline"]["stages"]],
    }


def _immutable_configuration(job: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(job[key])
        for key in (
            "contract_version",
            "media_type",
            "organization_id",
            "project_id",
            "build_id",
            "build_identity_digest",
            "session_id",
            "job_id",
            "requested_at",
            "inputs",
            "execution",
        )
    } | {"pipeline_configuration": _pipeline_configuration(job)}


def _validate_initial(job: dict[str, Any]) -> None:
    if (
        job["job_version"] != 1
        or job["previous_job_digest"] is not None
        or job["status"] != "queued"
        or job["started_at"] is not None
        or job["completed_at"] is not None
        or job["outputs"] is not None
        or job["failure"] is not None
        or any(
            stage != {
                "name": name,
                "state": "pending",
                "attempt_count": 0,
                "started_at": None,
                "completed_at": None,
                "detail": None,
            }
            for name, stage in zip(JOB_STAGES, job["pipeline"]["stages"], strict=True)
        )
    ):
        raise ValueError("processing-job version one is not the exact queued baseline")
    if job["execution"] != {
        "mode": "async",
        "max_attempts": 3,
        "egress": {
            "policy": "default_deny",
            "authorized": False,
            "authorization_decision_id": None,
            "destinations": [],
        },
    }:
        raise ValueError("processing-job execution policy escaped the V1 default-deny pin")


def _current_stage_index(job: dict[str, Any]) -> int | None:
    stages = job["pipeline"]["stages"]
    for index, stage in enumerate(stages):
        if stage["state"] != "succeeded":
            return index
    return None


def _validate_snapshot_semantics(job: dict[str, Any]) -> None:
    if job["status"] not in FOUNDATION_STATUSES:
        raise ValueError("processing-job status is outside the unstarted worker foundation")
    maximum = job["execution"]["max_attempts"]
    stages = job["pipeline"]["stages"]
    current = _current_stage_index(job)
    if any(stage["attempt_count"] > maximum for stage in stages):
        raise ValueError("processing-job stage exceeded max_attempts")
    if current is None:
        if (
            job["status"] != "succeeded"
            or any(
                stage["state"] != "succeeded"
                or stage["attempt_count"] < 1
                or stage["started_at"] is None
                or stage["completed_at"] is None
                for stage in stages
            )
            or job["started_at"] is None
            or job["completed_at"] is None
            or job["outputs"] is None
            or job["failure"] is not None
        ):
            raise ValueError("successful processing-job terminal snapshot is inconsistent")
        requested = _parse_timestamp(job["requested_at"])
        started = _parse_timestamp(job["started_at"])
        completed = _parse_timestamp(job["completed_at"])
        if started < requested or completed < started:
            raise ValueError("successful processing-job chronology is inconsistent")
        previous_completed = started
        for stage in stages:
            stage_started = _parse_timestamp(stage["started_at"])
            stage_completed = _parse_timestamp(stage["completed_at"])
            if stage_started < previous_completed or stage_completed < stage_started:
                raise ValueError("successful processing stages are not chronological")
            previous_completed = stage_completed
        if completed != previous_completed:
            raise ValueError("processing-job completion differs from its final stage")
        outputs = job["outputs"]
        candidate_refs = outputs["candidate_refs"]
        evidence_refs = outputs["derived_evidence_refs"]
        sorted_candidate_refs = sorted(
            candidate_refs,
            key=lambda item: (item["candidate_id"], item["candidate_version"]),
        )
        unique_candidate_refs = {
            (item["candidate_id"], item["candidate_version"])
            for item in candidate_refs
        }
        if candidate_refs != sorted_candidate_refs or len(unique_candidate_refs) != len(
            candidate_refs
        ):
            raise ValueError("processing-job candidate output references are not canonical")
        if evidence_refs != sorted(evidence_refs) or len(set(evidence_refs)) != len(
            evidence_refs
        ):
            raise ValueError("processing-job evidence output references are not canonical")
        if outputs["disposition"] == "no_issue_detected" and (
            candidate_refs or evidence_refs
        ):
            raise ValueError("no-issue processing result cannot publish artifacts")
        return
    for index, stage in enumerate(stages):
        if index < current:
            if (
                stage["state"] != "succeeded"
                or stage["attempt_count"] < 1
                or stage["started_at"] is None
                or stage["completed_at"] is None
            ):
                raise ValueError("completed pipeline prefix is inconsistent")
        elif index > current:
            if stage != {
                "name": JOB_STAGES[index],
                "state": "pending",
                "attempt_count": 0,
                "started_at": None,
                "completed_at": None,
                "detail": None,
            }:
                raise ValueError("future pipeline stage changed before its turn")
    active = stages[current]
    if job["status"] == "queued":
        if (
            active["state"] != "pending"
            or active["started_at"] is not None
            or active["completed_at"] is not None
            or active["detail"] is not None
            or job["completed_at"] is not None
            or job["outputs"] is not None
            or job["failure"] is not None
            or active["attempt_count"] >= maximum
        ):
            raise ValueError("queued processing-job does not expose an exact pending stage")
        if job["started_at"] is not None:
            raise ValueError("queued processing-job must reset its root start timestamp")
    elif job["status"] == "running":
        if (
            active["state"] not in {"running", "failed"}
            or active["attempt_count"] < 1
            or active["started_at"] is None
            or (active["state"] == "running" and active["completed_at"] is not None)
            or (active["state"] == "running" and active["detail"] is not None)
            or (active["state"] == "failed" and active["completed_at"] is None)
            or (active["state"] == "failed" and active["detail"] is None)
            or job["started_at"] is None
            or job["completed_at"] is not None
            or job["outputs"] is not None
            or job["failure"] is not None
        ):
            raise ValueError("running processing-job stage is inconsistent")
    elif job["status"] == "failed":
        failure = job["failure"]
        if (
            active["state"] != "failed"
            or active["attempt_count"] < 1
            or active["started_at"] is None
            or active["completed_at"] is None
            or active["detail"] is None
            or job["started_at"] is None
            or job["completed_at"] is None
            or job["outputs"] is not None
            or failure is None
            or failure["failed_stage"] != active["name"]
            or failure["retryable"] is not False
            or (
                failure["code"] == "STAGE_ATTEMPTS_EXHAUSTED"
                and active["attempt_count"] != maximum
            )
        ):
            raise ValueError("terminal processing-job failure is inconsistent")
    else:  # pragma: no cover - successful jobs returned above
        raise ValueError("processing-job status is inconsistent with its active stage")

    requested = _parse_timestamp(job["requested_at"])
    if job["started_at"] is not None and _parse_timestamp(job["started_at"]) < requested:
        raise ValueError("processing-job start predates its request")
    for stage in stages:
        if stage["started_at"] is not None:
            started = _parse_timestamp(stage["started_at"])
            if started < requested or (
                job["started_at"] is not None
                and started < _parse_timestamp(job["started_at"])
            ):
                raise ValueError("processing stage start predates the job")
            if stage["completed_at"] is not None and _parse_timestamp(
                stage["completed_at"]
            ) < started:
                raise ValueError("processing stage completed before it started")


def _changed_stage_indexes(before: dict[str, Any], after: dict[str, Any]) -> list[int]:
    return [
        index
        for index, (old, new) in enumerate(
            zip(before["pipeline"]["stages"], after["pipeline"]["stages"], strict=True)
        )
        if old != new
    ]


def _validate_transition(before: dict[str, Any], after: dict[str, Any]) -> None:
    if after["job_version"] != before["job_version"] + 1:
        raise ValueError("processing-job versions are not contiguous")
    if after["previous_job_digest"] != before["job_digest"]:
        raise ValueError("processing-job predecessor digest changed")
    if _immutable_configuration(after) != _immutable_configuration(before):
        raise ValueError("processing-job immutable scope/input/configuration changed")
    start_transition = (
        before["status"] == "queued"
        and before["started_at"] is None
        and after["status"] == "running"
        and after["started_at"] is not None
    ) or (
        before["status"] == "running"
        and before["started_at"] is not None
        and after["status"] == "queued"
        and after["started_at"] is None
    )
    if after["started_at"] != before["started_at"] and not start_transition:
        raise ValueError("processing-job root start timestamp changed")
    changed = _changed_stage_indexes(before, after)
    if len(changed) != 1:
        raise ValueError("one processing-job version must change exactly one stage")
    index = changed[0]
    old = before["pipeline"]["stages"][index]
    new = after["pipeline"]["stages"][index]
    current_before = _current_stage_index(before)
    if current_before != index:
        raise ValueError("processing-job transition skipped pipeline order")

    claim = (
        before["status"] == "queued"
        and old["state"] == "pending"
        and after["status"] == "running"
        and new
        == {
            **old,
            "state": "running",
            "attempt_count": old["attempt_count"] + 1,
            "started_at": new["started_at"],
        }
        and new["started_at"] is not None
        and after["completed_at"] is None
        and after["failure"] is None
        and after["outputs"] is None
    )
    checkpoint = (
        before["status"] == "running"
        and old["state"] == "running"
        and after["status"] == "queued"
        and new
        == {
            **old,
            "state": "succeeded",
            "completed_at": new["completed_at"],
            "detail": new["detail"],
        }
        and new["completed_at"] is not None
        and after["completed_at"] is None
        and after["failure"] is None
        and after["outputs"] is None
    )
    attempt_failed = (
        before["status"] == "running"
        and old["state"] == "running"
        and after["status"] == "running"
        and new
        == {
            **old,
            "state": "failed",
            "completed_at": new["completed_at"],
            "detail": new["detail"],
        }
        and new["completed_at"] is not None
        and new["detail"] is not None
        and new["attempt_count"] < after["execution"]["max_attempts"]
        and after["completed_at"] is None
        and after["failure"] is None
        and after["outputs"] is None
    )
    retry_queued = (
        before["status"] == "running"
        and old["state"] == "failed"
        and after["status"] == "queued"
        and new
        == {
            **old,
            "state": "pending",
            "started_at": None,
            "completed_at": None,
            "detail": None,
        }
        and after["completed_at"] is None
        and after["failure"] is None
        and after["outputs"] is None
        and new["attempt_count"] < after["execution"]["max_attempts"]
    )
    terminal_failure = (
        before["status"] == "running"
        and old["state"] == "running"
        and after["status"] == "failed"
        and new
        == {
            **old,
            "state": "failed",
            "completed_at": new["completed_at"],
            "detail": new["detail"],
        }
        and new["completed_at"] is not None
        and new["detail"] is not None
        and after["completed_at"] == new["completed_at"]
        and after["failure"] is not None
        and after["failure"]["failed_stage"] == new["name"]
        and after["failure"]["retryable"] is False
        and after["failure"]["detail"] == new["detail"]
        and after["outputs"] is None
    )
    terminal_success = (
        before["status"] == "running"
        and old["state"] == "running"
        and old["name"] == JOB_STAGES[-1]
        and after["status"] == "succeeded"
        and new
        == {
            **old,
            "state": "succeeded",
            "completed_at": new["completed_at"],
            "detail": new["detail"],
        }
        and new["completed_at"] is not None
        and after["completed_at"] == new["completed_at"]
        and after["outputs"] is not None
        and after["failure"] is None
    )
    if not (
        claim
        or checkpoint
        or attempt_failed
        or retry_queued
        or terminal_failure
        or terminal_success
    ):
        raise ValueError("processing-job state transition is not allowed")


class ProcessingJobStore:
    """Validated storage operations for a single deployment scope."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        organization_id: str | None,
        project_id: str | None,
        now: Callable[[], datetime],
        token_verifier: Callable[[str, int, str], str],
        token_factory: Callable[[], str],
        successful_output_validator: SuccessfulOutputValidator | None = None,
    ):
        self.connection = connection
        self.organization_id = organization_id
        self.project_id = project_id
        self.now = now
        self.token_verifier = token_verifier
        self.token_factory = token_factory
        self.successful_output_validator = successful_output_validator

    def _require_transaction(self) -> None:
        if not self.connection.in_transaction:
            raise ProcessingJobStoreError(
                500,
                "PROCESSING_JOB_TRANSACTION_REQUIRED",
                "processing-job validation requires one SQLite transaction",
            )

    def _storage_error(self, error: Exception) -> ProcessingJobStoreError:
        return ProcessingJobStoreError(
            500,
            "PROCESSING_JOB_STORAGE_CORRUPT",
            "stored processing-job state failed validation",
        )

    def _load_chain(
        self, job_id: str, *, enforce_scope: bool = True
    ) -> tuple[sqlite3.Row, list[dict[str, Any]]]:
        self._require_transaction()
        try:
            row = self.connection.execute(
                """SELECT job_id,session_id,organization_id,project_id,status,
                          requested_at,job_json
                     FROM jobs WHERE job_id = ?""",
                (job_id,),
            ).fetchone()
            if row is None:
                raise ProcessingJobStoreError(404, "JOB_NOT_FOUND", "job was not found")
            if enforce_scope and (
                row["organization_id"] != self.organization_id
                or row["project_id"] != self.project_id
            ):
                raise ProcessingJobStoreError(404, "JOB_NOT_FOUND", "job was not found")
            version_rows = self.connection.execute(
                """SELECT job_id,job_version,previous_job_digest,job_digest,status,
                          recorded_at,canonical_json
                     FROM tacua_processing_job_versions
                    WHERE job_id = ? ORDER BY job_version""",
                (job_id,),
            ).fetchall()
            if not version_rows:
                raise ValueError("processing-job has no version history")
            snapshots: list[dict[str, Any]] = []
            previous: dict[str, Any] | None = None
            previous_recorded: datetime | None = None
            first_started_at: str | None = None
            for expected_version, version_row in enumerate(version_rows, start=1):
                snapshot = _strict_document(version_row["canonical_json"])
                recorded = _parse_timestamp(version_row["recorded_at"])
                if (
                    version_row["job_id"] != job_id
                    or version_row["job_version"] != expected_version
                    or version_row["job_version"] != snapshot["job_version"]
                    or version_row["previous_job_digest"]
                    != snapshot["previous_job_digest"]
                    or version_row["job_digest"] != snapshot["job_digest"]
                    or version_row["status"] != snapshot["status"]
                    or recorded < _parse_timestamp(snapshot["requested_at"])
                    or (previous_recorded is not None and recorded < previous_recorded)
                ):
                    raise ValueError("processing-job version projection changed")
                if previous is None:
                    _validate_initial(snapshot)
                    if recorded != _parse_timestamp(snapshot["requested_at"]):
                        raise ValueError("initial processing-job record time changed")
                else:
                    _validate_transition(previous, snapshot)
                    changed = _changed_stage_indexes(previous, snapshot)
                    if len(changed) != 1:  # pragma: no cover - transition checked above
                        raise ValueError("processing-job event stage is ambiguous")
                    old_stage = previous["pipeline"]["stages"][changed[0]]
                    new_stage = snapshot["pipeline"]["stages"][changed[0]]
                    if new_stage["state"] == "running":
                        event_at = new_stage["started_at"]
                    elif new_stage["completed_at"] is not None:
                        event_at = new_stage["completed_at"]
                    elif old_stage["state"] == "failed" and new_stage["state"] == "pending":
                        event_at = version_rows[expected_version - 2]["recorded_at"]
                    else:  # pragma: no cover - transition checked above
                        raise ValueError("processing-job event chronology is ambiguous")
                    if event_at is None or recorded != _parse_timestamp(event_at):
                        raise ValueError("processing-job event time changed")
                _validate_snapshot_semantics(snapshot)
                if snapshot["started_at"] is not None:
                    if first_started_at is None:
                        first_started_at = snapshot["started_at"]
                    elif snapshot["started_at"] != first_started_at:
                        raise ValueError("processing-job original start timestamp changed")
                snapshots.append(snapshot)
                previous = snapshot
                previous_recorded = recorded
            head = snapshots[-1]
            _validate_head_projection(row, head)
            _validate_completion_anchor(self.connection, row, snapshots[0])
            if head["status"] == "succeeded" and self.successful_output_validator:
                try:
                    self.successful_output_validator(self.connection, copy.deepcopy(head))
                except Exception as error:
                    raise ValueError(
                        "successful processing outputs failed publication validation"
                    ) from error
            lease = self.connection.execute(
                """SELECT claimed_job_version,worker_id,stage_name,token_verifier,
                          acquired_at,renewed_at,expires_at
                     FROM tacua_processing_job_leases WHERE job_id = ?""",
                (job_id,),
            ).fetchone()
            current = _current_stage_index(head)
            if head["status"] == "running":
                if (
                    lease is None
                    or current is None
                    or head["pipeline"]["stages"][current]["state"] != "running"
                    or lease["claimed_job_version"] != head["job_version"]
                    or lease["stage_name"]
                    != head["pipeline"]["stages"][current]["name"]
                    or ID_PATTERN.fullmatch(lease["worker_id"]) is None
                    or VERIFIER_PATTERN.fullmatch(lease["token_verifier"]) is None
                    or _parse_timestamp(lease["acquired_at"])
                    != _parse_timestamp(
                        head["pipeline"]["stages"][current]["started_at"]
                    )
                    or _parse_timestamp(lease["acquired_at"]) != previous_recorded
                    or _parse_timestamp(lease["renewed_at"])
                    < _parse_timestamp(lease["acquired_at"])
                    or _parse_timestamp(lease["expires_at"])
                    <= _parse_timestamp(lease["renewed_at"])
                    or _parse_timestamp(lease["expires_at"])
                    != _parse_timestamp(lease["renewed_at"])
                    + timedelta(seconds=LEASE_SECONDS)
                ):
                    raise ValueError("running processing-job head has no exact lease")
            elif lease is not None:
                raise ValueError("non-running processing-job retained a lease")
            return row, snapshots
        except ProcessingJobStoreError:
            raise
        except (
            ContractError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            sqlite3.Error,
        ) as error:
            raise self._storage_error(error) from error

    @_map_sqlite_errors
    def _validate_all_leases(self) -> None:
        self._require_transaction()
        leases = self.connection.execute(
            """SELECT job_id,claimed_job_version,worker_id,stage_name,
                      token_verifier,acquired_at,renewed_at,expires_at
                 FROM tacua_processing_job_leases ORDER BY job_id"""
        ).fetchall()
        for lease in leases:
            _row, history = self._load_chain(lease["job_id"], enforce_scope=False)
            head = history[-1]
            current = _current_stage_index(head)
            if (
                head["status"] != "running"
                or current is None
                or head["pipeline"]["stages"][current]["state"] != "running"
                or lease["claimed_job_version"] != head["job_version"]
                or lease["worker_id"] is None
                or ID_PATTERN.fullmatch(lease["worker_id"]) is None
                or lease["stage_name"] != head["pipeline"]["stages"][current]["name"]
                or VERIFIER_PATTERN.fullmatch(lease["token_verifier"]) is None
                or _parse_timestamp(lease["renewed_at"])
                < _parse_timestamp(lease["acquired_at"])
                or _parse_timestamp(lease["expires_at"])
                <= _parse_timestamp(lease["renewed_at"])
                or _parse_timestamp(lease["expires_at"])
                > _parse_timestamp(lease["renewed_at"])
                + timedelta(seconds=LEASE_SECONDS)
            ):
                raise ValueError("processing-job lease differs from its running head")
        running_ids = {
            row["job_id"]
            for row in self.connection.execute(
                "SELECT job_id FROM jobs WHERE status = 'running'"
            )
        }
        if running_ids != {lease["job_id"] for lease in leases}:
            raise ValueError("every running processing-job head requires one exact lease")

    @_map_sqlite_errors
    def put_initial(self, job: dict[str, Any]) -> None:
        self._require_transaction()
        try:
            runtime_validate(job)
            _validate_initial(job)
            _validate_snapshot_semantics(job)
            row = self.connection.execute(
                """SELECT job_id,session_id,organization_id,project_id,status,
                          requested_at,job_json FROM jobs WHERE job_id = ?""",
                (job["job_id"],),
            ).fetchone()
            if row is None:
                raise ValueError("processing-job head was not inserted")
            _validate_head_projection(row, job)
            _validate_completion_anchor(self.connection, row, job)
            self.connection.execute(
                """INSERT INTO tacua_processing_job_versions
                   (job_id,job_version,previous_job_digest,job_digest,status,
                    recorded_at,canonical_json)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    job["job_id"],
                    1,
                    None,
                    job["job_digest"],
                    job["status"],
                    job["requested_at"],
                    canonical_json(job),
                ),
            )
        except (ContractError, KeyError, TypeError, ValueError, sqlite3.Error) as error:
            raise self._storage_error(error) from error

    def _event_time(self, history: list[dict[str, Any]]) -> datetime:
        now = self._now()
        row = self.connection.execute(
            """SELECT recorded_at FROM tacua_processing_job_versions
                WHERE job_id = ? ORDER BY job_version DESC LIMIT 1""",
            (history[-1]["job_id"],),
        ).fetchone()
        latest = _parse_timestamp(row["recorded_at"])
        return max(now, latest)

    def _now(self) -> datetime:
        now = self.now()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ProcessingJobStoreError(
                500, "PROCESSING_CLOCK_INVALID", "processing-job clock is invalid"
            )
        return now.astimezone(timezone.utc).replace(microsecond=0)

    def _append(self, history: list[dict[str, Any]], changed: dict[str, Any], at: datetime) -> dict[str, Any]:
        previous = history[-1]
        changed["job_version"] = previous["job_version"] + 1
        changed["previous_job_digest"] = previous["job_digest"]
        changed["job_digest"] = "sha256:" + "0" * 64
        try:
            snapshot = runtime_seal(changed)
            runtime_validate(snapshot)
            _validate_snapshot_semantics(snapshot)
            _validate_transition(previous, snapshot)
        except (ContractError, KeyError, TypeError, ValueError) as error:
            raise ProcessingJobStoreError(
                500,
                "PROCESSING_JOB_TRANSITION_INVALID",
                "processing-job transition could not be sealed",
            ) from error
        encoded = canonical_json(snapshot)
        cursor = self.connection.execute(
            """UPDATE jobs SET status = ?, job_json = ?
                WHERE job_id = ? AND status = ? AND job_json = ?""",
            (
                snapshot["status"],
                encoded,
                snapshot["job_id"],
                previous["status"],
                canonical_json(previous),
            ),
        )
        if cursor.rowcount != 1:
            raise ProcessingJobStoreError(
                409, "PROCESSING_JOB_STATE_CONFLICT", "processing-job head changed"
            )
        self.connection.execute(
            """INSERT INTO tacua_processing_job_versions
               (job_id,job_version,previous_job_digest,job_digest,status,
                recorded_at,canonical_json)
               VALUES (?,?,?,?,?,?,?)""",
            (
                snapshot["job_id"],
                snapshot["job_version"],
                snapshot["previous_job_digest"],
                snapshot["job_digest"],
                snapshot["status"],
                _timestamp(at),
                encoded,
            ),
        )
        history.append(snapshot)
        return snapshot

    def _require_active_session(self, job: dict[str, Any], now: datetime) -> None:
        session = self.connection.execute(
            """SELECT state,raw_media_expires_at,derived_data_expires_at
                 FROM sessions WHERE session_id = ?""",
            (job["session_id"],),
        ).fetchone()
        pending = self.connection.execute(
            "SELECT 1 FROM pending_deletions WHERE session_id = ?",
            (job["session_id"],),
        ).fetchone()
        if session is None or session["state"] == "deleting" or pending is not None:
            raise ProcessingJobStoreError(
                410, "SESSION_DELETED", "processing session was deleted"
            )
        if session["state"] != "completed":
            raise ProcessingJobStoreError(
                409, "SESSION_NOT_COMPLETED", "processing session is not completed"
            )
        if (
            session["raw_media_expires_at"] != session["derived_data_expires_at"]
            or _parse_timestamp(session["raw_media_expires_at"]) <= now
        ):
            raise ProcessingJobStoreError(
                410, "SESSION_RETENTION_EXPIRED", "processing session retention expired"
            )

    @_map_sqlite_errors
    def get(self, job_id: str) -> dict[str, Any]:
        _row, history = self._load_chain(job_id)
        return copy.deepcopy(history[-1])

    @_map_sqlite_errors
    def validate_population(self, *, session_id: str | None = None) -> None:
        self._require_transaction()
        try:
            _validate_session_job_population(
                self.connection,
                organization_id=self.organization_id,
                project_id=self.project_id,
                session_id=session_id,
            )
        except (KeyError, TypeError, ValueError, sqlite3.Error) as error:
            raise self._storage_error(error) from error

    @_map_sqlite_errors
    def list(self, *, session_id: str | None = None) -> list[dict[str, Any]]:
        self.validate_population(session_id=session_id)
        parameters: list[Any] = []
        where = []
        if self.organization_id is not None:
            where.append("organization_id = ?")
            parameters.append(self.organization_id)
        if self.project_id is not None:
            where.append("project_id = ?")
            parameters.append(self.project_id)
        if session_id is not None:
            where.append("session_id = ?")
            parameters.append(session_id)
        query = "SELECT job_id FROM jobs"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY requested_at DESC, job_id DESC"
        rows = self.connection.execute(query, parameters).fetchall()
        return [self.get(row["job_id"]) for row in rows]

    def _assert_lease(
        self, job_id: str, stage_name: str, lease_token: str, now: datetime
    ) -> tuple[list[dict[str, Any]], sqlite3.Row]:
        _row, history = self._load_chain(job_id)
        head = history[-1]
        self._require_active_session(head, now)
        lease = self.connection.execute(
            """SELECT job_id,claimed_job_version,worker_id,stage_name,
                      token_verifier,acquired_at,renewed_at,expires_at
                 FROM tacua_processing_job_leases WHERE job_id = ?""",
            (job_id,),
        ).fetchone()
        if not isinstance(lease_token, str) or TOKEN_PATTERN.fullmatch(lease_token) is None:
            raise ProcessingJobStoreError(
                409, "PROCESSING_LEASE_STALE", "processing-job lease is stale"
            )
        supplied = self.token_verifier(job_id, head["job_version"], lease_token)
        if (
            lease is None
            or head["status"] != "running"
            or lease["claimed_job_version"] != head["job_version"]
            or lease["stage_name"] != stage_name
            or _parse_timestamp(lease["expires_at"]) <= now
            or not hmac.compare_digest(lease["token_verifier"], supplied)
        ):
            raise ProcessingJobStoreError(
                409, "PROCESSING_LEASE_STALE", "processing-job lease is stale"
            )
        current = _current_stage_index(head)
        if (
            current is None
            or head["pipeline"]["stages"][current]["name"] != stage_name
            or head["pipeline"]["stages"][current]["state"] != "running"
        ):
            raise ProcessingJobStoreError(
                409, "PROCESSING_STAGE_MISMATCH", "processing stage is not lease-owned"
            )
        return history, lease

    @_map_sqlite_errors
    def validate_stage_lease(
        self, job_id: str, stage_name: str, lease_token: str
    ) -> tuple[dict[str, Any], str]:
        """Read-validate one exact live stage lease without mutating it."""

        self._require_transaction()
        if stage_name not in JOB_STAGES:
            raise ProcessingJobStoreError(
                409,
                "PROCESSING_STAGE_MISMATCH",
                "processing stage is not lease-owned",
            )
        history, lease = self._assert_lease(
            job_id, stage_name, lease_token, self._now()
        )
        return copy.deepcopy(history[-1]), lease["worker_id"]

    @_map_sqlite_errors
    def validate_publication_lease(
        self, job_id: str, lease_token: str
    ) -> tuple[dict[str, Any], str]:
        """Read-validate the exact live final-stage lease without mutating it."""

        job, worker_id = self.validate_stage_lease(
            job_id, JOB_STAGES[-1], lease_token
        )
        current = _current_stage_index(job)
        if current != len(JOB_STAGES) - 1:
            raise ProcessingJobStoreError(
                409,
                "PROCESSING_STAGE_MISMATCH",
                "processing result is only valid for the final stage",
            )
        return job, worker_id

    def _record_retryable_failure(
        self,
        history: list[dict[str, Any]],
        *,
        stage_index: int,
        detail: str,
        at: datetime,
    ) -> dict[str, Any]:
        failed = copy.deepcopy(history[-1])
        stage = failed["pipeline"]["stages"][stage_index]
        stage.update(state="failed", completed_at=_timestamp(at), detail=detail)
        self._append(history, failed, at)
        queued = copy.deepcopy(history[-1])
        queued["status"] = "queued"
        queued["started_at"] = None
        stage = queued["pipeline"]["stages"][stage_index]
        stage.update(state="pending", started_at=None, completed_at=None, detail=None)
        return self._append(history, queued, at)

    def _record_terminal_failure(
        self,
        history: list[dict[str, Any]],
        *,
        stage_index: int,
        code: str,
        detail: str,
        at: datetime,
    ) -> dict[str, Any]:
        failed = copy.deepcopy(history[-1])
        stage = failed["pipeline"]["stages"][stage_index]
        stage.update(state="failed", completed_at=_timestamp(at), detail=detail)
        failed["status"] = "failed"
        failed["completed_at"] = _timestamp(at)
        failed["failure"] = {
            "code": code,
            "failed_stage": stage["name"],
            "retryable": False,
            "detail": detail,
        }
        return self._append(history, failed, at)

    @_map_sqlite_errors
    def claim(self, worker_id: str) -> ProcessingJobClaimResult:
        self._require_transaction()
        if not isinstance(worker_id, str) or ID_PATTERN.fullmatch(worker_id) is None:
            raise ProcessingJobStoreError(400, "WORKER_ID_INVALID", "worker_id is invalid")
        now = self._now()
        now_text = _timestamp(now)
        self.validate_population()
        inconsistent = self.connection.execute(
            """SELECT jobs.job_id
                 FROM jobs
                 LEFT JOIN tacua_processing_job_leases AS leases
                        ON leases.job_id = jobs.job_id
                WHERE jobs.organization_id = ? AND jobs.project_id = ?
                  AND (
                      jobs.status NOT IN ('queued','running','succeeded','failed')
                      OR (jobs.status = 'running' AND leases.job_id IS NULL)
                      OR (jobs.status != 'running' AND leases.job_id IS NOT NULL)
                      OR (
                          jobs.status = 'running'
                          AND leases.claimed_job_version != (
                              SELECT MAX(versions.job_version)
                                FROM tacua_processing_job_versions AS versions
                               WHERE versions.job_id = jobs.job_id
                          )
                      )
                  )
                LIMIT 1""",
            (self.organization_id, self.project_id),
        ).fetchone()
        if inconsistent is not None:
            raise self._storage_error(
                ValueError("processing-job head/lease population is inconsistent")
            )
        candidates = self.connection.execute(
            """SELECT jobs.job_id
                 FROM jobs
                 JOIN sessions ON sessions.session_id = jobs.session_id
                 LEFT JOIN tacua_processing_job_leases AS leases
                        ON leases.job_id = jobs.job_id
                WHERE jobs.organization_id = ? AND jobs.project_id = ?
                  AND sessions.state = 'completed'
                  AND sessions.raw_media_expires_at > ?
                  AND sessions.derived_data_expires_at > ?
                  AND NOT EXISTS (
                      SELECT 1 FROM pending_deletions
                       WHERE pending_deletions.session_id = jobs.session_id
                  )
                  AND (
                      (jobs.status = 'queued' AND leases.job_id IS NULL)
                      OR
                      (jobs.status = 'running' AND leases.expires_at <= ?)
                  )
                ORDER BY jobs.requested_at ASC, jobs.job_id ASC
                LIMIT ?""",
            (
                self.organization_id,
                self.project_id,
                now_text,
                now_text,
                now_text,
                MAX_CLAIM_SCAN + 1,
            ),
        ).fetchall()
        has_more = len(candidates) > MAX_CLAIM_SCAN
        for candidate in candidates[:MAX_CLAIM_SCAN]:
            _row, history = self._load_chain(candidate["job_id"])
            head = history[-1]
            self._require_active_session(head, now)
            current = _current_stage_index(head)
            if current is None:
                raise self._storage_error(ValueError("processing job has no claimable stage"))
            stage = head["pipeline"]["stages"][current]
            if head["status"] == "running":
                lease = self.connection.execute(
                    "SELECT * FROM tacua_processing_job_leases WHERE job_id = ?",
                    (head["job_id"],),
                ).fetchone()
                if (
                    lease is None
                    or lease["claimed_job_version"] != head["job_version"]
                    or lease["stage_name"] != stage["name"]
                    or stage["state"] != "running"
                    or _parse_timestamp(lease["expires_at"]) > now
                ):
                    raise self._storage_error(ValueError("expired lease projection changed"))
                if stage["attempt_count"] >= head["execution"]["max_attempts"]:
                    self._record_terminal_failure(
                        history,
                        stage_index=current,
                        code="STAGE_ATTEMPTS_EXHAUSTED",
                        detail="The processing lease expired after the final permitted attempt.",
                        at=self._event_time(history),
                    )
                    self.connection.execute(
                        "DELETE FROM tacua_processing_job_leases WHERE job_id = ?",
                        (head["job_id"],),
                    )
                    continue
                event_time = self._event_time(history)
                self._record_retryable_failure(
                    history,
                    stage_index=current,
                    detail="The processing lease expired before a checkpoint.",
                    at=event_time,
                )
                self.connection.execute(
                    "DELETE FROM tacua_processing_job_leases WHERE job_id = ?",
                    (head["job_id"],),
                )
                head = history[-1]
                stage = head["pipeline"]["stages"][current]

            if head["status"] != "queued" or stage["state"] != "pending":
                raise self._storage_error(ValueError("queued processing head is not claimable"))
            if stage["attempt_count"] >= head["execution"]["max_attempts"]:
                raise self._storage_error(ValueError("exhausted stage remained queued"))
            event_time = self._event_time(history)
            running = copy.deepcopy(head)
            running["status"] = "running"
            running["started_at"] = next(
                (
                    snapshot["started_at"]
                    for snapshot in history
                    if snapshot["started_at"] is not None
                ),
                _timestamp(event_time),
            )
            running_stage = running["pipeline"]["stages"][current]
            running_stage.update(
                state="running",
                attempt_count=stage["attempt_count"] + 1,
                started_at=_timestamp(event_time),
                completed_at=None,
                detail=None,
            )
            running = self._append(history, running, event_time)
            token = self.token_factory()
            if not isinstance(token, str) or TOKEN_PATTERN.fullmatch(token) is None:
                raise ProcessingJobStoreError(
                    500, "PROCESSING_TOKEN_INVALID", "processing lease token is invalid"
                )
            expires = event_time + timedelta(seconds=LEASE_SECONDS)
            verifier = self.token_verifier(running["job_id"], running["job_version"], token)
            if VERIFIER_PATTERN.fullmatch(verifier) is None:
                raise ProcessingJobStoreError(
                    500, "PROCESSING_TOKEN_INVALID", "processing lease verifier is invalid"
                )
            self.connection.execute(
                """INSERT INTO tacua_processing_job_leases
                   (job_id,claimed_job_version,worker_id,stage_name,token_verifier,
                    acquired_at,renewed_at,expires_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    running["job_id"],
                    running["job_version"],
                    worker_id,
                    running_stage["name"],
                    verifier,
                    _timestamp(event_time),
                    _timestamp(event_time),
                    _timestamp(expires),
                ),
            )
            return ProcessingJobClaimResult(
                ProcessingJobClaim(
                    job=copy.deepcopy(running),
                    worker_id=worker_id,
                    stage_name=running_stage["name"],
                    lease_token=token,
                    lease_expires_at=_timestamp(expires),
                )
            )
        return ProcessingJobClaimResult(None, retry_required=has_more)

    @_map_sqlite_errors
    def renew(
        self,
        job_id: str,
        stage_name: str,
        lease_token: str,
    ) -> dict[str, Any]:
        """Extend one unexpired lease without changing its sealed job head."""

        self._require_transaction()
        now = self._now()
        history, lease = self._assert_lease(job_id, stage_name, lease_token, now)
        current_expiry = _parse_timestamp(lease["expires_at"])
        renewed_expiry = now + timedelta(seconds=LEASE_SECONDS)
        if renewed_expiry <= current_expiry:
            raise ProcessingJobStoreError(
                409,
                "PROCESSING_LEASE_RENEWAL_EARLY",
                "processing-job lease cannot be extended further yet",
            )
        verifier = self.token_verifier(job_id, history[-1]["job_version"], lease_token)
        cursor = self.connection.execute(
            """UPDATE tacua_processing_job_leases
                  SET renewed_at = ?, expires_at = ?
                WHERE job_id = ? AND claimed_job_version = ? AND stage_name = ?
                  AND token_verifier = ? AND expires_at = ?""",
            (
                _timestamp(now),
                _timestamp(renewed_expiry),
                job_id,
                history[-1]["job_version"],
                stage_name,
                verifier,
                lease["expires_at"],
            ),
        )
        if cursor.rowcount != 1:
            raise ProcessingJobStoreError(
                409, "PROCESSING_LEASE_STALE", "processing-job lease is stale"
            )
        return {
            "job_id": job_id,
            "job_version": history[-1]["job_version"],
            "worker_id": lease["worker_id"],
            "stage_name": stage_name,
            "lease_expires_at": _timestamp(renewed_expiry),
        }

    @_map_sqlite_errors
    def checkpoint(
        self,
        job_id: str,
        stage_name: str,
        lease_token: str,
        *,
        detail: str | None = None,
    ) -> dict[str, Any]:
        self._require_transaction()
        now = self._now()
        history, _lease = self._assert_lease(job_id, stage_name, lease_token, now)
        current = _current_stage_index(history[-1])
        if current is None or current == len(JOB_STAGES) - 1:
            raise ProcessingJobStoreError(
                409,
                "PROCESSING_PUBLICATION_REQUIRED",
                "final processing completion requires an atomic processing result",
            )
        if detail is not None and (
            not isinstance(detail, str)
            or not 1 <= len(detail) <= 4096
            or unicodedata.normalize("NFC", detail) != detail
        ):
            raise ProcessingJobStoreError(
                400, "PROCESSING_DETAIL_INVALID", "checkpoint detail is invalid"
            )
        event_time = self._event_time(history)
        queued = copy.deepcopy(history[-1])
        queued["status"] = "queued"
        queued["started_at"] = None
        stage = queued["pipeline"]["stages"][current]
        stage.update(state="succeeded", completed_at=_timestamp(event_time), detail=detail)
        result = self._append(history, queued, event_time)
        self.connection.execute(
            "DELETE FROM tacua_processing_job_leases WHERE job_id = ?", (job_id,)
        )
        return copy.deepcopy(result)

    @_map_sqlite_errors
    def succeed(
        self,
        job_id: str,
        stage_name: str,
        lease_token: str,
        *,
        outputs: dict[str, Any],
    ) -> dict[str, Any]:
        """Append the one terminal success snapshot and release its exact lease.

        Candidate/evidence persistence is intentionally owned by the caller's
        same SQLite transaction. This method only seals the job-side half of
        that publication boundary.
        """

        self._require_transaction()
        if not isinstance(outputs, dict) or set(outputs) != {
            "disposition",
            "candidate_refs",
            "derived_evidence_refs",
            "summary",
        }:
            raise ProcessingJobStoreError(
                400, "PROCESSING_RESULT_INVALID", "processing result is invalid"
            )
        now = self._now()
        history, _lease = self._assert_lease(job_id, stage_name, lease_token, now)
        current = _current_stage_index(history[-1])
        if current is None or current != len(JOB_STAGES) - 1:
            raise ProcessingJobStoreError(
                409,
                "PROCESSING_STAGE_MISMATCH",
                "processing result is only valid for the final stage",
            )
        event_time = self._event_time(history)
        succeeded = copy.deepcopy(history[-1])
        succeeded["status"] = "succeeded"
        succeeded["completed_at"] = _timestamp(event_time)
        succeeded["outputs"] = copy.deepcopy(outputs)
        stage = succeeded["pipeline"]["stages"][current]
        stage.update(
            state="succeeded",
            completed_at=_timestamp(event_time),
            detail="The processing result was published atomically.",
        )
        result = self._append(history, succeeded, event_time)
        removed = self.connection.execute(
            "DELETE FROM tacua_processing_job_leases WHERE job_id = ?", (job_id,)
        )
        if removed.rowcount != 1:
            raise ProcessingJobStoreError(
                409, "PROCESSING_LEASE_STALE", "processing-job lease is stale"
            )
        return copy.deepcopy(result)

    @_map_sqlite_errors
    def fail(
        self,
        job_id: str,
        stage_name: str,
        lease_token: str,
        *,
        code: str,
        detail: str,
        retryable: bool,
    ) -> dict[str, Any]:
        self._require_transaction()
        if not isinstance(code, str) or FAILURE_CODE_PATTERN.fullmatch(code) is None:
            raise ProcessingJobStoreError(
                400, "PROCESSING_FAILURE_INVALID", "failure code is invalid"
            )
        if code == "STAGE_ATTEMPTS_EXHAUSTED":
            raise ProcessingJobStoreError(
                400,
                "PROCESSING_FAILURE_INVALID",
                "failure code is reserved for store-owned attempt exhaustion",
            )
        if (
            not isinstance(detail, str)
            or not 1 <= len(detail) <= 1024
            or unicodedata.normalize("NFC", detail) != detail
        ):
            raise ProcessingJobStoreError(
                400, "PROCESSING_FAILURE_INVALID", "failure detail is invalid"
            )
        if not isinstance(retryable, bool):
            raise ProcessingJobStoreError(
                400, "PROCESSING_FAILURE_INVALID", "retryable must be boolean"
            )
        if not retryable and len(detail) > 512:
            raise ProcessingJobStoreError(
                400,
                "PROCESSING_FAILURE_INVALID",
                "terminal failure detail is invalid",
            )
        now = self._now()
        history, _lease = self._assert_lease(job_id, stage_name, lease_token, now)
        current = _current_stage_index(history[-1])
        if current is None:
            raise self._storage_error(ValueError("processing job has no active stage"))
        event_time = self._event_time(history)
        stage = history[-1]["pipeline"]["stages"][current]
        if retryable and stage["attempt_count"] < history[-1]["execution"]["max_attempts"]:
            result = self._record_retryable_failure(
                history, stage_index=current, detail=detail, at=event_time
            )
        else:
            terminal_code = "STAGE_ATTEMPTS_EXHAUSTED" if retryable else code
            terminal_detail = (
                "The processing stage exhausted its permitted attempts."
                if retryable
                else detail
            )
            result = self._record_terminal_failure(
                history,
                stage_index=current,
                code=terminal_code,
                detail=terminal_detail,
                at=event_time,
            )
        self.connection.execute(
            "DELETE FROM tacua_processing_job_leases WHERE job_id = ?", (job_id,)
        )
        return copy.deepcopy(result)
