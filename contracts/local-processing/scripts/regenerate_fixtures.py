#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministically regenerate the synthetic local-processing fixture corpus."""

from __future__ import annotations

import argparse
import base64
import copy
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parents[1]
for source in (
    ROOT / "src",
    REPOSITORY / "contracts" / "ticket-candidate" / "src",
    REPOSITORY / "services" / "backend" / "src",
):
    sys.path.insert(0, str(source))

import local_processing_contract as contract  # noqa: E402
import ticket_candidate_contract as ticket_candidate  # noqa: E402
from tacua_backend import evidence_domain  # noqa: E402


FIXTURES = ROOT / "fixtures"
SYNTHETIC_TRANSCRIPT = "Synthetic transcript fixture; never production evidence."
DIAGNOSTIC_ENVELOPE_DIGEST = "sha256:" + "d" * 64
DIAGNOSTIC_CONTENT_DIGEST = "sha256:" + "e" * 64
PREVIEW_BODY = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "YAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _command(version: str) -> dict[str, Any]:
    return {
        "argv": [
            "/usr/bin/python3",
            "/opt/tacua-processor/processor.py",
            "--input",
            contract.INPUT_PLACEHOLDER,
            "--output-directory",
            contract.OUTPUT_DIRECTORY_PLACEHOLDER,
        ],
        "contract_version": version,
        "max_stderr_bytes": 65_536,
        "max_stdout_bytes": 4_194_304,
        "timeout_seconds": 240,
    }


def _manifest(build_identity: dict[str, Any]) -> dict[str, Any]:
    value = _read_json(
        REPOSITORY / "contracts" / "runtime" / "fixtures" / "positive" / "capture.json"
    )
    value["build_identity_digest"] = build_identity["build_identity_digest"]
    value["upload"]["remote_session_id"] = value["session_id"]
    value = contract.runtime.seal(value)
    contract.runtime.validate(value)
    return value


def _stage(
    name: str,
    state: str,
    attempt: int,
    started: str | None,
    completed: str | None,
) -> dict[str, Any]:
    return {
        "attempt_count": attempt,
        "completed_at": completed,
        "detail": None,
        "name": name,
        "started_at": started,
        "state": state,
    }


def _job(
    *,
    stage_name: str,
    pipeline_version: str,
    job_version: int,
    current_attempt: int,
    build_identity: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    current = contract.JOB_STAGES.index(stage_name)
    stages = []
    for index, name in enumerate(contract.JOB_STAGES):
        if index < current:
            started_second = index * 2
            completed_second = started_second + 1
            stages.append(
                _stage(
                    name,
                    "succeeded",
                    1,
                    f"2026-07-21T10:03:{started_second:02d}Z",
                    f"2026-07-21T10:03:{completed_second:02d}Z",
                )
            )
        elif index == current:
            stages.append(
                _stage(
                    name,
                    "running",
                    current_attempt,
                    f"2026-07-21T10:03:{index * 2:02d}Z",
                    None,
                )
            )
        else:
            stages.append(_stage(name, "pending", 0, None, None))
    value = {
        "build_id": build_identity["build_id"],
        "build_identity_digest": build_identity["build_identity_digest"],
        "completed_at": None,
        "contract_version": "tacua.processing-job@1.0.0",
        "execution": {
            "egress": {
                "authorization_decision_id": None,
                "authorized": False,
                "destinations": [],
                "policy": "default_deny",
            },
            "max_attempts": 3,
            "mode": "async",
        },
        "failure": None,
        "inputs": {
            "capture_manifest_digest": manifest["manifest_digest"],
            "context_sources": [],
            "diagnostic_envelope_digests": [DIAGNOSTIC_ENVELOPE_DIGEST],
        },
        "job_digest": "sha256:" + "0" * 64,
        "job_id": "job_synthetic",
        "job_version": job_version,
        "media_type": "application/vnd.tacua.processing-job+json;version=1.0.0",
        "organization_id": manifest["organization_id"],
        "outputs": None,
        "pipeline": {"pipeline_version": pipeline_version, "stages": stages},
        "previous_job_digest": "sha256:" + "b" * 64,
        "project_id": manifest["project_id"],
        "requested_at": "2026-07-21T10:02:05Z",
        "session_id": manifest["session_id"],
        "started_at": "2026-07-21T10:03:00Z",
        "status": "running",
    }
    value = contract.runtime.seal(value)
    contract.runtime.validate(value)
    return value


def _capture(
    *,
    build_identity: dict[str, Any],
    manifest: dict[str, Any],
    isolated: bool = False,
) -> dict[str, Any]:
    prefix = (
        "/tacua-private-12345-aaaaaaaaaaaaaaaaaaaaaaaa/input/evidence"
        if isolated
        else "/dev/fd"
    )
    segment_path = f"{prefix}/evidence-000000.bin" if isolated else f"{prefix}/9"
    diagnostic_path = f"{prefix}/evidence-000001.bin" if isolated else f"{prefix}/10"
    segment = manifest["segments"][0]
    return {
        "build_identity": copy.deepcopy(build_identity),
        "derived_data_expires_at": manifest["retention"]["derived_data_expires_at"],
        "diagnostics": [
            {
                "content_digest": DIAGNOSTIC_CONTENT_DIGEST,
                "envelope_digest": DIAGNOSTIC_ENVELOPE_DIGEST,
                "envelope_id": "envelope_synthetic",
                "read_only_path": diagnostic_path,
                "received_at": "2026-07-21T10:02:04Z",
                "size_bytes": 3774,
            }
        ],
        "manifest": copy.deepcopy(manifest),
        "raw_media_expires_at": manifest["retention"]["raw_media_expires_at"],
        "segments": [
            {
                "content_digest": segment["content"]["content_digest"],
                "content_type": segment["content"]["content_type"],
                "read_only_path": segment_path,
                "received_at": "2026-07-21T10:02:00Z",
                "segment_id": segment["segment_id"],
                "sequence": segment["sequence"],
                "sidecar_digest": segment["content"]["sidecar_digest"],
                "size_bytes": segment["content"]["size_bytes"],
            }
        ],
        "session_completed_at": "2026-07-21T10:02:05Z",
        "session_created_at": "2026-07-21T10:00:00Z",
    }


def _replace_evidence_ids(value: Any, replacements: dict[str, str]) -> Any:
    if type(value) is str:
        return replacements.get(value, value)
    if type(value) is list:
        return [_replace_evidence_ids(item, replacements) for item in value]
    if type(value) is dict:
        return {
            key: _replace_evidence_ids(item, replacements)
            for key, item in value.items()
        }
    return value


def _candidate_bundle(
    *,
    build_identity: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    replacements = {
        "evidence_keyframe_001": "evidence_frame",
        "evidence_repository_001": "evidence_repository",
        "evidence_route_001": "evidence_route",
        "evidence_transcript_001": "evidence_transcript",
    }
    candidate = _replace_evidence_ids(
        _read_json(
            REPOSITORY
            / "contracts"
            / "ticket-candidate"
            / "fixtures"
            / "positive"
            / "version-1-draft.json"
        ),
        replacements,
    )
    candidate.update(
        {
            "build_id": build_identity["build_id"],
            "build_identity_digest": build_identity["build_identity_digest"],
            "candidate_created_at": "2026-07-21T10:03:09Z",
            "organization_id": manifest["organization_id"],
            "project_id": manifest["project_id"],
            "session_id": manifest["session_id"],
            "version_created_at": "2026-07-21T10:03:09Z",
        }
    )
    candidate["transition"]["actor"]["actor_id"] = "worker_synthetic"
    candidate["transition"]["occurred_at"] = "2026-07-21T10:03:09Z"

    specifications = (
        ("evidence_frame", "media.keyframe", "mobile_sdk", "image/png", 20_000),
        (
            "evidence_repository",
            "repository.commit_snapshot",
            "repository",
            "application/vnd.tacua.connector-snapshot+json",
            None,
        ),
        (
            "evidence_route",
            "sdk.route_transition",
            "mobile_sdk",
            "application/vnd.tacua.sdk-event+json",
            1_000,
        ),
        (
            "evidence_transcript",
            "media.transcript_excerpt",
            "mobile_sdk",
            "text/plain",
            19_000,
        ),
    )
    items = []
    for evidence_id, evidence_type, component, content_type, elapsed_ms in specifications:
        body = PREVIEW_BODY if evidence_id == "evidence_frame" else evidence_id.encode()
        item = evidence_domain.seal_item(
            {
                "availability": "available",
                "contract_version": evidence_domain.ITEM_VERSION,
                "description": f"Synthetic conformance evidence for {evidence_id}.",
                "evidence_id": evidence_id,
                "evidence_item_digest": "sha256:" + "0" * 64,
                "evidence_type": evidence_type,
                "organization_id": manifest["organization_id"],
                "project_id": manifest["project_id"],
                "reference": {
                    "content_digest": evidence_domain.sha256_digest(body),
                    "content_type": content_type,
                    "locator": {
                        "evidence_id": evidence_id,
                        "organization_id": manifest["organization_id"],
                        "project_id": manifest["project_id"],
                        "revision_id": f"revision_{evidence_id}",
                        "scheme": "tacua-evidence",
                    },
                    "size_bytes": len(body),
                },
                "session_id": manifest["session_id"],
                "source": {
                    "captured_at": "2026-07-21T10:00:20Z",
                    "component": component,
                    "snapshot_revision": build_identity["source"]["git_revision"]
                    if component == "repository"
                    else f"snapshot_{evidence_id}",
                    "source_id": "repo_mobile"
                    if component == "repository"
                    else "sdk_session",
                },
                "time_range": None
                if elapsed_ms is None
                else {
                    "clock": "session_monotonic",
                    "end_ms": elapsed_ms + 500,
                    "start_ms": elapsed_ms,
                },
                "unavailable": None,
            }
        )
        items.append(item)
    evidence_manifest = evidence_domain.seal_manifest(
        {
            "contract_version": evidence_domain.MANIFEST_VERSION,
            "items": items,
            "manifest_digest": "sha256:" + "0" * 64,
            "manifest_id": candidate["evidence_manifest"]["manifest_id"],
            "media_type": evidence_domain.MANIFEST_MEDIA_TYPE,
            "organization_id": manifest["organization_id"],
            "project_id": manifest["project_id"],
            "session_id": manifest["session_id"],
        }
    )
    evidence_domain.validate_manifest(evidence_manifest)
    candidate["evidence_manifest"] = {
        "evidence_ids": [item["evidence_id"] for item in items],
        "manifest_digest": evidence_manifest["manifest_digest"],
        "manifest_id": evidence_manifest["manifest_id"],
    }
    candidate = ticket_candidate.seal(candidate)
    ticket_candidate.validate_chain([candidate])
    preview = {
        "body_file": "preview-synthetic.png",
        "content_digest": contract.digest(PREVIEW_BODY),
        "content_type": "image/png",
        "evidence_id": "evidence_frame",
        "preview_revision_id": "preview_synthetic",
        "size_bytes": len(PREVIEW_BODY),
    }
    return candidate, evidence_manifest, preview


def _input(
    *,
    version: str,
    stage_name: str,
    job_version: int,
    build_identity: dict[str, Any],
    manifest: dict[str, Any],
    artifact: dict[str, Any] | None = None,
    current_attempt: int = 1,
) -> dict[str, Any]:
    pipeline = (
        contract.LEGACY_PIPELINE_V10
        if version == contract.INPUT_V10
        else contract.ARTIFACT_PIPELINE_V11
    )
    job = _job(
        stage_name=stage_name,
        pipeline_version=pipeline,
        job_version=job_version,
        current_attempt=current_attempt,
        build_identity=build_identity,
        manifest=manifest,
    )
    value: dict[str, Any] = {
        "binding": {
            "build_id": job["build_id"],
            "build_identity_digest": job["build_identity_digest"],
            "job_digest": job["job_digest"],
            "job_id": job["job_id"],
            "job_version": job["job_version"],
            "organization_id": job["organization_id"],
            "project_id": job["project_id"],
            "session_id": job["session_id"],
            "stage_name": stage_name,
            "worker_id": "worker_synthetic",
        },
        "capture": _capture(build_identity=build_identity, manifest=manifest),
        "contract_version": version,
        "input_digest": "sha256:" + "0" * 64,
        "job": job,
    }
    if version == contract.INPUT_V11:
        value["stage_inputs"] = {"artifacts": [] if artifact is None else [copy.deepcopy(artifact)]}
    value["input_digest"] = contract.digest_without(value, "input_digest")
    return value


def _transcript(manifest: dict[str, Any]) -> dict[str, Any]:
    sources = contract._expected_transcript_sources(manifest)
    source = sources[0]
    return {
        "contract_version": contract.TRANSCRIPT_V10,
        "language_tag": "en-GB",
        "source_segments": sources,
        "spans": [
            {
                "end_ms": 22_000,
                "segment_id": source["segment_id"],
                "start_ms": 19_000,
                "text": SYNTHETIC_TRANSCRIPT,
            }
        ],
        "speech_status": "detected",
    }


def _artifact(
    *,
    align_input_binding: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "artifact_digest": "sha256:" + "0" * 64,
        "artifact_id": contract._expected_artifact_id(align_input_binding["job_id"]),
        "artifact_kind": "transcript",
        "checkpoint_job_version": 3,
        "contract_version": contract.PROCESSING_ARTIFACT_V10,
        "created_at": "2026-07-21T10:03:01Z",
        "derived_data_expires_at": manifest["retention"]["derived_data_expires_at"],
        "job_id": align_input_binding["job_id"],
        "media_type": contract.PROCESSING_ARTIFACT_MEDIA_TYPE,
        "organization_id": align_input_binding["organization_id"],
        "payload": _transcript(manifest),
        "project_id": align_input_binding["project_id"],
        "session_id": align_input_binding["session_id"],
        "stage_name": "transcribe",
    }
    value["artifact_digest"] = contract.digest_without(value, "artifact_digest")
    return value


def _result(source_input: dict[str, Any], result: Any, version: str) -> dict[str, Any]:
    binding = source_input["binding"]
    return {
        "contract_version": version,
        "disposition": "checkpoint",
        "input_digest": source_input["input_digest"],
        "job_digest": binding["job_digest"],
        "job_id": binding["job_id"],
        "result": result,
        "session_id": binding["session_id"],
        "stage_name": binding["stage_name"],
    }


def _fixture_documents() -> dict[Path, bytes]:
    build_identity = _read_json(
        REPOSITORY
        / "contracts"
        / "sdk-backend-protocol"
        / "fixtures"
        / "positive"
        / "build-identity.json"
    )
    contract.protocol.validate(build_identity)
    manifest = _manifest(build_identity)

    input_v10 = _input(
        version=contract.INPUT_V10,
        stage_name="transcribe",
        job_version=2,
        build_identity=build_identity,
        manifest=manifest,
    )
    result_v10 = _result(input_v10, None, contract.RESULT_V10)

    input_terminal = _input(
        version=contract.INPUT_V10,
        stage_name="generate_tickets",
        job_version=10,
        build_identity=build_identity,
        manifest=manifest,
    )
    candidate, evidence_manifest, preview = _candidate_bundle(
        build_identity=build_identity,
        manifest=manifest,
    )
    result_terminal = _result(
        input_terminal,
        {
            "candidates": [
                {
                    "candidate": candidate,
                    "evidence_manifest": evidence_manifest,
                    "previews": [preview],
                }
            ],
            "disposition": "candidates_created",
            "summary": "One synthetic candidate with one bounded preview.",
        },
        contract.RESULT_V10,
    )
    result_terminal["disposition"] = "terminal"

    input_transcribe = _input(
        version=contract.INPUT_V11,
        stage_name="transcribe",
        job_version=2,
        build_identity=build_identity,
        manifest=manifest,
    )
    result_transcribe = _result(
        input_transcribe,
        {
            "artifacts": [
                {"artifact_kind": "transcript", "payload": _transcript(manifest)}
            ],
            "consumed_artifacts": [],
        },
        contract.RESULT_V11,
    )

    align_without_artifact = _input(
        version=contract.INPUT_V11,
        stage_name="align",
        job_version=4,
        build_identity=build_identity,
        manifest=manifest,
    )
    artifact = _artifact(
        align_input_binding=align_without_artifact["binding"], manifest=manifest
    )
    input_align = _input(
        version=contract.INPUT_V11,
        stage_name="align",
        job_version=4,
        build_identity=build_identity,
        manifest=manifest,
        artifact=artifact,
    )
    reference = {
        "artifact_digest": artifact["artifact_digest"],
        "artifact_id": artifact["artifact_id"],
    }
    result_align = _result(
        input_align,
        {"artifacts": [], "consumed_artifacts": [reference]},
        contract.RESULT_V11,
    )
    input_align_retry = _input(
        version=contract.INPUT_V11,
        stage_name="align",
        job_version=7,
        current_attempt=2,
        build_identity=build_identity,
        manifest=manifest,
        artifact=artifact,
    )
    result_align_retry = _result(
        input_align_retry,
        {"artifacts": [], "consumed_artifacts": [reference]},
        contract.RESULT_V11,
    )

    isolated_source = copy.deepcopy(input_align)
    isolated_source["capture"] = _capture(
        build_identity=build_identity, manifest=manifest, isolated=True
    )
    isolated_input = {
        "contract_version": contract.ISOLATED_INPUT_V10,
        "isolated_input_digest": "sha256:" + "0" * 64,
        "source_input": isolated_source,
        "source_input_digest": input_align["input_digest"],
    }
    isolated_input["isolated_input_digest"] = contract.digest_without(
        isolated_input, "isolated_input_digest"
    )
    isolated_output = {
        "contract_version": contract.ISOLATED_OUTPUT_V10,
        "previews": [],
        "result": copy.deepcopy(result_align),
        "result_digest": contract.digest(result_align),
    }

    documents: dict[Path, Any] = {
        Path("positive/adapter-v1.0-checkpoint/command.json"): _command(contract.COMMAND_V10),
        Path("positive/adapter-v1.0-checkpoint/input.json"): input_v10,
        Path("positive/adapter-v1.0-checkpoint/result.json"): result_v10,
        Path("positive/adapter-v1.0-terminal-preview/command.json"): _command(
            contract.COMMAND_V10
        ),
        Path("positive/adapter-v1.0-terminal-preview/input.json"): input_terminal,
        Path("positive/adapter-v1.0-terminal-preview/result.json"): result_terminal,
        Path("positive/adapter-v1.1-transcribe/command.json"): _command(contract.COMMAND_V11),
        Path("positive/adapter-v1.1-transcribe/input.json"): input_transcribe,
        Path("positive/adapter-v1.1-transcribe/result.json"): result_transcribe,
        Path("positive/adapter-v1.1-align/command.json"): _command(contract.COMMAND_V11),
        Path("positive/adapter-v1.1-align/input.json"): input_align,
        Path("positive/adapter-v1.1-align/result.json"): result_align,
        Path("positive/adapter-v1.1-align-retry/command.json"): _command(
            contract.COMMAND_V11
        ),
        Path("positive/adapter-v1.1-align-retry/input.json"): input_align_retry,
        Path("positive/adapter-v1.1-align-retry/result.json"): result_align_retry,
        Path("positive/isolated-v1.0-adapter-v1.1-align/isolated-input.json"): isolated_input,
        Path("positive/isolated-v1.0-adapter-v1.1-align/isolated-output.json"): isolated_output,
        Path("positive/isolated-v1.0-adapter-v1.1-align/input.json"): input_align,
    }

    command_extra = _command(contract.COMMAND_V10)
    command_extra["model"] = "forbidden"
    documents[Path("negative/command-extra-field/command.json")] = command_extra

    documents[
        Path("negative/command-v1.0-adapter-v1.1/command.json")
    ] = _command(contract.COMMAND_V10)
    documents[
        Path("negative/command-v1.0-adapter-v1.1/input.json")
    ] = input_transcribe
    documents[
        Path("negative/command-v1.0-adapter-v1.1/result.json")
    ] = result_transcribe

    extra_stage_inputs = copy.deepcopy(input_v10)
    extra_stage_inputs["stage_inputs"] = {"artifacts": []}
    extra_stage_inputs["input_digest"] = contract.digest_without(extra_stage_inputs, "input_digest")
    documents[Path("negative/v1.0-extra-stage-inputs/input.json")] = extra_stage_inputs

    preview_extra = copy.deepcopy(result_terminal)
    preview_extra["result"]["candidates"][0]["previews"][0]["unexpected"] = True
    documents[Path("negative/v1.0-preview-extra-field/input.json")] = input_terminal
    documents[Path("negative/v1.0-preview-extra-field/result.json")] = preview_extra

    unknown = copy.deepcopy(input_transcribe)
    unknown["contract_version"] = "tacua.local-processing-input@9.9.9"
    unknown["input_digest"] = contract.digest_without(unknown, "input_digest")
    documents[Path("negative/v1.1-unknown-contract/input.json")] = unknown

    tampered_input_digest = copy.deepcopy(input_transcribe)
    tampered_input_digest["input_digest"] = "sha256:" + "0" * 64
    documents[Path("negative/v1.1-tampered-input-digest/input.json")] = tampered_input_digest

    completion_mismatch = copy.deepcopy(input_transcribe)
    completion_mismatch["capture"]["session_completed_at"] = "2026-07-21T10:02:06Z"
    completion_mismatch["input_digest"] = contract.digest_without(
        completion_mismatch, "input_digest"
    )
    documents[
        Path("negative/v1.1-completion-time-mismatch/input.json")
    ] = completion_mismatch

    retention_mismatch = copy.deepcopy(input_transcribe)
    retention_mismatch["capture"]["session_created_at"] = "2026-07-21T09:57:01Z"
    retention_mismatch["input_digest"] = contract.digest_without(
        retention_mismatch, "input_digest"
    )
    documents[
        Path("negative/v1.1-retention-anchor-mismatch/input.json")
    ] = retention_mismatch

    missing_artifact = copy.deepcopy(input_align)
    missing_artifact["stage_inputs"]["artifacts"] = []
    missing_artifact["input_digest"] = contract.digest_without(missing_artifact, "input_digest")
    documents[Path("negative/v1.1-align-missing-artifact/input.json")] = missing_artifact

    artifact_time_mismatch = copy.deepcopy(input_align)
    changed_artifact = artifact_time_mismatch["stage_inputs"]["artifacts"][0]
    changed_artifact["created_at"] = "2026-07-21T10:03:00Z"
    changed_artifact["artifact_digest"] = contract.digest_without(
        changed_artifact, "artifact_digest"
    )
    artifact_time_mismatch["input_digest"] = contract.digest_without(
        artifact_time_mismatch, "input_digest"
    )
    documents[
        Path("negative/v1.1-artifact-created-at-mismatch/input.json")
    ] = artifact_time_mismatch

    tampered_artifact = copy.deepcopy(input_align)
    tampered_artifact["stage_inputs"]["artifacts"][0]["payload"]["spans"][0][
        "text"
    ] = "PRIVATE_NEGATIVE_TRANSCRIPT_SENTINEL"
    tampered_artifact["input_digest"] = contract.digest_without(tampered_artifact, "input_digest")
    documents[Path("negative/v1.1-transcript-artifact-tampered/input.json")] = tampered_artifact

    wrong_consumption = copy.deepcopy(result_align)
    wrong_consumption["result"]["consumed_artifacts"][0]["artifact_digest"] = "sha256:" + "f" * 64
    documents[Path("negative/v1.1-align-wrong-consumption/input.json")] = input_align
    documents[Path("negative/v1.1-align-wrong-consumption/result.json")] = wrong_consumption

    cross_binding = copy.deepcopy(result_align)
    cross_binding["job_id"] = "job_cross_binding"
    documents[Path("negative/v1.1-result-cross-binding/input.json")] = input_align
    documents[Path("negative/v1.1-result-cross-binding/result.json")] = cross_binding

    isolated_input_tampered = copy.deepcopy(isolated_input)
    isolated_input_tampered["isolated_input_digest"] = "sha256:" + "0" * 64
    documents[
        Path("negative/isolated-input-tampered-digest/isolated-input.json")
    ] = isolated_input_tampered

    isolated_input_swapped = copy.deepcopy(isolated_input)
    segment_path = isolated_input_swapped["source_input"]["capture"]["segments"][0][
        "read_only_path"
    ]
    diagnostic_path = isolated_input_swapped["source_input"]["capture"]["diagnostics"][
        0
    ]["read_only_path"]
    isolated_input_swapped["source_input"]["capture"]["segments"][0][
        "read_only_path"
    ] = diagnostic_path
    isolated_input_swapped["source_input"]["capture"]["diagnostics"][0][
        "read_only_path"
    ] = segment_path
    isolated_input_swapped["isolated_input_digest"] = contract.digest_without(
        isolated_input_swapped, "isolated_input_digest"
    )
    documents[
        Path("negative/isolated-input-swapped-evidence-paths/isolated-input.json")
    ] = isolated_input_swapped

    isolated_source_mismatch = copy.deepcopy(isolated_input)
    isolated_source_mismatch["source_input"]["binding"][
        "worker_id"
    ] = "worker_fabricated"
    isolated_source_mismatch["isolated_input_digest"] = contract.digest_without(
        isolated_source_mismatch, "isolated_input_digest"
    )
    documents[
        Path("negative/isolated-source-provenance-mismatch/input.json")
    ] = input_align
    documents[
        Path(
            "negative/isolated-source-provenance-mismatch/isolated-input.json"
        )
    ] = isolated_source_mismatch
    documents[
        Path(
            "negative/isolated-source-provenance-mismatch/isolated-output.json"
        )
    ] = isolated_output

    isolated_output_tampered = copy.deepcopy(isolated_output)
    isolated_output_tampered["result_digest"] = "sha256:" + "0" * 64
    documents[
        Path("negative/isolated-output-tampered-result-digest/isolated-output.json")
    ] = isolated_output_tampered

    preview_body = b"synthetic unreferenced preview"
    isolated_output_preview = copy.deepcopy(isolated_output)
    isolated_output_preview["previews"] = [
        {
            "content_base64": base64.b64encode(preview_body).decode("ascii"),
            "content_digest": contract.digest(preview_body),
            "name": "unreferenced.png",
            "size_bytes": len(preview_body),
        }
    ]
    documents[
        Path("negative/isolated-output-unreferenced-preview/isolated-output.json")
    ] = isolated_output_preview

    encoded = {
        path: contract.canonical_bytes(value) for path, value in documents.items()
    }
    encoded[
        Path("positive/adapter-v1.0-terminal-preview/preview-synthetic.png")
    ] = PREVIEW_BODY
    return encoded


def _check(documents: dict[Path, bytes]) -> bool:
    expected = set(documents)
    entries = list(FIXTURES.rglob("*"))
    if any(path.is_symlink() for path in entries):
        return False
    actual_files = {
        path.relative_to(FIXTURES) for path in entries if path.is_file()
    }
    expected_directories: set[Path] = set()
    for path in expected:
        parent = path.parent
        while parent != Path("."):
            expected_directories.add(parent)
            parent = parent.parent
    actual_directories = {
        path.relative_to(FIXTURES) for path in entries if path.is_dir()
    }
    if actual_files != expected or actual_directories != expected_directories:
        return False
    return all((FIXTURES / path).read_bytes() == body for path, body in documents.items())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    documents = _fixture_documents()
    if args.check:
        if not _check(documents):
            print("synthetic local-processing fixtures differ", file=sys.stderr)
            return 1
        print("synthetic local-processing fixtures are reproducible")
        return 0
    for relative, body in documents.items():
        destination = FIXTURES / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
    print("synthetic local-processing fixtures regenerated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
