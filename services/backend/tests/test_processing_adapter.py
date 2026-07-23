# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend.candidate_domain import TICKET_CONTRACT  # noqa: E402
from tacua_backend.contracts import canonical_json, runtime_seal  # noqa: E402
from tacua_backend.instance_lock import (  # noqa: E402
    InstanceLockError,
    acquire_state_instance_lock,
)
from tacua_backend.processing_adapter import (  # noqa: E402
    COMMAND_CONTRACT,
    COMMAND_CONTRACT_V11,
    INPUT_PLACEHOLDER,
    OUTPUT_DIRECTORY_PLACEHOLDER,
    LocalProcessingAdapter,
    LocalProcessorCommand,
    ProcessingAdapterError,
    _run_bounded_command,
    load_local_processor_command,
)
from tacua_backend.processing_jobs import ARTIFACT_PIPELINE_VERSION  # noqa: E402
from tacua_backend.processing_worker import _run as run_worker  # noqa: E402
from tacua_backend.service import ApiError, PilotBackend  # noqa: E402
from test_backend import BackendHarness  # noqa: E402


class AdapterArtifactPipelineBackend(PilotBackend):
    """Test-only producer; production continues to create pipeline 1.0 jobs."""

    def _queued_job_snapshot(self, *args, **kwargs):
        job = super()._queued_job_snapshot(*args, **kwargs)
        job["pipeline"]["pipeline_version"] = ARTIFACT_PIPELINE_VERSION
        return runtime_seal(job)


CHECKPOINT_PROCESSOR = r'''
import hashlib
import json
import os
from pathlib import Path
import sys

def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)

arguments = dict(zip(sys.argv[1::2], sys.argv[2::2], strict=True))
raw = Path(arguments["--input"]).read_bytes()
document = json.loads(raw.decode("utf-8"))
assert canonical(document).encode("utf-8") == raw
assert set(document) == {"binding", "capture", "contract_version", "input_digest", "job"}
assert document["contract_version"] == "tacua.local-processing-input@1.0.0"
subject = dict(document)
expected_digest = subject.pop("input_digest")
actual_digest = "sha256:" + hashlib.sha256(canonical(subject).encode("utf-8")).hexdigest()
assert actual_digest == expected_digest
assert "TACUA_TEST_SECRET" not in os.environ

def forbidden(value):
    if isinstance(value, dict):
        assert not ({"credential_id", "lease_token", "launch_code", "secret"} & set(value))
        for child in value.values():
            forbidden(child)
    elif isinstance(value, list):
        for child in value:
            forbidden(child)

forbidden(document)
accounting = document["capture"]["manifest"]["app_audio_accounting"]
assert accounting["version"] == 1
assert accounting["complete"] is True
assert accounting["unknown_ranges"] == []
assert [
    (item["segment_id"], item["sequence"])
    for item in accounting["segments"]
] == [
    (item["segment_id"], item["sequence"])
    for item in document["capture"]["segments"]
]
for item in document["capture"]["segments"] + document["capture"]["diagnostics"]:
    body = Path(item["read_only_path"]).read_bytes()
    assert len(body) == item["size_bytes"]
    assert "sha256:" + hashlib.sha256(body).hexdigest() == item["content_digest"]
    assert os.stat(item["read_only_path"]).st_mode & 0o222 == 0

binding = document["binding"]
result = {
    "contract_version": "tacua.local-processing-result@1.0.0",
    "input_digest": document["input_digest"],
    "job_id": binding["job_id"],
    "job_digest": binding["job_digest"],
    "session_id": binding["session_id"],
    "stage_name": binding["stage_name"],
    "disposition": "terminal" if binding["stage_name"] == "generate_tickets" else "checkpoint",
    "result": {
        "disposition": "no_issue_detected",
        "summary": "The deterministic local fixture found no issue.",
        "candidates": [],
    } if binding["stage_name"] == "generate_tickets" else None,
}
sys.stdout.buffer.write(canonical(result).encode("utf-8"))
'''


CANDIDATE_PROCESSOR = r'''
import base64
import json
from pathlib import Path
import sys

def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)

arguments = dict(zip(sys.argv[1::2], sys.argv[2::2], strict=True))
document = json.loads(Path(arguments["--input"]).read_text(encoding="utf-8"))
binding = document["binding"]
terminal = binding["stage_name"] == "generate_tickets"
terminal_result = None
if terminal:
    terminal_result = json.loads(Path(arguments["--template"]).read_text(encoding="utf-8"))
    for bundle_index, bundle in enumerate(terminal_result["candidates"]):
        for preview_index, preview in enumerate(bundle["previews"]):
            body = base64.b64decode(preview.pop("body_base64"), validate=True)
            name = f"preview-{bundle_index}-{preview_index}.png"
            Path(arguments["--output"], name).write_bytes(body)
            preview["body_file"] = name
result = {
    "contract_version": "tacua.local-processing-result@1.0.0",
    "input_digest": document["input_digest"],
    "job_id": binding["job_id"],
    "job_digest": binding["job_digest"],
    "session_id": binding["session_id"],
    "stage_name": binding["stage_name"],
    "disposition": "terminal" if terminal else "checkpoint",
    "result": terminal_result,
}
sys.stdout.buffer.write(canonical(result).encode("utf-8"))
'''


ARTIFACT_PIPELINE_PROCESSOR = r'''
import hashlib
import json
from pathlib import Path
import sys

def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)

arguments = dict(zip(sys.argv[1::2], sys.argv[2::2], strict=True))
raw = Path(arguments["--input"]).read_bytes()
document = json.loads(raw.decode("utf-8"))
assert canonical(document).encode("utf-8") == raw
assert document["contract_version"] == "tacua.local-processing-input@1.1.0"
subject = dict(document)
expected_digest = subject.pop("input_digest")
assert expected_digest == "sha256:" + hashlib.sha256(canonical(subject).encode("utf-8")).hexdigest()
binding = document["binding"]
stage_inputs = document["stage_inputs"]["artifacts"]
if binding["stage_name"] == "transcribe":
    assert stage_inputs == []
    sources = [
        {
            "segment_id": segment["segment_id"],
            "sequence": segment["sequence"],
            "content_digest": segment["content"]["content_digest"],
            "start_ms": segment["time_range"]["start_ms"],
            "end_ms": segment["time_range"]["end_ms"],
        }
        for segment in document["capture"]["manifest"]["segments"]
        if segment["availability"] == "available"
    ]
    first = sources[0]
    artifacts = [{
        "artifact_kind": "transcript",
        "payload": {
            "contract_version": "tacua.transcript@1.0.0",
            "language_tag": "en-GB",
            "speech_status": "detected",
            "source_segments": sources,
            "spans": [{
                "segment_id": first["segment_id"],
                "start_ms": first["start_ms"],
                "end_ms": first["end_ms"],
                "text": "PRIVATE_ADAPTER_TRANSCRIPT_SENTINEL",
            }],
        },
    }]
    consumed = []
elif binding["stage_name"] == "align":
    assert len(stage_inputs) == 1
    artifact = stage_inputs[0]
    assert artifact["contract_version"] == "tacua.processing-stage-artifact@1.0.0"
    assert artifact["artifact_kind"] == "transcript"
    assert artifact["payload"]["spans"][0]["text"] == "PRIVATE_ADAPTER_TRANSCRIPT_SENTINEL"
    artifacts = []
    consumed = [{
        "artifact_id": artifact["artifact_id"],
        "artifact_digest": artifact["artifact_digest"],
    }]
else:
    raise AssertionError("artifact pipeline advanced beyond its implemented boundary")
result = {
    "contract_version": "tacua.local-processing-result@1.1.0",
    "input_digest": document["input_digest"],
    "job_id": binding["job_id"],
    "job_digest": binding["job_digest"],
    "session_id": binding["session_id"],
    "stage_name": binding["stage_name"],
    "disposition": "checkpoint",
    "result": {
        "artifacts": artifacts,
        "consumed_artifacts": consumed,
    },
}
sys.stdout.buffer.write(canonical(result).encode("utf-8"))
'''


class LocalProcessingAdapterTests(BackendHarness):
    def processor_script(self, source: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "processor.py"
        path.write_text(source, encoding="utf-8")
        path.chmod(0o600)
        return path

    def command(
        self,
        script: Path,
        *extra_arguments: str,
        timeout_seconds: int = 30,
        stdout_bytes: int = 4_194_304,
        stderr_bytes: int = 65_536,
        contract_version: str = COMMAND_CONTRACT,
    ) -> LocalProcessorCommand:
        return LocalProcessorCommand(
            argv=(
                sys.executable,
                str(script),
                "--input",
                INPUT_PLACEHOLDER,
                "--output",
                OUTPUT_DIRECTORY_PLACEHOLDER,
                *extra_arguments,
            ),
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=stdout_bytes,
            max_stderr_bytes=stderr_bytes,
            contract_version=contract_version,
        )

    def install(self, command: LocalProcessorCommand) -> LocalProcessingAdapter:
        adapter = LocalProcessingAdapter(command)
        adapter.bind_backend(self.backend)
        self.backend._processing_engine = adapter
        return adapter

    def test_exact_command_document_is_required_and_shell_syntax_is_literal(self) -> None:
        script = self.processor_script(CHECKPOINT_PROCESSOR)
        directory = Path(script).parent
        document = {
            "contract_version": COMMAND_CONTRACT,
            "argv": [
                sys.executable,
                str(script),
                "--input",
                INPUT_PLACEHOLDER,
                "--output",
                OUTPUT_DIRECTORY_PLACEHOLDER,
                "; touch /tmp/not-a-shell",
            ],
            "timeout_seconds": 30,
            "max_stdout_bytes": 65_536,
            "max_stderr_bytes": 65_536,
        }
        command_path = directory / "command.json"
        command_path.write_bytes(canonical_json(document).encode("utf-8"))
        command_path.chmod(0o600)
        loaded = load_local_processor_command(command_path)
        self.assertEqual(tuple(document["argv"]), loaded.argv)
        self.assertEqual(COMMAND_CONTRACT, loaded.contract_version)
        self.assertIn("; touch /tmp/not-a-shell", loaded.argv)

        document["contract_version"] = COMMAND_CONTRACT_V11
        command_path.write_bytes(canonical_json(document).encode("utf-8"))
        command_path.chmod(0o600)
        loaded_v11 = load_local_processor_command(command_path)
        self.assertEqual(COMMAND_CONTRACT_V11, loaded_v11.contract_version)
        document["contract_version"] = COMMAND_CONTRACT

        command_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        command_path.chmod(0o600)
        with self.assertRaises(ProcessingAdapterError) as captured:
            load_local_processor_command(command_path)
        self.assertEqual("PROCESSOR_JSON_NOT_CANONICAL", captured.exception.code)

        document["argv"].append("{unknown}")
        command_path.write_bytes(canonical_json(document).encode("utf-8"))
        command_path.chmod(0o600)
        with self.assertRaises(ProcessingAdapterError) as captured:
            load_local_processor_command(command_path)
        self.assertEqual("PROCESSOR_ARGV_INVALID", captured.exception.code)

    def test_opt_in_adapter_v11_passes_transcript_to_align_then_pauses(self) -> None:
        self.backend = AdapterArtifactPipelineBackend(
            self.config, self.admin_secret, clock=self.clock
        )
        lifecycle = self.full_completed_session()
        job = lifecycle["completion_receipt"]["processing_job"]
        script = self.processor_script(ARTIFACT_PIPELINE_PROCESSOR)
        self.install(
            self.command(script, contract_version=COMMAND_CONTRACT_V11)
        )

        transcribed = self.backend.run_processing_once("worker_adapter_v11")
        assert transcribed is not None
        self.assertEqual(
            "succeeded", transcribed["pipeline"]["stages"][0]["state"]
        )
        aligned = self.backend.run_processing_once("worker_adapter_v11")
        assert aligned is not None
        self.assertEqual("succeeded", aligned["pipeline"]["stages"][1]["state"])
        self.assertEqual("pending", aligned["pipeline"]["stages"][2]["state"])
        self.assertIsNone(self.backend.run_processing_once("worker_adapter_v11"))
        self.assertNotIn(
            "PRIVATE_ADAPTER_TRANSCRIPT_SENTINEL", canonical_json(aligned)
        )
        self.assertNotIn(
            "PRIVATE_ADAPTER_TRANSCRIPT_SENTINEL",
            canonical_json(self.backend.list_jobs()),
        )
        with self.backend._connect() as connection:
            artifact_body = connection.execute(
                "SELECT canonical_json FROM tacua_processing_artifacts"
            ).fetchone()[0]
            receipt_body = connection.execute(
                """SELECT canonical_json
                     FROM tacua_processing_artifact_consumptions"""
            ).fetchone()[0]
        self.assertIn("PRIVATE_ADAPTER_TRANSCRIPT_SENTINEL", artifact_body)
        self.assertNotIn("PRIVATE_ADAPTER_TRANSCRIPT_SENTINEL", receipt_body)
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertEqual(aligned, restarted.get_job(job["job_id"]))
        self.assertEqual([], list(self.backend.temp_dir.iterdir()))

    def test_adapter_v11_wrong_consumed_reference_fails_without_receipt(self) -> None:
        self.backend = AdapterArtifactPipelineBackend(
            self.config, self.admin_secret, clock=self.clock
        )
        lifecycle = self.full_completed_session()
        job_id = lifecycle["completion_receipt"]["processing_job"]["job_id"]
        source = ARTIFACT_PIPELINE_PROCESSOR.replace(
            '"artifact_id": artifact["artifact_id"],',
            '"artifact_id": "artifact_wrong_reference",',
        )
        self.install(
            self.command(
                self.processor_script(source),
                contract_version=COMMAND_CONTRACT_V11,
            )
        )

        transcribed = self.backend.run_processing_once("worker_adapter_v11_bad_ref")
        assert transcribed is not None
        with self.assertRaises(ApiError) as captured:
            self.backend.run_processing_once("worker_adapter_v11_bad_ref")
        self.assertEqual("PROCESSING_ENGINE_FAILED", captured.exception.code)
        self.assertNotIn(
            "PRIVATE_ADAPTER_TRANSCRIPT_SENTINEL", str(captured.exception)
        )
        job = self.backend.get_job(job_id)
        self.assertEqual("queued", job["status"])
        self.assertEqual("pending", job["pipeline"]["stages"][1]["state"])
        self.assertEqual(1, job["pipeline"]["stages"][1]["attempt_count"])
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM tacua_processing_artifact_consumptions"
                ).fetchone()[0],
            )
        self.assertEqual([], list(self.backend.temp_dir.iterdir()))

    def test_adapter_v10_refuses_artifact_pipeline_before_child_execution(self) -> None:
        self.backend = AdapterArtifactPipelineBackend(
            self.config, self.admin_secret, clock=self.clock
        )
        lifecycle = self.full_completed_session()
        marker_directory = tempfile.TemporaryDirectory()
        self.addCleanup(marker_directory.cleanup)
        marker = Path(marker_directory.name) / "child-ran"
        script = self.processor_script(
            f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"
        )
        self.install(self.command(script))
        with self.assertRaises(ApiError) as captured:
            self.backend.run_processing_once("worker_adapter_v10_guard")
        self.assertEqual("PROCESSING_ENGINE_FAILED", captured.exception.code)
        self.assertFalse(marker.exists())
        job = self.backend.get_job(
            lifecycle["completion_receipt"]["processing_job"]["job_id"]
        )
        self.assertEqual("queued", job["status"])
        self.assertEqual(1, job["pipeline"]["stages"][0]["attempt_count"])

    def test_verified_descriptor_input_progresses_all_stages_to_zero_candidates(self) -> None:
        lifecycle = self.full_completed_session()
        script = self.processor_script(CHECKPOINT_PROCESSOR)
        self.install(self.command(script))
        results = []
        with patch.dict(os.environ, {"TACUA_TEST_SECRET": "must-not-reach-child"}):
            for _stage in range(5):
                result = self.backend.run_processing_once("worker_local")
                self.assertIsNotNone(result)
                results.append(result)
        self.assertEqual(["queued"] * 4 + ["succeeded"], [r["status"] for r in results])
        self.assertEqual(
            "no_issue_detected", results[-1]["outputs"]["disposition"]
        )
        self.assertEqual([], results[-1]["outputs"]["candidate_refs"])
        session_id = lifecycle["launch_receipt"]["session_id"]
        with self.backend._connect() as connection:
            modes = [
                (self.backend.state_dir / row["relative_path"]).stat().st_mode & 0o777
                for table in ("segments", "diagnostics", "completions")
                for row in connection.execute(
                    f"SELECT relative_path FROM {table} WHERE session_id = ?",
                    (session_id,),
                )
            ]
        self.assertEqual([0o400, 0o400, 0o400], modes)
        self.assertEqual([], list(self.backend.temp_dir.iterdir()))

    def test_two_candidates_and_preview_files_publish_atomically(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        job = lifecycle["completion_receipt"]["processing_job"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        for field in ("candidate_created_at", "version_created_at"):
            candidate[field] = job["requested_at"]
        candidate["transition"]["occurred_at"] = job["requested_at"]
        candidate["transition"]["actor"]["actor_id"] = "worker_local"
        candidate = TICKET_CONTRACT.seal(candidate)
        second = copy.deepcopy(candidate)
        second["candidate_id"] = "candidate_profile_copy_second"
        second = TICKET_CONTRACT.seal(second)
        bundles = []
        for document in (candidate, second):
            serialized_previews = []
            for preview in previews:
                serialized = dict(preview)
                serialized["body_base64"] = base64.b64encode(
                    serialized.pop("body")
                ).decode("ascii")
                serialized_previews.append(serialized)
            bundles.append(
                {
                    "candidate": document,
                    "evidence_manifest": manifest,
                    "previews": serialized_previews,
                }
            )
        terminal = {
            "disposition": "candidates_created",
            "summary": "The deterministic local fixture found two issues.",
            "candidates": bundles,
        }
        template_directory = tempfile.TemporaryDirectory()
        self.addCleanup(template_directory.cleanup)
        template_path = Path(template_directory.name) / "terminal.json"
        template_path.write_bytes(canonical_json(terminal).encode("utf-8"))
        template_path.chmod(0o400)
        script = self.processor_script(CANDIDATE_PROCESSOR)
        self.install(self.command(script, "--template", str(template_path)))

        final = None
        for _stage in range(5):
            final = self.backend.run_processing_once("worker_local")
        assert final is not None
        self.assertEqual("succeeded", final["status"])
        self.assertEqual(2, len(final["outputs"]["candidate_refs"]))
        listed = self.backend.list_candidates(session_id)
        self.assertEqual(2, len(listed["candidates"]))
        self.assertEqual([], list(self.backend.temp_dir.iterdir()))

    def test_noncanonical_child_output_is_content_free_retryable_failure(self) -> None:
        lifecycle = self.full_completed_session()
        script = self.processor_script("import sys; sys.stdout.write('{ }\\n')")
        self.install(self.command(script))
        with self.assertRaises(ApiError) as captured:
            self.backend.run_processing_once("worker_local")
        self.assertEqual("PROCESSING_ENGINE_FAILED", captured.exception.code)
        job = self.backend.get_job(
            lifecycle["completion_receipt"]["processing_job"]["job_id"]
        )
        self.assertEqual("queued", job["status"])
        self.assertEqual(1, job["pipeline"]["stages"][0]["attempt_count"])
        self.assertEqual([], list(self.backend.temp_dir.iterdir()))

    def test_timeout_stdout_and_stderr_are_independently_bounded(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        work = Path(directory.name)
        cases = (
            (
                "import sys; sys.stdout.buffer.write(b'x' * 1025)",
                "PROCESSOR_OUTPUT_LIMIT",
                10,
            ),
            (
                "import sys; sys.stderr.buffer.write(b'x' * 1025)",
                "PROCESSOR_OUTPUT_LIMIT",
                10,
            ),
            ("import time; time.sleep(2)", "PROCESSOR_TIMEOUT", 1),
        )
        for source, expected_code, timeout in cases:
            with self.subTest(expected_code=expected_code, source=source):
                script = self.processor_script(source)
                command = self.command(
                    script,
                    timeout_seconds=timeout,
                    stdout_bytes=1_024,
                    stderr_bytes=1_024,
                )
                argv = command.expand(
                    input_path="/dev/null", output_directory=work
                )
                with self.assertRaises(ProcessingAdapterError) as captured:
                    _run_bounded_command(
                        command,
                        argv,
                        cwd=work,
                        pass_fds=(),
                    )
                self.assertEqual(expected_code, captured.exception.code)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process groups")
    def test_successful_processor_cannot_leave_a_descriptor_holding_descendant(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        work = Path(directory.name)
        survived = work / "descendant-survived"
        script = self.processor_script(
            r'''
import os
from pathlib import Path
import sys
import time

arguments = dict(zip(sys.argv[1::2], sys.argv[2::2], strict=True))
child = os.fork()
if child == 0:
    # Let the leader's pipes reach EOF while retaining every explicitly passed
    # evidence/input descriptor, just as an accidental daemonized child would.
    os.close(1)
    os.close(2)
    time.sleep(0.5)
    Path(arguments["--survived"]).write_text("unsafe", encoding="utf-8")
    time.sleep(5)
    os._exit(0)
sys.stdout.buffer.write(b"ok")
'''
        )
        command = self.command(script, "--survived", str(survived))
        argv = command.expand(input_path="/dev/null", output_directory=work)
        self.assertEqual(
            b"ok",
            _run_bounded_command(command, argv, cwd=work, pass_fds=()),
        )
        time.sleep(0.8)
        self.assertFalse(survived.exists())

    def test_child_symlink_output_is_rejected_and_removed(self) -> None:
        self.full_completed_session()
        source = r'''
import json
import os
from pathlib import Path
import sys
arguments = dict(zip(sys.argv[1::2], sys.argv[2::2], strict=True))
document = json.loads(Path(arguments["--input"]).read_text(encoding="utf-8"))
os.symlink("/etc/passwd", Path(arguments["--output"], "unsafe"))
binding = document["binding"]
result = {
    "contract_version": "tacua.local-processing-result@1.0.0",
    "input_digest": document["input_digest"],
    "job_id": binding["job_id"],
    "job_digest": binding["job_digest"],
    "session_id": binding["session_id"],
    "stage_name": binding["stage_name"],
    "disposition": "checkpoint",
    "result": None,
}
sys.stdout.write(json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True))
'''
        self.install(self.command(self.processor_script(source)))
        with self.assertRaises(ApiError) as captured:
            self.backend.run_processing_once("worker_local")
        self.assertEqual("PROCESSING_ENGINE_FAILED", captured.exception.code)
        self.assertEqual([], list(self.backend.temp_dir.iterdir()))

    def test_tampered_evidence_is_rejected_before_child_execution(self) -> None:
        lifecycle = self.full_completed_session()
        marker_directory = tempfile.TemporaryDirectory()
        self.addCleanup(marker_directory.cleanup)
        marker = Path(marker_directory.name) / "executed"
        source = (
            "from pathlib import Path; import sys; "
            f"Path({str(marker)!r}).write_text('yes'); sys.exit(3)"
        )
        script = self.processor_script(source)
        self.install(self.command(script))
        with self.backend._connect() as connection:
            row = connection.execute(
                "SELECT relative_path FROM segments WHERE session_id = ?",
                (lifecycle["launch_receipt"]["session_id"],),
            ).fetchone()
        (self.backend.state_dir / row["relative_path"]).write_bytes(b"tampered")
        with self.assertRaises(ApiError) as captured:
            self.backend.run_processing_once("worker_local")
        self.assertEqual("PROCESSING_ENGINE_FAILED", captured.exception.code)
        self.assertFalse(marker.exists())

    def test_crashed_processing_workspace_is_removed_on_normal_restart(self) -> None:
        workspace = self.backend.temp_dir / "processing-crashed-fixture"
        output = workspace / "output"
        output.mkdir(parents=True)
        (output / "partial.bin").write_bytes(b"partial")
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assertFalse(workspace.exists())
        self.assertIsNone(restarted._processing_engine)

    def test_worker_refuses_a_state_directory_owned_by_another_process(self) -> None:
        args = SimpleNamespace(
            config_file=Path("/unused/config.json"),
            admin_secret_file=Path("/unused/secret"),
            command_file=Path("/unused/command.json"),
            worker_id="worker_local",
            run_once=True,
            drain=False,
            max_stages=1,
        )
        with acquire_state_instance_lock(
            self.config.state_directory, create_directory=False
        ):
            with patch(
                "tacua_backend.processing_worker.load_public_config",
                return_value=self.config,
            ):
                with self.assertRaises(InstanceLockError):
                    run_worker(args)

    def test_worker_run_once_then_bounded_drain_reaches_queue_empty(self) -> None:
        self.full_completed_session()
        command = self.command(self.processor_script(CHECKPOINT_PROCESSOR))
        args = SimpleNamespace(
            config_file=Path("/unused/config.json"),
            admin_secret_file=Path("/unused/secret"),
            command_file=Path("/unused/command.json"),
            worker_id="worker_local",
            run_once=True,
            drain=False,
            max_stages=1,
        )
        patches = (
            patch(
                "tacua_backend.processing_worker.load_public_config",
                return_value=self.config,
            ),
            patch(
                "tacua_backend.processing_worker.load_config",
                return_value=(self.config, self.admin_secret),
            ),
            patch(
                "tacua_backend.processing_worker.load_local_processor_command",
                return_value=command,
            ),
        )
        with patches[0], patches[1], patches[2]:
            once = run_worker(args)
            args.run_once = False
            args.drain = True
            args.max_stages = 10
            drained = run_worker(args)
        self.assertEqual(1, once["processed_stages"])
        self.assertFalse(once["queue_empty"])
        self.assertTrue(once["stage_limit_reached"])
        self.assertEqual(4, drained["processed_stages"])
        self.assertTrue(drained["queue_empty"])
        self.assertFalse(drained["stage_limit_reached"])


if __name__ == "__main__":
    unittest.main()
