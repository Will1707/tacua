# SPDX-License-Identifier: Apache-2.0
"""Cross-check the inert fixture contract against the current runtime wires."""

from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[3]
SOURCE = REPOSITORY / "services" / "backend" / "src"
CONTRACT_SOURCE = REPOSITORY / "contracts" / "local-processing" / "src"
for source in (SOURCE, CONTRACT_SOURCE):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from local_processing_contract import (  # noqa: E402
    COMMAND_V10,
    COMMAND_V11,
    INPUT_V10,
    INPUT_V11,
    ISOLATED_INPUT_V10,
    ISOLATED_OUTPUT_V10,
    POSITIVE_CASES,
    canonical_bytes,
    load_json,
    validate_local_input,
)
from tacua_backend.contracts import runtime_seal  # noqa: E402
from tacua_backend.processing_adapter import (  # noqa: E402
    COMMAND_CONTRACT,
    COMMAND_CONTRACT_V11,
    _ProcessingInput,
    _parse_result,
    _processing_input,
    load_local_processor_command,
)
from tacua_backend.processing_jobs import (  # noqa: E402
    ARTIFACT_PIPELINE_VERSION,
    ProcessingCheckpoint,
    ProcessingResult,
)
from tacua_backend.service import PilotBackend  # noqa: E402
from test_backend import BackendHarness  # noqa: E402


FIXTURES = REPOSITORY / "contracts" / "local-processing" / "fixtures" / "positive"
RUNNER_PATH = REPOSITORY / "services" / "backend" / "scripts" / "run_isolated_processor.py"


class ArtifactPipelineBackend(PilotBackend):
    """Test-only producer; normal completion remains pipeline 1.0."""

    def _queued_job_snapshot(self, *args, **kwargs):
        job = super()._queued_job_snapshot(*args, **kwargs)
        job["pipeline"]["pipeline_version"] = ARTIFACT_PIPELINE_VERSION
        return runtime_seal(job)


def _load_runner():
    specification = importlib.util.spec_from_file_location(
        "tacua_contract_compatibility_isolated_runner", RUNNER_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("isolated runner module cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RUNNER = _load_runner()


class LocalProcessingRuntimeCompatibilityTests(BackendHarness):
    def _claim(self, worker_id: str):
        with self.backend._lock, self.backend._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = self.backend._processing_job_store(connection).claim(worker_id)
        self.assertFalse(result.retry_required)
        self.assertIsNotNone(result.claim)
        return result.claim

    def _assert_runtime_input_conforms(self, claim, command_version: str) -> dict:
        with _processing_input(
            self.backend,
            claim,
            command_contract_version=command_version,
        ) as snapshot:
            validate_local_input(snapshot.document)
            self.assertEqual(canonical_bytes(snapshot.document), snapshot.encoded)
            return copy.deepcopy(snapshot.document)

    def test_actual_legacy_adapter_input_conforms_without_shape_change(self) -> None:
        self.full_completed_session()
        claim = self._claim("worker_contract_v10")
        document = self._assert_runtime_input_conforms(claim, COMMAND_CONTRACT)
        self.assertEqual(INPUT_V10, document["contract_version"])
        self.assertEqual(
            {"binding", "capture", "contract_version", "input_digest", "job"},
            set(document),
        )

    def test_actual_artifact_inputs_conform_through_align(self) -> None:
        self.backend = ArtifactPipelineBackend(
            self.config, self.admin_secret, clock=self.clock
        )
        self.full_completed_session()
        transcribe_claim = self._claim("worker_contract_v11")
        transcribe_input = self._assert_runtime_input_conforms(
            transcribe_claim, COMMAND_CONTRACT_V11
        )
        self.assertEqual(INPUT_V11, transcribe_input["contract_version"])
        self.assertEqual([], transcribe_input["stage_inputs"]["artifacts"])

        sources = [
            {
                "content_digest": segment["content"]["content_digest"],
                "end_ms": segment["time_range"]["end_ms"],
                "segment_id": segment["segment_id"],
                "sequence": segment["sequence"],
                "start_ms": segment["time_range"]["start_ms"],
            }
            for segment in transcribe_input["capture"]["manifest"]["segments"]
            if segment["availability"] == "available"
        ]
        first = sources[0]
        checkpoint = ProcessingCheckpoint(
            artifacts=(
                {
                    "artifact_kind": "transcript",
                    "payload": {
                        "contract_version": "tacua.transcript@1.0.0",
                        "language_tag": "en-GB",
                        "source_segments": sources,
                        "spans": [
                            {
                                "end_ms": min(first["end_ms"], first["start_ms"] + 1),
                                "segment_id": first["segment_id"],
                                "start_ms": first["start_ms"],
                                "text": "Synthetic runtime conformance transcript.",
                            }
                        ],
                        "speech_status": "detected",
                    },
                },
            )
        )
        self.backend.publish_processing_checkpoint(
            transcribe_claim.job["job_id"],
            transcribe_claim.stage_name,
            transcribe_claim.lease_token,
            checkpoint,
        )
        align_claim = self._claim("worker_contract_v11")
        align_input = self._assert_runtime_input_conforms(
            align_claim, COMMAND_CONTRACT_V11
        )
        self.assertEqual("align", align_input["binding"]["stage_name"])
        self.assertEqual(1, len(align_input["stage_inputs"]["artifacts"]))
        first_artifact = copy.deepcopy(align_input["stage_inputs"]["artifacts"][0])

        self.backend.fail_processing_job(
            align_claim.job["job_id"],
            "align",
            align_claim.lease_token,
            code="SYNTHETIC_ALIGNMENT_RETRY",
            detail="Synthetic conformance retry.",
            retryable=True,
        )
        retry_claim = self._claim("worker_contract_v11")
        retry_input = self._assert_runtime_input_conforms(
            retry_claim, COMMAND_CONTRACT_V11
        )
        self.assertEqual(2, retry_input["job"]["pipeline"]["stages"][1]["attempt_count"])
        self.assertEqual(first_artifact, retry_input["stage_inputs"]["artifacts"][0])
        self.assertLess(
            first_artifact["checkpoint_job_version"],
            retry_input["binding"]["job_version"],
        )

    def test_fixture_commands_and_results_match_runtime_parsers(self) -> None:
        cases = (
            ("adapter-v1.0-checkpoint", COMMAND_V10, type(None)),
            ("adapter-v1.0-terminal-preview", COMMAND_V10, ProcessingResult),
            ("adapter-v1.1-transcribe", COMMAND_V11, ProcessingCheckpoint),
            ("adapter-v1.1-align", COMMAND_V11, ProcessingCheckpoint),
            ("adapter-v1.1-align-retry", COMMAND_V11, ProcessingCheckpoint),
        )
        self.assertEqual(
            {name for name, kind in POSITIVE_CASES.items() if kind == ("local",)},
            {name for name, _command, _result in cases},
        )
        for name, expected_command, expected_result_type in cases:
            directory = FIXTURES / name
            with self.subTest(name=name):
                command = load_local_processor_command(directory / "command.json")
                self.assertEqual(expected_command, command.contract_version)
                input_document = load_json(directory / "input.json")
                result_document = load_json(directory / "result.json")
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    output = root / "output"
                    output.mkdir()
                    terminal = result_document.get("result")
                    if type(terminal) is dict:
                        for bundle in terminal.get("candidates", []):
                            for preview in bundle.get("previews", []):
                                source = directory / preview["body_file"]
                                (output / preview["body_file"]).write_bytes(
                                    source.read_bytes()
                                )
                    descriptor = os.open(output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        metadata = os.fstat(descriptor)
                        snapshot = _ProcessingInput(
                            document=input_document,
                            encoded=canonical_bytes(input_document),
                            input_descriptor=-1,
                            evidence_descriptors=(),
                            work_directory=root,
                            output_directory=output,
                            output_directory_descriptor=descriptor,
                            output_directory_identity=(metadata.st_dev, metadata.st_ino),
                        )
                        parsed = _parse_result(canonical_bytes(result_document), snapshot)
                    finally:
                        os.close(descriptor)
                self.assertIsInstance(parsed, expected_result_type)

    def test_isolated_wrapper_fixture_uses_frozen_wrapper_and_runtime_output_transport(
        self,
    ) -> None:
        directory = FIXTURES / "isolated-v1.0-adapter-v1.1-align"
        isolated_input = load_json(directory / "isolated-input.json")
        isolated_output_path = directory / "isolated-output.json"
        isolated_output = load_json(isolated_output_path)
        self.assertEqual(ISOLATED_INPUT_V10, RUNNER.INPUT_CONTRACT)
        self.assertEqual(ISOLATED_OUTPUT_V10, RUNNER.OUTPUT_CONTRACT)
        self.assertEqual(ISOLATED_INPUT_V10, isolated_input["contract_version"])
        self.assertEqual(INPUT_V11, isolated_input["source_input"]["contract_version"])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            result_bytes = RUNNER._validate_output_envelope(
                isolated_output_path.read_bytes(), output
            )
        self.assertEqual(canonical_bytes(isolated_output["result"]), result_bytes)


if __name__ == "__main__":
    unittest.main()
