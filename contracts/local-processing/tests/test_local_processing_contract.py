# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_processing_contract import (  # noqa: E402
    ContractError,
    NEGATIVE_CASES,
    POSITIVE_CASES,
    MAX_TRANSCRIPT_BYTES,
    canonical_bytes,
    digest,
    digest_without,
    load_json,
    parse_canonical_bytes,
    validate_artifact,
    validate_bundle,
    validate_command,
    validate_fixture_corpus,
    validate_exchange,
    validate_isolated_exchange,
    validate_local_result,
)
import local_processing_contract as contract  # noqa: E402


FIXTURES = ROOT / "fixtures"
VALIDATOR = ROOT / "scripts" / "validate.py"
REGENERATOR = ROOT / "scripts" / "regenerate_fixtures.py"
PRIVATE_SENTINEL = "PRIVATE_NEGATIVE_TRANSCRIPT_SENTINEL"


class LocalProcessingContractTests(unittest.TestCase):
    def test_exact_positive_and_negative_fixture_corpus(self) -> None:
        validate_fixture_corpus(FIXTURES)
        self.assertEqual(
            set(POSITIVE_CASES),
            {item.name for item in (FIXTURES / "positive").iterdir() if item.is_dir()},
        )
        self.assertEqual(
            set(NEGATIVE_CASES),
            {item.name for item in (FIXTURES / "negative").iterdir() if item.is_dir()},
        )

    def test_every_checked_in_json_fixture_is_exact_canonical_utf8(self) -> None:
        for path in sorted(FIXTURES.rglob("*.json")):
            with self.subTest(path=path.relative_to(FIXTURES)):
                document = load_json(path)
                self.assertEqual(canonical_bytes(document), path.read_bytes())

    def test_each_positive_bundle_validates_independently(self) -> None:
        for name in sorted(POSITIVE_CASES):
            with self.subTest(name=name):
                validate_bundle(FIXTURES / "positive" / name)

    def test_each_negative_fixture_fails_with_content_free_error(self) -> None:
        sentinel_path = (
            FIXTURES
            / "negative"
            / "v1.1-transcript-artifact-tampered"
            / "input.json"
        )
        self.assertIn(PRIVATE_SENTINEL, sentinel_path.read_text(encoding="utf-8"))
        for name, specification in sorted(NEGATIVE_CASES.items()):
            operation, expected_code, *files = specification
            documents = [load_json(FIXTURES / "negative" / name / item) for item in files]
            with self.subTest(name=name):
                with self.assertRaises(ContractError) as captured:
                    if operation == "artifact":
                        validate_artifact(documents[0])
                    elif operation == "exchange":
                        validate_exchange(documents[0], documents[1])
                    elif operation == "command-exchange":
                        from local_processing_contract import validate_command_exchange

                        validate_command_exchange(
                            documents[0], documents[1], documents[2]
                        )
                    else:
                        validate_isolated_exchange(
                            documents[0], documents[1], documents[2]
                        )
                rendered = str(captured.exception)
                self.assertEqual(expected_code, captured.exception.code)
                self.assertNotIn(PRIVATE_SENTINEL, rendered)
                self.assertNotIn("Synthetic transcript fixture", rendered)
                self.assertEqual(
                    f"{captured.exception.code}: local processing contract invalid",
                    rendered,
                )

    def test_strict_json_profile_rejects_noncanonical_and_unsafe_values(self) -> None:
        canonical = load_json(
            FIXTURES / "positive" / "adapter-v1.0-checkpoint" / "command.json"
        )
        pretty = json.dumps(canonical, indent=2).encode("utf-8")
        duplicate = b'{"contract_version":"a","contract_version":"b"}'
        floating = b'{"value":1.0}'
        unsafe = b'{"value":9007199254740992}'
        non_nfc = '{"value":"e\u0301"}'.encode("utf-8")
        for payload in (pretty, duplicate, floating, unsafe, non_nfc):
            with self.subTest(payload=payload[:32]):
                with self.assertRaises(ContractError):
                    parse_canonical_bytes(payload)

        three_values = canonical_bytes({"first": 1, "second": 2})
        with mock.patch.object(contract, "MAX_JSON_VALUES", 3):
            self.assertEqual(
                {"first": 1, "second": 2}, parse_canonical_bytes(three_values)
            )
        with mock.patch.object(contract, "MAX_JSON_VALUES", 2):
            with self.assertRaises(ContractError) as captured:
                parse_canonical_bytes(three_values)
        self.assertEqual("JSON_STRUCTURE_LIMIT", captured.exception.code)

    def test_document_load_is_bounded_if_file_grows_after_stat(self) -> None:
        path = Path("PRIVATE_GROWING_DOCUMENT_SENTINEL.json")
        metadata = mock.Mock(st_mode=contract.stat.S_IFREG, st_size=2)
        opener = mock.mock_open(read_data=b"{}x")
        with (
            mock.patch.object(contract, "MAX_ISOLATED_OUTPUT_BYTES", 2),
            mock.patch.object(Path, "stat", autospec=True, return_value=metadata),
            mock.patch.object(Path, "open", opener),
            mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("unbounded read must not be used"),
            ),
        ):
            with self.assertRaises(ContractError) as captured:
                load_json(path)
        self.assertEqual("DOCUMENT_SIZE_INVALID", captured.exception.code)
        opener.assert_called_once_with("rb")
        opener().read.assert_called_once_with(3)
        self.assertNotIn("PRIVATE_GROWING_DOCUMENT_SENTINEL", str(captured.exception))

        with mock.patch.object(
            Path,
            "stat",
            autospec=True,
            side_effect=OSError("PRIVATE_GROWING_DOCUMENT_SENTINEL"),
        ):
            with self.assertRaises(ContractError) as captured:
                load_json(path)
        self.assertEqual("DOCUMENT_UNAVAILABLE", captured.exception.code)
        self.assertNotIn("PRIVATE_GROWING_DOCUMENT_SENTINEL", str(captured.exception))

    def test_unknown_contract_is_never_inferred_from_shape(self) -> None:
        document = copy.deepcopy(
            load_json(FIXTURES / "positive" / "adapter-v1.1-transcribe" / "input.json")
        )
        document["contract_version"] = "tacua.local-processing-input@1.0.1"
        from local_processing_contract import digest_without

        document["input_digest"] = digest_without(document, "input_digest")
        with self.assertRaises(ContractError) as captured:
            validate_artifact(document)
        self.assertEqual("CONTRACT_VERSION_UNSUPPORTED", captured.exception.code)

    def test_direct_api_enforces_json_profile_and_result_size(self) -> None:
        command = copy.deepcopy(
            load_json(FIXTURES / "positive" / "adapter-v1.0-checkpoint" / "command.json")
        )
        command["argv"][1] = "e\u0301"
        with self.assertRaises(ContractError) as captured:
            validate_command(command)
        self.assertEqual("JSON_STRING_INVALID", captured.exception.code)

        result = copy.deepcopy(
            load_json(FIXTURES / "positive" / "adapter-v1.0-checkpoint" / "result.json")
        )
        result["stage_name"] = "generate_tickets"
        result["disposition"] = "terminal"
        result["result"] = {
            "candidates": [],
            "disposition": "no_issue_detected",
            "summary": "Synthetic bounded result.",
        }
        with mock.patch.object(contract, "MAX_LOCAL_DOCUMENT_BYTES", 128):
            with self.assertRaises(ContractError) as captured:
                validate_local_result(result)
        self.assertEqual("RESULT_SIZE_INVALID", captured.exception.code)

    def test_runtime_resource_bounds_cover_evidence_and_prospective_artifact(self) -> None:
        source_input = load_json(
            FIXTURES / "positive" / "adapter-v1.1-transcribe" / "input.json"
        )
        with mock.patch.object(contract, "MAX_INPUT_EVIDENCE_BYTES", 1):
            with self.assertRaises(ContractError) as captured:
                validate_artifact(source_input)
        self.assertEqual("INPUT_EVIDENCE_SIZE_INVALID", captured.exception.code)

        result = copy.deepcopy(
            load_json(
                FIXTURES
                / "positive"
                / "adapter-v1.1-transcribe"
                / "result.json"
            )
        )
        result["result"]["artifacts"][0]["payload"]["spans"][0]["text"] = (
            "\\" * MAX_TRANSCRIPT_BYTES
        )
        with self.assertRaises(ContractError) as captured:
            validate_exchange(source_input, result)
        self.assertEqual("ARTIFACT_DRAFT_SIZE_INVALID", captured.exception.code)

    def test_terminal_preview_and_isolated_source_provenance_are_exact(self) -> None:
        terminal = FIXTURES / "positive" / "adapter-v1.0-terminal-preview"
        result = load_json(terminal / "result.json")
        preview = result["result"]["candidates"][0]["previews"][0]
        body = (terminal / preview["body_file"]).read_bytes()
        self.assertEqual(preview["size_bytes"], len(body))
        self.assertEqual(preview["content_digest"], digest(body))

        isolated = FIXTURES / "positive" / "isolated-v1.0-adapter-v1.1-align"
        original = load_json(isolated / "input.json")
        wrapper = load_json(isolated / "isolated-input.json")
        self.assertEqual(original["input_digest"], digest_without(original, "input_digest"))
        self.assertEqual(original["input_digest"], wrapper["source_input_digest"])
        validate_isolated_exchange(
            original,
            wrapper,
            load_json(isolated / "isolated-output.json"),
        )
        validate_bundle(isolated)

        mismatch = FIXTURES / "negative" / "isolated-source-provenance-mismatch"
        with self.assertRaises(ContractError) as captured:
            validate_isolated_exchange(
                load_json(mismatch / "input.json"),
                load_json(mismatch / "isolated-input.json"),
                load_json(mismatch / "isolated-output.json"),
            )
        self.assertEqual("ISOLATED_SOURCE_PROVENANCE_MISMATCH", captured.exception.code)

    def test_bundle_preview_body_read_is_bounded_by_declared_size(self) -> None:
        source = FIXTURES / "positive" / "adapter-v1.0-terminal-preview"
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "bundle"
            shutil.copytree(source, copied)
            result = load_json(copied / "result.json")
            preview = result["result"]["candidates"][0]["previews"][0]
            body = copied / preview["body_file"]
            body.write_bytes(body.read_bytes() + b"unexpected")
            real_open = Path.open

            def guarded_open(path: Path, *args, **kwargs):
                if path == body:
                    raise AssertionError("size mismatch must reject before reading")
                return real_open(path, *args, **kwargs)

            with mock.patch.object(Path, "open", autospec=True, side_effect=guarded_open):
                with self.assertRaises(ContractError) as captured:
                    validate_bundle(copied)
            self.assertEqual("FIXTURE_PREVIEW_INVALID", captured.exception.code)

    def test_bundle_rejects_unlisted_nested_or_symlink_entries(self) -> None:
        source = FIXTURES / "positive" / "adapter-v1.0-checkpoint"
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "bundle"
            shutil.copytree(source, copied)
            (copied / "extra").mkdir()
            with self.assertRaises(ContractError) as captured:
                validate_bundle(copied)
            self.assertEqual("FIXTURE_BUNDLE_FILES_INVALID", captured.exception.code)
            (copied / "extra").rmdir()
            (copied / "alias.json").symlink_to(copied / "input.json")
            with self.assertRaises(ContractError) as captured:
                validate_bundle(copied)
            self.assertEqual("FIXTURE_BUNDLE_FILES_INVALID", captured.exception.code)

    def test_cli_rejects_malformed_types_and_arguments_without_echo(self) -> None:
        transcribe_result = load_json(
            FIXTURES / "positive" / "adapter-v1.1-transcribe" / "result.json"
        )
        bad_span = copy.deepcopy(transcribe_result)
        bad_span["result"]["artifacts"][0]["payload"]["spans"][0][
            "segment_id"
        ] = ["PRIVATE_ARG_SENTINEL"]
        bad_manifest = copy.deepcopy(
            load_json(
                FIXTURES / "positive" / "adapter-v1.1-transcribe" / "input.json"
            )
        )
        bad_manifest["capture"]["manifest"] = []
        bad_manifest["input_digest"] = digest_without(bad_manifest, "input_digest")
        terminal = copy.deepcopy(
            load_json(
                FIXTURES
                / "positive"
                / "adapter-v1.0-terminal-preview"
                / "result.json"
            )
        )
        terminal["result"]["disposition"] = ["PRIVATE_ARG_SENTINEL"]
        malformed = (
            {"contract_version": ["PRIVATE_ARG_SENTINEL"]},
            bad_span,
            bad_manifest,
            terminal,
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, document in enumerate(malformed):
                path = Path(temporary) / f"malformed-{index}.json"
                path.write_bytes(canonical_bytes(document))
                completed = subprocess.run(
                    [sys.executable, "-B", str(VALIDATOR), "artifact", str(path)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                with self.subTest(index=index):
                    self.assertEqual(1, completed.returncode)
                    self.assertEqual(b"", completed.stdout)
                    report = json.loads(completed.stderr)
                    self.assertEqual("invalid", report["status"])
                    self.assertNotIn(b"PRIVATE_ARG_SENTINEL", completed.stderr)
                    self.assertNotIn(b"Traceback", completed.stderr)
                    self.assertNotIn(str(path).encode(), completed.stderr)

        argument_cases = (
            ["PRIVATE_ARG_SENTINEL"],
            ["artifact"],
            [
                "artifact",
                str(FIXTURES / "positive" / "adapter-v1.0-checkpoint" / "command.json"),
                "PRIVATE_ARG_SENTINEL",
            ],
        )
        for arguments in argument_cases:
            completed = subprocess.run(
                [sys.executable, "-B", str(VALIDATOR), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            with self.subTest(arguments=arguments[:1]):
                self.assertEqual(2, completed.returncode)
                self.assertEqual(b"", completed.stdout)
                self.assertEqual("CLI_ARGUMENT_INVALID", json.loads(completed.stderr)["code"])
                self.assertNotIn(b"PRIVATE_ARG_SENTINEL", completed.stderr)

    def test_cli_reports_only_stable_content_free_json(self) -> None:
        valid = subprocess.run(
            [sys.executable, "-B", str(VALIDATOR), "fixtures", str(FIXTURES)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(0, valid.returncode, valid.stderr)
        self.assertEqual(
            {
                "authority": "synthetic_contract_only",
                "code": "LOCAL_PROCESSING_CONTRACT_VALID",
                "status": "valid",
            },
            json.loads(valid.stdout),
        )
        self.assertEqual(b"", valid.stderr)

        invalid_path = (
            FIXTURES
            / "negative"
            / "v1.1-transcript-artifact-tampered"
            / "input.json"
        )
        invalid = subprocess.run(
            [sys.executable, "-B", str(VALIDATOR), "artifact", str(invalid_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(1, invalid.returncode)
        self.assertEqual(b"", invalid.stdout)
        report = json.loads(invalid.stderr)
        self.assertEqual("invalid", report["status"])
        self.assertEqual("synthetic_contract_only", report["authority"])
        self.assertNotIn(PRIVATE_SENTINEL, invalid.stderr.decode("utf-8"))
        self.assertNotIn(str(invalid_path), invalid.stderr.decode("utf-8"))

        mismatch = FIXTURES / "negative" / "isolated-source-provenance-mismatch"
        isolated = subprocess.run(
            [
                sys.executable,
                "-B",
                str(VALIDATOR),
                "isolated-exchange",
                str(mismatch / "input.json"),
                str(mismatch / "isolated-input.json"),
                str(mismatch / "isolated-output.json"),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(1, isolated.returncode)
        self.assertEqual(b"", isolated.stdout)
        self.assertEqual(
            "ISOLATED_SOURCE_PROVENANCE_MISMATCH",
            json.loads(isolated.stderr)["code"],
        )

    def test_fixture_regeneration_is_byte_reproducible(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-B", str(REGENERATOR), "--check"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
