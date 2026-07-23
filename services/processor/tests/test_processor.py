# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
PROCESSOR_PATH = ROOT / "services" / "processor" / "processor.py"
SYNTHETIC_FIXTURE_PATH = (
    ROOT / "services" / "processor" / "scripts" / "build_synthetic_runner_fixture.py"
)
CHECKPOINT_INPUT = (
    ROOT
    / "contracts"
    / "local-processing"
    / "fixtures"
    / "positive"
    / "adapter-v1.0-checkpoint"
    / "input.json"
)
TERMINAL_FIXTURE = (
    ROOT
    / "contracts"
    / "local-processing"
    / "fixtures"
    / "positive"
    / "adapter-v1.0-terminal-preview"
)
DIAGNOSTIC_REQUEST = (
    ROOT
    / "contracts"
    / "sdk-backend-protocol"
    / "fixtures"
    / "positive"
    / "diagnostic-upload-request.json"
)

spec = importlib.util.spec_from_file_location("tacua_offline_processor", PROCESSOR_PATH)
assert spec is not None and spec.loader is not None
processor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(processor)

fixture_spec = importlib.util.spec_from_file_location(
    "tacua_synthetic_runner_fixture", SYNTHETIC_FIXTURE_PATH
)
assert fixture_spec is not None and fixture_spec.loader is not None
synthetic_fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(synthetic_fixture)

sys.path.insert(0, str(ROOT / "contracts" / "local-processing" / "src"))
import local_processing_contract  # noqa: E402

sys.path.insert(0, str(ROOT / "contracts" / "ticket-candidate" / "src"))
import ticket_candidate_contract  # noqa: E402

sys.path.insert(0, str(ROOT / "services" / "backend" / "src"))
from tacua_backend import evidence_domain  # noqa: E402


def source_fixture(path: Path) -> dict:
    return json.loads(path.read_bytes())


def isolated_wrapper(source: dict) -> dict:
    wrapper = {
        "contract_version": processor.ISOLATED_INPUT_CONTRACT,
        "isolated_input_digest": "sha256:" + "0" * 64,
        "source_input": source,
        "source_input_digest": source["input_digest"],
    }
    wrapper["isolated_input_digest"] = processor.digest_without(
        wrapper, "isolated_input_digest"
    )
    return wrapper


class OfflineProcessorTests(unittest.TestCase):
    def test_synthetic_runner_fixture_rebinds_exact_bytes_canonically(self) -> None:
        media = b"synthetic MOV bytes for an inert runner fixture\n"
        source_bytes, diagnostic_bytes = synthetic_fixture.build(media)
        source = json.loads(source_bytes)
        diagnostic = json.loads(diagnostic_bytes)

        self.assertEqual(synthetic_fixture.canonical_bytes(source), source_bytes)
        self.assertEqual(
            synthetic_fixture.canonical_bytes(diagnostic), diagnostic_bytes
        )
        local_processing_contract.validate_local_input(source)

        segment = source["capture"]["segments"][0]
        manifest_segment = source["capture"]["manifest"]["segments"][0]["content"]
        self.assertEqual(segment["read_only_path"], "/dev/fd/9")
        self.assertEqual(segment["size_bytes"], len(media))
        self.assertEqual(segment["content_digest"], processor.digest_bytes(media))
        self.assertEqual(manifest_segment["content_digest"], segment["content_digest"])
        self.assertEqual(manifest_segment["size_bytes"], len(media))

        diagnostic_reference = source["capture"]["diagnostics"][0]
        self.assertEqual(diagnostic_reference["read_only_path"], "/dev/fd/10")
        self.assertEqual(diagnostic_reference["size_bytes"], len(diagnostic_bytes))
        self.assertEqual(
            diagnostic_reference["content_digest"],
            processor.digest_bytes(diagnostic_bytes),
        )
        self.assertEqual(
            diagnostic["envelope_digest"],
            processor.digest_without(diagnostic, "envelope_digest"),
        )
        self.assertIn(
            diagnostic["envelope_digest"],
            source["job"]["inputs"]["diagnostic_envelope_digests"],
        )

    def test_checkpoint_main_emits_one_canonical_content_free_envelope(self) -> None:
        source = source_fixture(CHECKPOINT_INPUT)
        wrapper = isolated_wrapper(source)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_path = root / "input.json"
            model_path = root / "model.bin"
            input_path.write_bytes(processor.canonical_bytes(wrapper))
            model_path.write_bytes(b"synthetic model\n")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROCESSOR_PATH),
                    "--input",
                    str(input_path),
                    "--model",
                    str(model_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        document = json.loads(completed.stdout)
        self.assertEqual(processor.canonical_bytes(document), completed.stdout)
        self.assertEqual(document["contract_version"], processor.ISOLATED_OUTPUT_CONTRACT)
        self.assertEqual(document["previews"], [])
        self.assertEqual(document["result"]["disposition"], "checkpoint")
        self.assertIsNone(document["result"]["result"])
        self.assertEqual(
            document["result_digest"], processor.digest(document["result"])
        )

    def test_tampered_isolated_digest_fails_without_output(self) -> None:
        source = source_fixture(CHECKPOINT_INPUT)
        wrapper = isolated_wrapper(source)
        wrapper["isolated_input_digest"] = "sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_path = root / "input.json"
            model_path = root / "model.bin"
            input_path.write_bytes(processor.canonical_bytes(wrapper))
            model_path.write_bytes(b"synthetic model\n")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROCESSOR_PATH),
                    "--input",
                    str(input_path),
                    "--model",
                    str(model_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_wrapper_accepts_runner_rewritten_read_only_paths(self) -> None:
        source = source_fixture(TERMINAL_FIXTURE / "input.json")
        original_digest = source["input_digest"]
        source["capture"]["segments"][0]["read_only_path"] = (
            "/tacua-private-test/input/evidence/segment.mov"
        )
        source["capture"]["diagnostics"][0]["read_only_path"] = (
            "/tacua-private-test/input/evidence/diagnostic.json"
        )
        wrapper = {
            "contract_version": processor.ISOLATED_INPUT_CONTRACT,
            "isolated_input_digest": "sha256:" + "0" * 64,
            "source_input": source,
            "source_input_digest": original_digest,
        }
        wrapper["isolated_input_digest"] = processor.digest_without(
            wrapper,
            "isolated_input_digest",
        )

        self.assertIs(processor.validate_wrapper(wrapper), source)
        self.assertNotEqual(
            processor.digest_without(source, "input_digest"),
            original_digest,
        )

    def test_dynamic_candidate_and_evidence_pass_authoritative_contracts(self) -> None:
        source = source_fixture(TERMINAL_FIXTURE / "input.json")
        keyframe = (TERMINAL_FIXTURE / "preview-synthetic.png").read_bytes()
        bundle, name, body = processor.build_candidate_bundle(
            source,
            mark={
                "elapsed_ms": 20_000,
                "event_id": "event_issue",
                "kind": "spoken",
                "marker_id": "marker_synthetic",
                "occurred_at": "2026-07-21T10:00:20Z",
                "sequence": 11,
            },
            ordinal=1,
            keyframe=keyframe,
            transcript="The save button uses the wrong copy and should say Save profile.",
            narration_sources=[
                {
                    "content_digest": "sha256:" + "3" * 64,
                    "content_type": "video/quicktime",
                    "end_ms": 40_000,
                    "segment_id": "segment_synthetic",
                    "size_bytes": 2_048,
                    "start_ms": 5_000,
                }
            ],
            model_id="whisper-base-en",
            model_digest="sha256:" + "a" * 64,
            created_at="2026-07-21T10:03:09Z",
        )
        ticket_candidate_contract.validate_chain([bundle["candidate"]])
        evidence_domain.validate_manifest(bundle["evidence_manifest"])
        self.assertEqual(name, bundle["previews"][0]["body_file"])
        self.assertEqual(body, keyframe)
        self.assertEqual(
            bundle["previews"][0]["content_digest"],
            processor.digest_bytes(keyframe),
        )
        self.assertEqual(bundle["candidate"]["state"], "draft")
        clarification = bundle["candidate"]["content"]["clarifications"][0]
        self.assertEqual(clarification["impact"], "blocking")
        self.assertEqual(clarification["status"], "unresolved")
        evidence_types = {
            item["evidence_type"] for item in bundle["evidence_manifest"]["items"]
        }
        self.assertEqual(evidence_types, {"media.keyframe", "media.clip"})
        self.assertNotIn(
            "media.transcript_excerpt",
            evidence_types,
        )

    def test_segment_boundary_selects_the_later_segment(self) -> None:
        first = {"end_ms": 10_000, "sequence": 0, "start_ms": 0}
        second = {"end_ms": 20_000, "sequence": 1, "start_ms": 10_000}
        self.assertIs(
            processor.segment_for_time([first, second], 10_000),
            second,
        )
        self.assertIs(
            processor.segment_for_time([first, second], 20_000),
            second,
        )

    def test_narration_window_can_span_adjacent_segments(self) -> None:
        first = {
            "end_ms": 10_000,
            "sequence": 0,
            "start_ms": 0,
        }
        second = {
            "end_ms": 20_000,
            "sequence": 1,
            "start_ms": 10_000,
        }
        selected = processor.narration_segments([first, second], 5_000, 15_000)
        self.assertEqual(
            [(start, end) for _segment, start, end in selected],
            [(5_000, 10_000), (10_000, 15_000)],
        )
        self.assertEqual(
            processor.narration_segments([first, second], 5_000, 25_000),
            [],
        )

    def test_marker_clocks_must_agree_and_close_marks_are_ambiguous(self) -> None:
        envelope = json.loads(DIAGNOSTIC_REQUEST.read_bytes())["envelope"]
        mark = next(
            event for event in envelope["events"] if event["event_type"] == "issue_mark"
        )
        mark["data"]["narration_elapsed_ms"] += 1
        with self.assertRaises(processor.ProcessorError):
            processor.issue_marks([envelope])

        ambiguous = processor.ambiguous_marker_ids(
            [
                {"elapsed_ms": 20_000, "marker_id": "marker_first"},
                {"elapsed_ms": 25_000, "marker_id": "marker_second"},
                {"elapsed_ms": 60_000, "marker_id": "marker_third"},
            ]
        )
        self.assertEqual(ambiguous, {"marker_first", "marker_second"})

    def test_video_gap_rejects_candidate_before_media_execution(self) -> None:
        source = source_fixture(TERMINAL_FIXTURE / "input.json")
        envelope = json.loads(DIAGNOSTIC_REQUEST.read_bytes())["envelope"]
        diagnostic = processor.canonical_bytes(envelope)
        source["capture"]["manifest"]["gaps"][0]["time_range"] = {
            "clock": "session_monotonic",
            "end_ms": 20_001,
            "start_ms": 19_999,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            diagnostic_path = root / "diagnostic.json"
            diagnostic_path.write_bytes(diagnostic)
            diagnostic_reference = source["capture"]["diagnostics"][0]
            diagnostic_reference["content_digest"] = processor.digest_bytes(diagnostic)
            diagnostic_reference["read_only_path"] = str(diagnostic_path)
            diagnostic_reference["size_bytes"] = len(diagnostic)

            media_path = root / "segment.mov"
            media_path.write_bytes(b"x" * 2_048)
            source["capture"]["segments"][0]["read_only_path"] = str(media_path)
            with mock.patch.object(
                processor,
                "extract_keyframe",
                side_effect=AssertionError("media extraction must not run inside a video gap"),
            ):
                with self.assertRaisesRegex(
                    processor.ProcessorError,
                    "app-video capture gap",
                ):
                    processor.generate_tickets(
                        source,
                        ffmpeg=Path("/not-used/ffmpeg"),
                        ffprobe=Path("/not-used/ffprobe"),
                        whisper_cli=Path("/not-used/whisper"),
                        model=Path("/not-used/model"),
                        model_id="whisper-base-en",
                        model_digest="sha256:" + "a" * 64,
                    )

    def test_silence_gate_and_focal_transcript_selection(self) -> None:
        silence = processor.array("h", [0] * (processor.PCM_FRAME_SAMPLES * 10))
        speech = processor.array(
            "h",
            [1_000, -1_000] * (processor.PCM_FRAME_SAMPLES * 3),
        )
        self.assertFalse(processor.has_narration_signal(silence))
        self.assertTrue(processor.has_narration_signal(speech))

        text = processor.select_transcript_text(
            {
                "transcription": [
                    {
                        "offsets": {"from": 0, "to": 2_000},
                        "text": "Unrelated opening context.",
                    },
                    {
                        "offsets": {"from": 14_000, "to": 18_000},
                        "text": "The button copy is wrong.",
                    },
                    {
                        "offsets": {"from": 30_000, "to": 35_000},
                        "text": "Unrelated later context.",
                    },
                ]
            },
            marker_offset_ms=15_000,
        )
        self.assertEqual(text, "The button copy is wrong.")

    def test_keyframe_adapts_until_preview_fits(self) -> None:
        attempts: list[str] = []

        def fake_run(argv: list[str], **_kwargs: object) -> bytes:
            filter_value = argv[argv.index("-vf") + 1]
            attempts.append(filter_value)
            destination = Path(argv[-1])
            if "1080" in filter_value:
                destination.write_bytes(
                    processor.PNG_MAGIC + (b"x" * processor.MAX_PREVIEW_BYTES)
                )
            else:
                destination.write_bytes(processor.PNG_MAGIC + b"safe")
            return b""

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "frame.png"
            with mock.patch.object(processor, "run_bounded", side_effect=fake_run):
                body = processor.extract_keyframe(
                    Path("/fake/ffmpeg"),
                    {
                        "end_ms": 60_000,
                        "path": Path("/fake/media"),
                        "start_ms": 0,
                    },
                    20_000,
                    destination,
                )
        self.assertEqual(body, processor.PNG_MAGIC + b"safe")
        self.assertEqual(len(attempts), 2)
        self.assertIn("1080", attempts[0])
        self.assertIn("720", attempts[1])

    def test_subprocess_and_total_preview_output_are_bounded(self) -> None:
        with mock.patch.object(processor, "MAX_TOOL_STDOUT_BYTES", 8):
            with self.assertRaisesRegex(
                processor.ProcessorError,
                "output exceeded",
            ):
                processor.run_bounded(
                    [sys.executable, "-c", "print('x' * 64)"],
                    capture_stdout=True,
                )

        preview = processor.PNG_MAGIC + b"x"
        with mock.patch.object(
            processor,
            "MAX_TOTAL_PREVIEW_BYTES",
            len(preview),
        ):
            with self.assertRaisesRegex(
                processor.ProcessorError,
                "total bound",
            ):
                processor.isolated_output(
                    {"contract_version": "test"},
                    [("frame-001.png", preview), ("frame-002.png", preview)],
                )

    def test_transcript_redaction_is_bounded_and_credential_safe(self) -> None:
        text = processor.redact_text(
            "Use bearer abcdefghijklmnopqrstuvwxyz123456 and "
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789 before " + ("x" * 8_000)
        )
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", text)
        self.assertNotIn("ghp_", text)
        self.assertLessEqual(len(text), processor.MAX_TRANSCRIPT_CODEPOINTS)
        self.assertIn("[redacted credential]", text)


if __name__ == "__main__":
    unittest.main()
