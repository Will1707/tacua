# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "contracts" / "runtime" / "src"))

import protocol_contract as protocol  # noqa: E402


POSITIVE = ROOT / "fixtures" / "positive"
NEGATIVE = ROOT / "fixtures" / "negative"
CANONICAL = ROOT / "fixtures" / "canonical"


def load(name: str) -> dict:
    return protocol.load_json(POSITIVE / name)


class ProtocolContractTests(unittest.TestCase):
    def test_every_positive_fixture_validates(self) -> None:
        for path in sorted(POSITIVE.glob("*.json")):
            with self.subTest(path=path.name):
                protocol.validate(protocol.load_json(path))

    def test_full_lifecycle_bundle_validates(self) -> None:
        protocol.validate_bundle(
            load("build-identity.json"),
            load("capture-scope.json"),
            load("launch-exchange-request.json"),
            load("launch-exchange-receipt.json"),
            [(load("segment-upload-intent.json"), load("segment-upload-receipt.json"))],
            [(load("diagnostic-upload-request.json"), load("diagnostic-upload-receipt.json"))],
            load("completion-request.json"),
            load("completion-receipt.json"),
            (load("deletion-request.json"), load("deletion-tombstone.json")),
        )

    def test_exact_idempotent_replays_validate(self) -> None:
        for filename in (
            "launch-exchange-request.json",
            "segment-upload-intent.json",
            "diagnostic-upload-request.json",
            "completion-request.json",
            "deletion-request.json",
        ):
            with self.subTest(filename=filename):
                value = load(filename)
                protocol.validate_idempotent_replay(value, copy.deepcopy(value))

    def test_completion_receipt_is_cleanup_authority_not_agent_authority(self) -> None:
        request = load("completion-request.json")
        receipt = load("completion-receipt.json")
        protocol.validate_completion_pair(request, receipt)
        self.assertEqual(receipt["processing_job"]["status"], "queued")
        self.assertEqual(receipt["credential"]["state"], "completion_replay_only")
        self.assertEqual(receipt["local_cleanup"]["state"], "authorized_after_durable_receipt")
        self.assertNotIn("agent_authorization", protocol.canonical_json(receipt))

    def test_launch_receipt_cannot_echo_secrets(self) -> None:
        receipt = load("launch-exchange-receipt.json")
        encoded = protocol.canonical_json(receipt)
        self.assertNotIn("launch_code", encoded)
        self.assertNotIn("secret", encoded)

    def test_canonical_digest_vectors(self) -> None:
        fixture = json.loads((CANONICAL / "digest-vectors.json").read_text(encoding="utf-8"))
        self.assertEqual(fixture["specification"], "tacua.canonical-json@1.0.0")
        for vector in fixture["vectors"]:
            with self.subTest(vector=vector["name"]):
                canonical = protocol.canonical_json(vector["value"])
                encoded = canonical.encode("utf-8")
                self.assertEqual(canonical, vector["canonical_utf8"])
                self.assertEqual(encoded.hex(), vector["canonical_utf8_hex"])
                self.assertEqual(protocol.digest(encoded), vector["sha256"])

    def test_artifact_digest_vectors(self) -> None:
        fixture = json.loads((CANONICAL / "artifact-digests.json").read_text(encoding="utf-8"))
        for vector in fixture["artifacts"]:
            with self.subTest(fixture=vector["fixture"]):
                value = protocol.load_json((CANONICAL / vector["fixture"]).resolve())
                field = vector["digest_field"]
                self.assertEqual(value[field], vector["expected_digest"])
                self.assertEqual(protocol.digest_without(value, field), vector["expected_digest"])

    def test_negative_conformance_fixtures(self) -> None:
        index = json.loads((NEGATIVE / "cases.json").read_text(encoding="utf-8"))
        for case in index["cases"]:
            with self.subTest(case=case["file"]):
                with self.assertRaises(protocol.ContractError) as caught:
                    self._run_negative_case(case)
                self.assertEqual(caught.exception.code, case["expected_code"])

    def _run_negative_case(self, case: dict[str, str]) -> None:
        mode = case["mode"]
        path = NEGATIVE / case["file"]
        if mode == "load":
            protocol.load_json(path)
            return
        value = protocol.load_json(path)
        if mode == "validate":
            protocol.validate(value)
        elif mode == "segment_pair":
            protocol.validate_segment_pair(load("segment-upload-intent.json"), value)
        elif mode == "completion_pair":
            protocol.validate_completion_pair(load("completion-request.json"), value)
        elif mode == "deletion_pair":
            protocol.validate_deletion_pair(load("deletion-request.json"), value)
        elif mode == "completion_replay":
            protocol.validate_idempotent_replay(load("completion-request.json"), value)
        else:
            self.fail(f"unknown negative-fixture mode {mode!r}")

    def test_schema_files_are_valid_json(self) -> None:
        for path in sorted((ROOT / "schemas").glob("*.json")):
            with self.subTest(path=path.name):
                schema = protocol.load_json(path)
                stack = [schema]
                while stack:
                    node = stack.pop()
                    if isinstance(node, dict):
                        if node.get("type") == "object":
                            self.assertIs(node.get("additionalProperties"), False)
                        stack.extend(node.values())
                    elif isinstance(node, list):
                        stack.extend(node)


if __name__ == "__main__":
    unittest.main()
