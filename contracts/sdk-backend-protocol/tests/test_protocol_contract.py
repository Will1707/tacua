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
            [
                (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
            ],
            [(load("segment-upload-intent.json"), load("segment-upload-receipt.json"))],
            [(load("diagnostic-upload-request.json"), load("diagnostic-upload-receipt.json"))],
            load("completion-request.json"),
            load("completion-receipt.json"),
            (load("deletion-request.json"), load("deletion-tombstone.json")),
        )
        self.assertNotEqual(
            load("segment-upload-intent.json")["credential_id"],
            load("completion-request.json")["credential_id"],
        )

    def test_exact_idempotent_request_and_response_replays_validate(self) -> None:
        exchanges = (
            ("launch-exchange-request.json", "launch-exchange-receipt.json"),
            ("segment-upload-intent.json", "segment-upload-receipt.json"),
            ("diagnostic-upload-request.json", "diagnostic-upload-receipt.json"),
            ("completion-request.json", "completion-receipt.json"),
            ("deletion-request.json", "deletion-tombstone.json"),
        )
        for request_filename, response_filename in exchanges:
            with self.subTest(request=request_filename):
                request = load(request_filename)
                response = load(response_filename)
                protocol.validate_idempotent_replay(
                    request,
                    response,
                    copy.deepcopy(request),
                    copy.deepcopy(response),
                )

    def test_current_credential_can_recover_exact_upload_accepted_before_rotation(self) -> None:
        _, history = protocol.validate_launch_chain(
            load("build-identity.json"),
            load("capture-scope.json"),
            [
                (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
            ],
        )
        request = load("segment-upload-intent.json")
        response = load("segment-upload-receipt.json")
        authentication_id = load("receiving-resume-receipt.json")["credential"]["credential_id"]
        self.assertNotEqual(request["credential_id"], authentication_id)

        protocol.validate_authenticated_exact_replay(
            request,
            response,
            copy.deepcopy(request),
            copy.deepcopy(response),
            authentication_id,
            "2026-07-21T10:02:10Z",
            history,
            "receiving",
        )

    def test_missing_durable_upload_cannot_reuse_revoked_body_credential(self) -> None:
        _, history = protocol.validate_launch_chain(
            load("build-identity.json"),
            load("capture-scope.json"),
            [
                (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
            ],
        )
        request = load("segment-upload-intent.json")
        authentication_id = load("receiving-resume-receipt.json")["credential"]["credential_id"]
        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_new_upload_authentication(
                request,
                authentication_id,
                "2026-07-21T10:02:10Z",
                history,
                "receiving",
            )
        self.assertEqual(caught.exception.code, "AUTHENTICATION_CREDENTIAL_MISMATCH")

        replacement = copy.deepcopy(request)
        replacement.update(
            {
                "upload_id": "upload_segment_after_rotation",
                "credential_id": authentication_id,
                "requested_at": "2026-07-21T10:02:09Z",
            }
        )
        replacement = protocol.seal(replacement)
        protocol.validate_new_upload_authentication(
            replacement,
            authentication_id,
            "2026-07-21T10:02:10Z",
            history,
            "receiving",
        )

    def test_completed_resume_credential_recovers_only_its_bound_completion(self) -> None:
        _, history = protocol.validate_launch_chain(
            load("build-identity.json"),
            load("capture-scope.json"),
            [
                (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
                (load("completed-resume-request.json"), load("completed-resume-receipt.json")),
            ],
        )
        authentication_id = load("completed-resume-receipt.json")["credential"]["credential_id"]
        completion_request = load("completion-request.json")
        completion_response = load("completion-receipt.json")
        self.assertNotEqual(completion_request["credential_id"], authentication_id)
        protocol.validate_authenticated_exact_replay(
            completion_request,
            completion_response,
            copy.deepcopy(completion_request),
            copy.deepcopy(completion_response),
            authentication_id,
            "2026-07-21T10:02:30Z",
            history,
            "completed",
        )

        segment_request = load("segment-upload-intent.json")
        segment_response = load("segment-upload-receipt.json")
        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_authenticated_exact_replay(
                segment_request,
                segment_response,
                copy.deepcopy(segment_request),
                copy.deepcopy(segment_response),
                authentication_id,
                "2026-07-21T10:02:30Z",
                history,
                "completed",
            )
        self.assertEqual(caught.exception.code, "REPLAY_CAPABILITY_MISMATCH")

    def test_exact_lookup_precedes_rotated_replay_authorization(self) -> None:
        _, history = protocol.validate_launch_chain(
            load("build-identity.json"),
            load("capture-scope.json"),
            [
                (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
                (load("completed-resume-request.json"), load("completed-resume-receipt.json")),
            ],
        )
        request = load("segment-upload-intent.json")
        conflicting = copy.deepcopy(request)
        conflicting["requested_at"] = "2026-07-21T10:01:58Z"
        conflicting = protocol.seal(conflicting)
        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_authenticated_exact_replay(
                request,
                load("segment-upload-receipt.json"),
                conflicting,
                load("segment-upload-receipt.json"),
                "credential_not_current",
                "2026-07-21T10:02:30Z",
                history,
                "completed",
            )
        self.assertEqual(caught.exception.code, "CURRENT_CREDENTIAL_MISMATCH")

        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_authenticated_exact_replay(
                request,
                load("segment-upload-receipt.json"),
                conflicting,
                load("segment-upload-receipt.json"),
                load("completed-resume-receipt.json")["credential"]["credential_id"],
                "2026-07-21T10:02:30Z",
                history,
                "completed",
            )
        self.assertEqual(caught.exception.code, "IDEMPOTENCY_CONFLICT")

    def test_first_launch_uses_server_internal_receipt_chronology(self) -> None:
        request = load("launch-exchange-request.json")
        receipt = load("launch-exchange-receipt.json")
        request["requested_at"] = "2099-01-01T00:00:00Z"
        request = protocol.seal(request)
        receipt["request_digest"] = request["request_digest"]
        receipt = protocol.seal(receipt)
        protocol.validate_launch_pair(request, receipt)

        receipt["received_at"] = "2026-07-21T09:57:02Z"
        receipt = protocol.seal(receipt)
        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_launch_pair(request, receipt)
        self.assertEqual(caught.exception.code, "INVALID_CHRONOLOGY")

    def test_completed_resume_cannot_reenable_upload(self) -> None:
        request = load("completed-resume-request.json")
        receipt = load("completed-resume-receipt.json")
        protocol.validate_launch_pair(request, receipt)
        self.assertEqual(receipt["session_state"], "completed")
        self.assertEqual(receipt["credential"]["state"], "completion_replay_or_delete_only")
        self.assertEqual(receipt["credential"]["replay_completion_id"], request["expected_completion_id"])
        self.assertEqual(
            receipt["previous_credential_revocation"]["credential_id"],
            request["previous_credential_id"],
        )

    def test_launch_chain_rejects_reuse_of_any_earlier_credential_id(self) -> None:
        request = load("completed-resume-request.json")
        receipt = load("completed-resume-receipt.json")
        reused_id = load("launch-exchange-receipt.json")["credential"]["credential_id"]
        request["credential"]["credential_id"] = reused_id
        request = protocol.seal(request)
        receipt["request_digest"] = request["request_digest"]
        receipt["credential"]["credential_id"] = reused_id
        receipt = protocol.seal(receipt)
        protocol.validate_launch_pair(request, receipt)

        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_launch_chain(
                load("build-identity.json"),
                load("capture-scope.json"),
                [
                    (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                    (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
                    (request, receipt),
                ],
            )
        self.assertEqual(caught.exception.code, "DUPLICATE_CREDENTIAL_ID")

    def test_launch_chain_enforces_credential_history_bound(self) -> None:
        pair = (load("launch-exchange-request.json"), load("launch-exchange-receipt.json"))
        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_launch_chain(
                load("build-identity.json"),
                load("capture-scope.json"),
                [pair] * (protocol.MAX_SESSION_CREDENTIALS + 1),
            )
        self.assertEqual(protocol.MAX_SESSION_CREDENTIALS, 64)
        self.assertEqual(caught.exception.code, "CREDENTIAL_ROTATION_LIMIT_REACHED")

    def test_launch_chain_rejects_completed_to_receiving_regression(self) -> None:
        completed_request = load("completed-resume-request.json")
        completed_receipt = load("completed-resume-receipt.json")
        request = copy.deepcopy(completed_request)
        request.update(
            {
                "exchange_id": "exchange_state_regression",
                "launch_code": "V" * 43,
                "expected_session_state": "receiving",
                "expected_completion_id": None,
                "previous_credential_id": completed_receipt["credential"]["credential_id"],
                "requested_at": "2026-07-21T10:02:30Z",
            }
        )
        request["credential"].update({"credential_id": "credential_state_regression", "secret": "W" * 43})
        request = protocol.seal(request)

        receipt = copy.deepcopy(completed_receipt)
        receipt.update(
            {
                "exchange_id": request["exchange_id"],
                "request_digest": request["request_digest"],
                "session_state": "receiving",
                "received_at": "2026-07-21T10:02:31Z",
                "issued_at": "2026-07-21T10:02:31Z",
            }
        )
        receipt["credential"].update(
            {
                "credential_id": request["credential"]["credential_id"],
                "state": "active",
                "replay_completion_id": None,
            }
        )
        receipt["previous_credential_revocation"].update(
            {
                "credential_id": request["previous_credential_id"],
                "revoked_at": receipt["issued_at"],
            }
        )
        receipt = protocol.seal(receipt)
        protocol.validate_launch_pair(request, receipt)

        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_launch_chain(
                load("build-identity.json"),
                load("capture-scope.json"),
                [
                    (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                    (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
                    (completed_request, completed_receipt),
                    (request, receipt),
                ],
            )
        self.assertEqual(caught.exception.code, "SESSION_STATE_REGRESSION")

    def test_every_pair_binds_the_authenticated_credential(self) -> None:
        cases = (
            (
                load("launch-exchange-request.json"),
                load("launch-exchange-receipt.json"),
                protocol.validate_launch_pair,
                "LAUNCH_BINDING_MISMATCH",
                lambda value: value["credential"].__setitem__("credential_id", "credential_other"),
            ),
            (
                load("segment-upload-intent.json"),
                load("segment-upload-receipt.json"),
                protocol.validate_segment_pair,
                "SEGMENT_BINDING_MISMATCH",
                lambda value: value.__setitem__("credential_id", "credential_other"),
            ),
            (
                load("diagnostic-upload-request.json"),
                load("diagnostic-upload-receipt.json"),
                protocol.validate_diagnostic_pair,
                "DIAGNOSTIC_BINDING_MISMATCH",
                lambda value: value.__setitem__("credential_id", "credential_other"),
            ),
            (
                load("completion-request.json"),
                load("completion-receipt.json"),
                protocol.validate_completion_pair,
                "COMPLETION_CREDENTIAL_MISMATCH",
                lambda value: value["credential"].__setitem__("credential_id", "credential_other"),
            ),
            (
                load("deletion-request.json"),
                load("deletion-tombstone.json"),
                protocol.validate_deletion_pair,
                "DELETION_BINDING_MISMATCH",
                lambda value: value["credential"].__setitem__("credential_id", "credential_other"),
            ),
        )
        for request, response, validator, expected_code, mutate in cases:
            with self.subTest(request=request["message_type"]):
                mutate(response)
                response = protocol.seal(response)
                with self.assertRaises(protocol.ContractError) as caught:
                    validator(request, response)
                self.assertEqual(caught.exception.code, expected_code)

    def test_bundle_rejects_unrelated_credential_not_in_rotation_chain(self) -> None:
        intent = load("segment-upload-intent.json")
        receipt = load("segment-upload-receipt.json")
        intent["credential_id"] = "credential_other"
        intent = protocol.seal(intent)
        receipt["credential_id"] = "credential_other"
        receipt["intent_digest"] = intent["intent_digest"]
        receipt = protocol.seal(receipt)
        protocol.validate_segment_pair(intent, receipt)
        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_bundle(
                load("build-identity.json"),
                load("capture-scope.json"),
                [
                    (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                    (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
                ],
                [(intent, receipt)],
                [(load("diagnostic-upload-request.json"), load("diagnostic-upload-receipt.json"))],
                load("completion-request.json"),
                load("completion-receipt.json"),
                (load("deletion-request.json"), load("deletion-tombstone.json")),
            )
        self.assertEqual(caught.exception.code, "UNRELATED_CREDENTIAL")

    def test_bundle_rejects_backdated_old_credential_accepted_after_revocation(self) -> None:
        intent = load("segment-upload-intent.json")
        receipt = load("segment-upload-receipt.json")
        intent = protocol.seal(intent)
        receipt["intent_digest"] = intent["intent_digest"]
        receipt["runtime_receipt"]["received_at"] = "2026-07-21T10:02:04Z"
        receipt["runtime_receipt"]["receipt_digest"] = protocol.runtime.digest_without(
            receipt["runtime_receipt"],
            "receipt_digest",
        )
        receipt = protocol.seal(receipt)
        protocol.validate_segment_pair(intent, receipt)
        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_bundle(
                load("build-identity.json"),
                load("capture-scope.json"),
                [
                    (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                    (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
                ],
                [(intent, receipt)],
                [(load("diagnostic-upload-request.json"), load("diagnostic-upload-receipt.json"))],
                load("completion-request.json"),
                load("completion-receipt.json"),
                (load("deletion-request.json"), load("deletion-tombstone.json")),
            )
        self.assertEqual(caught.exception.code, "REVOKED_CREDENTIAL")

    def test_completion_must_use_current_credential_at_server_acceptance(self) -> None:
        request = load("completion-request.json")
        receipt = load("completion-receipt.json")
        request["credential_id"] = load("launch-exchange-receipt.json")["credential"]["credential_id"]
        request = protocol.seal(request)
        receipt["request_digest"] = request["request_digest"]
        receipt["credential"]["credential_id"] = request["credential_id"]
        receipt = protocol.seal(receipt)
        protocol.validate_completion_pair(request, receipt)
        with self.assertRaises(protocol.ContractError) as caught:
            protocol.validate_bundle(
                load("build-identity.json"),
                load("capture-scope.json"),
                [
                    (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                    (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
                ],
                [(load("segment-upload-intent.json"), load("segment-upload-receipt.json"))],
                [(load("diagnostic-upload-request.json"), load("diagnostic-upload-receipt.json"))],
                request,
                receipt,
            )
        self.assertEqual(caught.exception.code, "CURRENT_CREDENTIAL_MISMATCH")

    def test_completion_compares_segment_receipts_as_keyed_sets_not_arrival_order(self) -> None:
        first_intent = load("segment-upload-intent.json")
        first_receipt = load("segment-upload-receipt.json")
        second_intent = copy.deepcopy(first_intent)
        second_intent.update(
            {
                "upload_id": "upload_segment_second",
                "sequence": 1,
                "segment_id": "segment_second",
                "sidecar_digest": "sha256:" + "6" * 64,
            }
        )
        second_intent["transport"]["content_digest"] = "sha256:" + "5" * 64
        second_intent = protocol.seal(second_intent)

        second_receipt = copy.deepcopy(first_receipt)
        second_receipt.update(
            {
                "upload_id": second_intent["upload_id"],
                "intent_digest": second_intent["intent_digest"],
                "sequence": second_intent["sequence"],
                "segment_id": second_intent["segment_id"],
                "sidecar_digest": second_intent["sidecar_digest"],
                "transport_digest": second_intent["transport"]["content_digest"],
            }
        )
        second_receipt["runtime_receipt"].update(
            {
                "object_id": "object_segment_second",
                "segment_id": second_intent["segment_id"],
                "content_digest": second_intent["transport"]["content_digest"],
            }
        )
        second_receipt["runtime_receipt"]["receipt_digest"] = protocol.runtime.digest_without(
            second_receipt["runtime_receipt"],
            "receipt_digest",
        )
        second_receipt = protocol.seal(second_receipt)
        protocol.validate_segment_pair(second_intent, second_receipt)

        completion_request = load("completion-request.json")
        manifest = completion_request["capture_manifest"]
        manifest["segments"][0]["time_range"]["end_ms"] = 30000
        second_segment = copy.deepcopy(manifest["segments"][0])
        second_segment.update({"segment_id": second_intent["segment_id"], "sequence": 1})
        second_segment["time_range"].update({"start_ms": 30000, "end_ms": 60000})
        second_segment["content"].update(
            {
                "content_digest": second_intent["transport"]["content_digest"],
                "sidecar_digest": second_intent["sidecar_digest"],
            }
        )
        manifest["segments"].append(second_segment)
        manifest["upload"]["receipts"].append(copy.deepcopy(second_receipt["runtime_receipt"]))
        completion_request["capture_manifest"] = protocol.runtime.seal(manifest)
        completion_request["segment_receipts"] = [second_receipt, first_receipt]
        completion_request = protocol.seal(completion_request)

        completion_receipt = load("completion-receipt.json")
        completion_receipt["request_digest"] = completion_request["request_digest"]
        completion_receipt["processing_job"]["inputs"]["capture_manifest_digest"] = completion_request[
            "capture_manifest"
        ]["manifest_digest"]
        completion_receipt["processing_job"] = protocol.runtime.seal(completion_receipt["processing_job"])
        completion_receipt["local_cleanup"]["manifest_digest"] = completion_request["capture_manifest"][
            "manifest_digest"
        ]
        completion_receipt["local_cleanup"]["segment_receipt_digests"] = [
            second_receipt["segment_receipt_digest"],
            first_receipt["segment_receipt_digest"],
        ]
        completion_receipt = protocol.seal(completion_receipt)

        protocol.validate_bundle(
            load("build-identity.json"),
            load("capture-scope.json"),
            [
                (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
            ],
            [(first_intent, first_receipt), (second_intent, second_receipt)],
            [(load("diagnostic-upload-request.json"), load("diagnostic-upload-receipt.json"))],
            completion_request,
            completion_receipt,
        )

    def test_completed_resume_credential_can_delete_without_upload_capability(self) -> None:
        deletion_request = load("deletion-request.json")
        tombstone = load("deletion-tombstone.json")
        deletion_request["credential_id"] = load("completed-resume-receipt.json")["credential"]["credential_id"]
        deletion_request = protocol.seal(deletion_request)
        tombstone["deletion_request_digest"] = deletion_request["request_digest"]
        tombstone["credential"]["credential_id"] = deletion_request["credential_id"]
        tombstone = protocol.seal(tombstone)
        protocol.validate_bundle(
            load("build-identity.json"),
            load("capture-scope.json"),
            [
                (load("launch-exchange-request.json"), load("launch-exchange-receipt.json")),
                (load("receiving-resume-request.json"), load("receiving-resume-receipt.json")),
                (load("completed-resume-request.json"), load("completed-resume-receipt.json")),
            ],
            [(load("segment-upload-intent.json"), load("segment-upload-receipt.json"))],
            [(load("diagnostic-upload-request.json"), load("diagnostic-upload-receipt.json"))],
            load("completion-request.json"),
            load("completion-receipt.json"),
            (deletion_request, tombstone),
        )

    def test_transport_configuration_is_transitively_bound_to_build_scope(self) -> None:
        build = load("build-identity.json")
        expected = protocol.digest(
            {
                "backend_origin": "https://qa.tacua.example",
                "transport_policy_version": "tacua.sdk-transport@1.0.0",
            }
        )
        self.assertEqual(build["transport_configuration_digest"], expected)

    def test_completion_receipt_is_cleanup_authority_not_agent_authority(self) -> None:
        request = load("completion-request.json")
        receipt = load("completion-receipt.json")
        protocol.validate_completion_pair(request, receipt)
        self.assertEqual(receipt["processing_job"]["status"], "queued")
        self.assertEqual(receipt["credential"]["state"], "completion_replay_or_delete_only")
        self.assertEqual(receipt["local_cleanup"]["state"], "authorized_after_durable_receipt")
        self.assertNotIn("agent_authorization", protocol.canonical_json(receipt))

    def test_deletion_tombstone_is_only_replay_and_keychain_cleanup_authority(self) -> None:
        request = load("deletion-request.json")
        tombstone = load("deletion-tombstone.json")
        protocol.validate_deletion_pair(request, tombstone)
        self.assertEqual(tombstone["credential"]["state"], "deletion_replay_only")
        self.assertEqual(
            tombstone["credential"]["verifier_retained_until"],
            tombstone["tombstone_expires_at"],
        )
        self.assertEqual(tombstone["session_access"]["uploads"], "revoked")
        self.assertEqual(
            tombstone["local_credential_cleanup"],
            "authorized_after_durable_tombstone",
        )

    def test_http_mapping_uses_private_transport_digest_header(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Tacua-Content-Digest", readme)
        self.assertNotIn("`Content-Length`, and `Content-Digest`", readme)

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
        elif mode == "diagnostic_pair":
            protocol.validate_diagnostic_pair(load("diagnostic-upload-request.json"), value)
        elif mode == "completed_resume_pair":
            protocol.validate_launch_pair(load("completed-resume-request.json"), value)
        elif mode == "completion_pair":
            protocol.validate_completion_pair(load("completion-request.json"), value)
        elif mode == "deletion_pair":
            protocol.validate_deletion_pair(load("deletion-request.json"), value)
        elif mode == "completion_replay":
            protocol.validate_idempotent_replay(
                load("completion-request.json"),
                load("completion-receipt.json"),
                value,
                load("completion-receipt.json"),
            )
        elif mode == "launch_response_replay":
            request = load("launch-exchange-request.json")
            protocol.validate_idempotent_replay(
                request,
                load("launch-exchange-receipt.json"),
                copy.deepcopy(request),
                value,
            )
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
