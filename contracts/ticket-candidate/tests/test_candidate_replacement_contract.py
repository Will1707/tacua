# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from candidate_replacement_contract import (  # noqa: E402
    validate_replacement_request,
    validate_replacement_response,
)
from ticket_candidate_contract import (  # noqa: E402
    ContractError,
    canonical_json_artifact,
    load_json,
    seal,
)


def _source() -> dict:
    return load_json(ROOT / "fixtures" / "positive" / "version-1-draft.json")


def _binding(candidate: dict) -> dict:
    return {
        "candidate_id": candidate["candidate_id"],
        "candidate_version": candidate["candidate_version"],
        "candidate_digest": candidate["candidate_digest"],
        "candidate_content_digest": candidate["candidate_content_digest"],
        "evidence_manifest_digest": candidate["evidence_manifest"]["manifest_digest"],
    }


def _split_bundle() -> tuple[dict, dict]:
    source = _source()
    occurred_at = "2026-07-22T18:00:00Z"
    reason = "The narration identifies two independently actionable issues."
    candidates: list[dict] = []
    for suffix, title in (("copy", "Copy issue"), ("highlight", "Highlight issue")):
        candidate = copy.deepcopy(source)
        candidate["candidate_id"] = f"candidate_split_{suffix}"
        candidate["candidate_version"] = 1
        candidate["previous_candidate_digest"] = None
        candidate["state"] = "draft"
        candidate["candidate_created_at"] = occurred_at
        candidate["version_created_at"] = occurred_at
        candidate["lineage"] = {
            "operation": "split",
            "parents": [
                {
                    "candidate_id": source["candidate_id"],
                    "candidate_version": source["candidate_version"],
                    "candidate_digest": source["candidate_digest"],
                }
            ],
        }
        candidate["transition"] = {
            "from_state": None,
            "to_state": "draft",
            "actor": {"actor_type": "human", "actor_id": "reviewer_owner"},
            "occurred_at": occurred_at,
            "reason": reason,
        }
        candidate["content"]["title"] = title
        candidate["review"] = {
            "status": "in_review",
            "reviewer_action_required": True,
            "last_human_actor_id": "reviewer_owner",
            "last_reviewed_at": occurred_at,
            "notes": [],
        }
        candidate["approval"] = None
        candidate["rejection"] = None
        candidates.append(seal(candidate))

    request = {
        "operation": "split",
        "actor_id": "reviewer_owner",
        "reason": reason,
        "sources": [_binding(source)],
        "results": [
            {"candidate_id": candidate["candidate_id"], "content": candidate["content"]}
            for candidate in candidates
        ],
    }
    response = {
        "operation": {
            "operation_id": "replacement_split_001",
            "operation": "split",
            "actor_id": "reviewer_owner",
            "occurred_at": occurred_at,
            "sources": copy.deepcopy(request["sources"]),
            "results": [_binding(candidate) for candidate in candidates],
        },
        "candidates": candidates,
    }
    return request, response


class CandidateReplacementContractTests(unittest.TestCase):
    def test_valid_split_request_and_committed_response(self) -> None:
        request, response = _split_bundle()
        validate_replacement_request(request)
        validate_replacement_response(response, request=request)

    def test_request_cardinality_identity_and_content_fail_closed(self) -> None:
        request, _ = _split_bundle()
        cases: list[tuple[str, dict, str]] = []

        invalid = copy.deepcopy(request)
        invalid["results"] = invalid["results"][:1]
        cases.append(("cardinality", invalid, "SCHEMA_MIN_ITEMS"))

        invalid = copy.deepcopy(request)
        invalid["results"][0]["candidate_id"] = invalid["sources"][0]["candidate_id"]
        cases.append(("source-result collision", invalid, "SOURCE_RESULT_ID_COLLISION"))

        invalid = copy.deepcopy(request)
        invalid["results"][1]["content"] = copy.deepcopy(invalid["results"][0]["content"])
        cases.append(("duplicate content", invalid, "DUPLICATE_RESULT_CONTENT"))

        invalid = copy.deepcopy(request)
        invalid["reason"] = "Bearer this-is-a-synthetic-secret-token-value"
        cases.append(("credential-like value", invalid, "SECRET_VALUE_DETECTED"))

        for label, value, code in cases:
            with self.subTest(label=label):
                with self.assertRaises(ContractError) as raised:
                    validate_replacement_request(value)
                self.assertEqual(code, raised.exception.code)

    def test_response_binds_order_lineage_actor_time_evidence_and_content(self) -> None:
        request, response = _split_bundle()
        mutations: list[tuple[str, dict, str]] = []

        invalid = copy.deepcopy(response)
        invalid["candidates"].reverse()
        mutations.append(("result order", invalid, "RESULT_CANDIDATE_MISMATCH"))

        invalid = copy.deepcopy(response)
        invalid["operation"]["results"][0]["candidate_digest"] = "sha256:" + "f" * 64
        mutations.append(("binding", invalid, "RESULT_BINDING_MISMATCH"))

        invalid = copy.deepcopy(response)
        invalid["candidates"][0]["lineage"]["parents"] = []
        invalid["candidates"][0] = seal(invalid["candidates"][0])
        mutations.append(("lineage", invalid, "LINEAGE_PARENT_MISMATCH"))

        invalid = copy.deepcopy(response)
        invalid["candidates"][0]["content"]["title"] = "Changed after confirmation"
        invalid["candidates"][0] = seal(invalid["candidates"][0])
        invalid["operation"]["results"][0] = _binding(invalid["candidates"][0])
        mutations.append(("request content", invalid, "REQUEST_RESPONSE_CONTENT_MISMATCH"))

        invalid = copy.deepcopy(response)
        invalid["candidates"][0]["transition"]["reason"] = "Server substituted the reason."
        invalid["candidates"][0] = seal(invalid["candidates"][0])
        invalid["operation"]["results"][0] = _binding(invalid["candidates"][0])
        mutations.append(("request reason", invalid, "REQUEST_RESPONSE_BINDING_MISMATCH"))

        for label, value, code in mutations:
            with self.subTest(label=label):
                with self.assertRaises(ContractError) as raised:
                    validate_replacement_response(value, request=request)
                self.assertEqual(code, raised.exception.code)

    def test_merge_requires_two_to_sixteen_distinct_sources(self) -> None:
        split_request, split_response = _split_bundle()
        first_source = split_request["sources"][0]
        second_source = copy.deepcopy(first_source)
        second_source["candidate_id"] = "candidate_second_source"
        second_source["candidate_digest"] = "sha256:" + "b" * 64
        second_source["candidate_content_digest"] = "sha256:" + "c" * 64
        second_source["evidence_manifest_digest"] = "sha256:" + "d" * 64
        request = {
            **copy.deepcopy(split_request),
            "operation": "merge",
            "sources": [first_source, second_source],
            "results": [copy.deepcopy(split_request["results"][0])],
        }
        validate_replacement_request(request)

        request["sources"] = [first_source]
        with self.assertRaises(ContractError) as raised:
            validate_replacement_request(request)
        self.assertEqual("SCHEMA_MIN_ITEMS", raised.exception.code)

        self.assertEqual(2, len(split_response["candidates"]))

    def test_cli_validates_canonical_request_and_response_without_authority(self) -> None:
        request, response = _split_bundle()
        with tempfile.TemporaryDirectory() as directory:
            request_path = Path(directory) / "request.json"
            response_path = Path(directory) / "response.json"
            request_path.write_bytes(canonical_json_artifact(request))
            response_path.write_bytes(canonical_json_artifact(response))
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "ticket_candidate.py"),
                    "validate-replacement-response",
                    str(response_path),
                    "--request",
                    str(request_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        output = json.loads(result.stdout)
        self.assertEqual("split", output["operation"])
        self.assertFalse(output["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
