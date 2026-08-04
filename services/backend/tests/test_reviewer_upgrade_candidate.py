# SPDX-License-Identifier: Apache-2.0
"""Adversarial no-command tests for prepared reviewer release validation."""

from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services/backend/scripts"
sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_candidate as CANDIDATE  # noqa: E402


CANDIDATE_COMMIT = "1" * 40
INSTALLED_COMMIT = "2" * 40
REPOSITORY_IDENTITY = "Will1707/tacua"
REVIEWER_REF = "tacua-reviewer-web:qa-candidate"
REVIEWER_ID = "sha256:" + "3" * 64
INGRESS = "services/backend/ingress/haproxy.cfg"
UPGRADER = "services/backend/scripts/reviewer_upgrade_transaction.py"


class ReleaseFixture:
    def __init__(
        self,
        base: Path,
        *,
        local_build: bool = True,
        omitted_source: str | None = None,
    ) -> None:
        self.base = base.resolve()
        self.base.chmod(0o700)
        self.old_repository = self.base / "installed-source"
        old_ingress = self.old_repository / INGRESS
        old_ingress.parent.mkdir(parents=True, mode=0o700)
        old_ingress.write_bytes(b"global\n  daemon\n")
        old_ingress.chmod(0o600)

        self.source_document: dict[str, object] = {
            "configs": {
                "tacua_loopback_ingress": {"file": str(old_ingress)}
            },
            "networks": {"default": {"internal": True}},
            "services": {
                "backend": {
                    "environment": ["TACUA_MODE=serve", "TACUA_PORT=8080"],
                    "image": "tacua-backend:installed",
                },
                "reviewer": {
                    "environment": {"TACUA_REVIEW": "true"},
                    "image": "tacua-reviewer-web:installed",
                },
            },
        }
        if local_build:
            for service, dockerfile in (
                ("backend", "services/backend/Dockerfile"),
                ("reviewer", "services/reviewer-web/Dockerfile"),
            ):
                self.source_document["services"][service]["build"] = {
                    "context": str(self.old_repository),
                    "dockerfile": dockerfile,
                }
        self.source_compose = self.base / "sealed-source-compose.json"
        self.source_compose.write_bytes(
            CANDIDATE.canonical_json(self.source_document)
        )
        self.source_compose.chmod(CANDIDATE.SOURCE_COMPOSE_MODE)

        self.tools_directory = self.base / "tools"
        self.tools_directory.mkdir(mode=0o700)
        self.tool_paths: dict[str, Path] = {}
        for name in sorted(CANDIDATE._TOOLS):
            path = self.tools_directory / name
            path.write_bytes(f"#!/bin/sh\n# {name}\n".encode("ascii"))
            path.chmod(0o500)
            self.tool_paths[name] = path

        self.source_payloads = {
            relative: f"fixture:{relative}\n".encode("ascii")
            for relative in CANDIDATE.REQUIRED_RUNTIME_FILES
            if relative != omitted_source
        }
        if INGRESS in self.source_payloads:
            self.source_payloads[INGRESS] = b"global\n  daemon\n"
        self.file_records = [
            {
                "digest": CANDIDATE.digest(payload),
                "mode": CANDIDATE.SOURCE_FILE_MODE,
                "path": relative,
                "size": len(payload),
            }
            for relative, payload in sorted(self.source_payloads.items())
        ]
        generation = CANDIDATE.release_generation_id(
            candidate_commit=CANDIDATE_COMMIT,
            installed_commit=INSTALLED_COMMIT,
            repository_identity=REPOSITORY_IDENTITY,
            tree_digest_value=CANDIDATE.tree_digest(self.file_records),
            source_compose_path=str(self.source_compose),
            source_compose_digest=CANDIDATE.digest(
                self.source_compose.read_bytes()
            ),
            tools=self._tool_records(),
        )
        self.releases = self.base / CANDIDATE.RELEASES_DIRECTORY
        self.releases.mkdir(mode=CANDIDATE.PRIVATE_DIRECTORY_MODE)
        self.release = self.releases / generation
        self.release.mkdir(mode=0o700)
        self.repository = self.release / CANDIDATE.SOURCE_DIRECTORY
        self.repository.mkdir(mode=0o700)
        directories = {self.repository}
        for relative, payload in sorted(self.source_payloads.items()):
            target = self.repository / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            cursor = target.parent
            while cursor != self.repository:
                directories.add(cursor)
                cursor = cursor.parent
            target.write_bytes(payload)
            target.chmod(CANDIDATE.SOURCE_FILE_MODE)
        for directory in sorted(
            directories, key=lambda item: len(item.parts), reverse=True
        ):
            directory.chmod(CANDIDATE.SOURCE_DIRECTORY_MODE)

        closure_paths = [entry["path"] for entry in self.file_records]
        self.manifest = {
            "candidate_commit": CANDIDATE_COMMIT,
            "contract_version": CANDIDATE.SOURCE_MANIFEST_CONTRACT,
            "files": deepcopy(self.file_records),
            "manifest_digest": "",
            "repository_identity": REPOSITORY_IDENTITY,
            "runtime_closure": {
                "closure_digest": CANDIDATE.closure_digest(
                    self.file_records, closure_paths
                ),
                "files": closure_paths,
            },
            "tree_digest": CANDIDATE.tree_digest(self.file_records),
        }
        self.manifest["manifest_digest"] = CANDIDATE.document_digest(
            self.manifest, "manifest_digest"
        )
        self.manifest_path = self.release / CANDIDATE.SOURCE_MANIFEST_FILE
        self.manifest_path.write_bytes(CANDIDATE.canonical_json(self.manifest))
        self.manifest_path.chmod(CANDIDATE.MANIFEST_MODE)

        self.candidate_document = deepcopy(self.source_document)
        self.candidate_document["configs"]["tacua_loopback_ingress"][
            "file"
        ] = str(self.repository / INGRESS)
        self.candidate_document["services"]["reviewer"]["image"] = REVIEWER_REF
        if local_build:
            for service in ("backend", "reviewer"):
                self.candidate_document["services"][service]["build"][
                    "context"
                ] = str(self.repository)
        self.candidate_path = self.release / CANDIDATE.CANDIDATE_COMPOSE_FILE
        self.candidate_path.write_bytes(
            CANDIDATE.canonical_json(self.candidate_document)
        )
        self.candidate_path.chmod(CANDIDATE.CANDIDATE_COMPOSE_MODE)

        root_metadata = self.release.lstat()
        self.receipt = {
            "candidate_commit": CANDIDATE_COMMIT,
            "candidate_compose": {
                "digest": CANDIDATE.digest(self.candidate_path.read_bytes()),
                "mode": CANDIDATE.CANDIDATE_COMPOSE_MODE,
                "path": CANDIDATE.CANDIDATE_COMPOSE_FILE,
            },
            "contract_version": CANDIDATE.PREPARATION_RECEIPT_CONTRACT,
            "generation_id": generation,
            "installed_commit": INSTALLED_COMMIT,
            "receipt_digest": "",
            "release_binding": {
                "device": root_metadata.st_dev,
                "inode": root_metadata.st_ino,
                "mode": CANDIDATE.RELEASE_MODE,
            },
            "repository_identity": REPOSITORY_IDENTITY,
            "reviewer_image": {"id": REVIEWER_ID, "ref": REVIEWER_REF},
            "source_compose": {
                "digest": CANDIDATE.digest(self.source_compose.read_bytes()),
                "mode": CANDIDATE.SOURCE_COMPOSE_MODE,
                "path": str(self.source_compose),
            },
            "source_manifest_digest": self.manifest["manifest_digest"],
            "status": "verified",
            "tools": self._tool_records(),
            "verification": {
                "attempt_id": "attempt-000001",
                "commands_digest": "sha256:" + "4" * 64,
                "status": "verified",
            },
        }
        self._seal_receipt()
        self.receipt_path = self.release / CANDIDATE.PREPARATION_RECEIPT_FILE
        self.receipt_path.write_bytes(CANDIDATE.canonical_json(self.receipt))
        self.receipt_path.chmod(CANDIDATE.RECEIPT_MODE)
        self.release.chmod(CANDIDATE.RELEASE_MODE)

    def _tool_records(self) -> dict[str, dict[str, object]]:
        records: dict[str, dict[str, object]] = {}
        for name, path in self.tool_paths.items():
            metadata = path.lstat()
            records[name] = {
                "device": metadata.st_dev,
                "digest": CANDIDATE.digest(path.read_bytes()),
                "inode": metadata.st_ino,
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": str(path),
                "uid": metadata.st_uid,
            }
        return records

    def _seal_receipt(self) -> None:
        self.receipt["receipt_digest"] = CANDIDATE.document_digest(
            self.receipt, "receipt_digest"
        )

    def write_manifest(self, *, seal: bool = True, canonical: bool = True) -> None:
        if seal:
            self.manifest["manifest_digest"] = CANDIDATE.document_digest(
                self.manifest, "manifest_digest"
            )
        self.manifest_path.chmod(0o600)
        payload = CANDIDATE.canonical_json(self.manifest)
        self.manifest_path.write_bytes(payload if canonical else payload + b"\n")
        self.manifest_path.chmod(CANDIDATE.MANIFEST_MODE)

    def write_receipt(self, *, seal: bool = True, canonical: bool = True) -> None:
        if seal:
            self._seal_receipt()
        self.receipt_path.chmod(0o600)
        payload = CANDIDATE.canonical_json(self.receipt)
        self.receipt_path.write_bytes(payload if canonical else payload + b"\n")
        self.receipt_path.chmod(CANDIDATE.RECEIPT_MODE)

    def write_candidate(self, document: dict[str, object]) -> None:
        self.candidate_document = document
        self.candidate_path.write_bytes(CANDIDATE.canonical_json(document))
        self.receipt["candidate_compose"]["digest"] = CANDIDATE.digest(
            self.candidate_path.read_bytes()
        )
        self.write_receipt()

    def make_root_writable(self) -> None:
        self.release.chmod(0o700)

    def seal_root(self) -> None:
        self.release.chmod(CANDIDATE.RELEASE_MODE)


class ReviewerUpgradeCandidateTests(unittest.TestCase):
    def fixture(
        self,
        *,
        local_build: bool = True,
        omitted_source: str | None = None,
    ) -> ReleaseFixture:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return ReleaseFixture(
            Path(temporary.name),
            local_build=local_build,
            omitted_source=omitted_source,
        )

    def assert_invalid(self, fixture: ReleaseFixture, **kwargs: object) -> None:
        with self.assertRaises(CANDIDATE.CandidateError) as caught:
            CANDIDATE.load_prepared_release(fixture.release, **kwargs)
        self.assertEqual(caught.exception.code, "REVIEWER_UPGRADE_CANDIDATE_INVALID")
        self.assertEqual(str(caught.exception), "REVIEWER_UPGRADE_CANDIDATE_INVALID")
        self.assertNotIn(str(fixture.base), str(caught.exception))

    def test_loads_exact_local_build_release_without_commands(self) -> None:
        fixture = self.fixture()
        with mock.patch.object(
            subprocess, "run", side_effect=AssertionError("command invoked")
        ) as run:
            prepared = CANDIDATE.load_prepared_release(
                fixture.release,
                expected_commit=CANDIDATE_COMMIT,
                expected_repository_identity=REPOSITORY_IDENTITY,
            )
        run.assert_not_called()
        self.assertEqual(prepared.release_root, fixture.release)
        self.assertEqual(prepared.repository, fixture.repository)
        self.assertEqual(prepared.candidate_compose, fixture.candidate_path)
        self.assertEqual(prepared.receipt, fixture.receipt)
        self.assertEqual(prepared.source_manifest, fixture.manifest)

    def test_loads_exact_production_no_build_release(self) -> None:
        fixture = self.fixture(local_build=False)
        prepared = CANDIDATE.load_prepared_release(fixture.release)
        for service in ("backend", "reviewer"):
            self.assertNotIn(
                "build", fixture.candidate_document["services"][service]
            )
        self.assertEqual(prepared.repository, fixture.repository)

    def test_expected_commit_and_repository_are_strict(self) -> None:
        fixture = self.fixture()
        for kwargs in (
            {"expected_commit": "f" * 40},
            {"expected_repository_identity": "Other/project"},
            {"expected_commit": "F" * 40},
            {"expected_repository_identity": "https://example.invalid/repo"},
        ):
            with self.subTest(kwargs=kwargs):
                self.assert_invalid(fixture, **kwargs)

    def test_exact_release_layout_and_directory_modes(self) -> None:
        cases = (
            "extra",
            "release_mode",
            "releases_mode",
            "preparations_parent_mode",
            "source_mode",
        )
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "extra":
                    fixture.make_root_writable()
                    (fixture.release / "unexpected").write_bytes(b"x")
                    fixture.seal_root()
                elif case == "release_mode":
                    fixture.release.chmod(0o700)
                elif case == "releases_mode":
                    fixture.releases.chmod(0o755)
                elif case == "preparations_parent_mode":
                    fixture.base.chmod(0o755)
                else:
                    fixture.repository.chmod(0o755)
                self.assert_invalid(fixture)

    def test_required_runtime_file_cannot_be_omitted_from_an_otherwise_exact_tree(self) -> None:
        omitted = "services/backend/scripts/reviewer_upgrade_bootstrap.py"
        self.assertIn(omitted, CANDIDATE.REQUIRED_RUNTIME_FILES)
        fixture = self.fixture(omitted_source=omitted)
        self.assertNotIn(omitted, fixture.manifest["runtime_closure"]["files"])
        self.assert_invalid(fixture)

    def test_exact_evidence_and_source_modes(self) -> None:
        cases = (
            ("manifest", 0o600),
            ("receipt", 0o600),
            ("candidate", 0o400),
            ("source_compose", 0o600),
            ("source_file", 0o644),
            ("source_directory", 0o755),
            ("tool", 0o522),
        )
        for case, mode in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                paths = {
                    "manifest": fixture.manifest_path,
                    "receipt": fixture.receipt_path,
                    "candidate": fixture.candidate_path,
                    "source_compose": fixture.source_compose,
                    "source_file": fixture.repository / INGRESS,
                    "source_directory": fixture.repository / "services/backend",
                    "tool": fixture.tool_paths["git"],
                }
                paths[case].chmod(mode)
                self.assert_invalid(fixture)

    def test_manifest_requires_exact_shape_canonical_json_and_self_digest(self) -> None:
        cases = ("extra_key", "noncanonical", "self_digest", "contract")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "extra_key":
                    fixture.manifest["extra"] = True
                    fixture.write_manifest()
                elif case == "noncanonical":
                    fixture.write_manifest(canonical=False)
                elif case == "self_digest":
                    fixture.manifest["manifest_digest"] = "sha256:" + "0" * 64
                    fixture.write_manifest(seal=False)
                else:
                    fixture.manifest["contract_version"] = "wrong"
                    fixture.write_manifest()
                self.assert_invalid(fixture)

    def test_manifest_binds_order_paths_modes_sizes_digests_and_tree(self) -> None:
        cases = ("order", "path", "mode", "size", "digest", "tree")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "order":
                    fixture.manifest["files"].reverse()
                elif case == "path":
                    fixture.manifest["files"][0]["path"] = "../escape"
                elif case == "mode":
                    fixture.manifest["files"][0]["mode"] = 0o644
                elif case == "size":
                    fixture.manifest["files"][0]["size"] += 1
                elif case == "digest":
                    fixture.manifest["files"][0]["digest"] = "sha256:" + "0" * 64
                else:
                    fixture.manifest["tree_digest"] = "sha256:" + "0" * 64
                fixture.write_manifest()
                self.assert_invalid(fixture)

    def test_runtime_closure_is_complete_sorted_and_digest_bound(self) -> None:
        cases = ("missing", "unknown", "order", "digest", "extra_key")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                closure = fixture.manifest["runtime_closure"]
                if case == "missing":
                    closure["files"] = closure["files"][:-1]
                    closure["closure_digest"] = CANDIDATE.closure_digest(
                        fixture.manifest["files"], closure["files"]
                    )
                elif case == "unknown":
                    closure["files"][0] = "missing.py"
                elif case == "order":
                    closure["files"].reverse()
                elif case == "digest":
                    closure["closure_digest"] = "sha256:" + "0" * 64
                else:
                    closure["extra"] = False
                fixture.write_manifest()
                self.assert_invalid(fixture)

    def test_source_tree_rejects_missing_tamper_extra_empty_directory_and_special(self) -> None:
        cases = ("missing", "tamper", "extra", "empty_directory", "fifo")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "missing":
                    target = fixture.repository / UPGRADER
                    target.parent.chmod(0o755)
                    target.unlink()
                    target.parent.chmod(CANDIDATE.SOURCE_DIRECTORY_MODE)
                elif case == "tamper":
                    target = fixture.repository / INGRESS
                    target.chmod(0o644)
                    target.write_bytes(b"changed but retained length")
                    target.chmod(CANDIDATE.SOURCE_FILE_MODE)
                else:
                    fixture.repository.chmod(0o755)
                    target = fixture.repository / {
                        "extra": "extra.txt",
                        "empty_directory": "empty",
                        "fifo": "pipe",
                    }[case]
                    if case == "extra":
                        target.write_bytes(b"extra")
                        target.chmod(CANDIDATE.SOURCE_FILE_MODE)
                    elif case == "empty_directory":
                        target.mkdir(mode=CANDIDATE.SOURCE_DIRECTORY_MODE)
                    else:
                        os.mkfifo(target, CANDIDATE.SOURCE_FILE_MODE)
                    fixture.repository.chmod(CANDIDATE.SOURCE_DIRECTORY_MODE)
                self.assert_invalid(fixture)

    def test_links_and_hardlinks_are_rejected(self) -> None:
        cases = (
            "manifest_symlink",
            "receipt_hardlink",
            "candidate_hardlink",
            "source_symlink",
            "source_hardlink",
            "source_compose_symlink",
            "tool_symlink",
            "tool_hardlink",
        )
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "manifest_symlink":
                    fixture.make_root_writable()
                    fixture.manifest_path.unlink()
                    fixture.manifest_path.symlink_to(fixture.base / "missing")
                    fixture.seal_root()
                elif case == "receipt_hardlink":
                    fixture.make_root_writable()
                    os.link(fixture.receipt_path, fixture.base / "receipt-hardlink")
                    fixture.seal_root()
                elif case == "candidate_hardlink":
                    fixture.make_root_writable()
                    outside = fixture.base / "candidate-link-source"
                    outside.write_bytes(fixture.candidate_path.read_bytes())
                    outside.chmod(CANDIDATE.CANDIDATE_COMPOSE_MODE)
                    fixture.candidate_path.unlink()
                    os.link(outside, fixture.candidate_path)
                    fixture.seal_root()
                elif case == "source_symlink":
                    target = fixture.repository / INGRESS
                    target.parent.chmod(0o755)
                    target.unlink()
                    target.symlink_to(fixture.base / "missing")
                    target.parent.chmod(CANDIDATE.SOURCE_DIRECTORY_MODE)
                elif case == "source_hardlink":
                    os.link(fixture.repository / INGRESS, fixture.base / "source-hardlink")
                elif case == "source_compose_symlink":
                    fixture.source_compose.unlink()
                    fixture.source_compose.symlink_to(fixture.base / "missing")
                elif case == "tool_symlink":
                    target = fixture.tool_paths["git"]
                    target.unlink()
                    target.symlink_to(fixture.base / "missing")
                else:
                    os.link(fixture.tool_paths["git"], fixture.base / "git-hardlink")
                self.assert_invalid(fixture)

    def test_receipt_requires_exact_shape_canonical_json_and_bindings(self) -> None:
        cases = (
            "extra_key",
            "noncanonical",
            "self_digest",
            "status",
            "generation",
            "installed",
            "release_inode",
            "manifest_digest",
            "candidate_path",
            "image_ref",
            "image_id",
            "tool_set",
            "verification",
        )
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "extra_key":
                    fixture.receipt["extra"] = True
                elif case == "noncanonical":
                    fixture.write_receipt(canonical=False)
                    self.assert_invalid(fixture)
                    continue
                elif case == "self_digest":
                    fixture.receipt["receipt_digest"] = "sha256:" + "0" * 64
                    fixture.write_receipt(seal=False)
                    self.assert_invalid(fixture)
                    continue
                elif case == "status":
                    fixture.receipt["status"] = "pending"
                elif case == "generation":
                    fixture.receipt["generation_id"] = "0" * 64
                elif case == "installed":
                    fixture.receipt["installed_commit"] = CANDIDATE_COMMIT
                elif case == "release_inode":
                    fixture.receipt["release_binding"]["inode"] += 1
                elif case == "manifest_digest":
                    fixture.receipt["source_manifest_digest"] = "sha256:" + "0" * 64
                elif case == "candidate_path":
                    fixture.receipt["candidate_compose"]["path"] = "./candidate-compose.json"
                elif case == "image_ref":
                    fixture.receipt["reviewer_image"]["ref"] = "tacua-reviewer-web:latest"
                elif case == "image_id":
                    fixture.receipt["reviewer_image"]["id"] = "image-id"
                elif case == "tool_set":
                    fixture.receipt["tools"].pop("git")
                else:
                    fixture.receipt["verification"]["status"] = "succeeded"
                fixture.write_receipt()
                self.assert_invalid(fixture)

    def test_source_and_candidate_compose_are_digest_mode_and_path_bound(self) -> None:
        cases = ("source_digest", "source_path", "candidate_digest", "candidate_mode")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "source_digest":
                    fixture.receipt["source_compose"]["digest"] = "sha256:" + "0" * 64
                elif case == "source_path":
                    fixture.receipt["source_compose"]["path"] = "relative.json"
                elif case == "candidate_digest":
                    fixture.receipt["candidate_compose"]["digest"] = "sha256:" + "0" * 64
                else:
                    fixture.receipt["candidate_compose"]["mode"] = 0o400
                fixture.write_receipt()
                self.assert_invalid(fixture)

    def test_source_compose_candidate_compose_and_tool_content_tamper_is_rejected(self) -> None:
        cases = ("source", "candidate", "tool", "authority_ingress")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "source":
                    fixture.source_compose.chmod(0o600)
                    fixture.source_compose.write_bytes(b'{"tampered":true}')
                    fixture.source_compose.chmod(CANDIDATE.SOURCE_COMPOSE_MODE)
                elif case == "candidate":
                    fixture.candidate_path.write_bytes(b'{"tampered":true}')
                elif case == "tool":
                    target = fixture.tool_paths["python"]
                    target.chmod(0o700)
                    target.write_bytes(b"tampered\n")
                    target.chmod(0o500)
                else:
                    target = fixture.old_repository / INGRESS
                    target.write_bytes(b"tampered ingress\n")
                self.assert_invalid(fixture)

    def test_source_and_candidate_compose_require_canonical_json(self) -> None:
        cases = ("source", "candidate")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "source":
                    target = fixture.source_compose
                    target.chmod(0o600)
                    target.write_bytes(target.read_bytes() + b"\n")
                    target.chmod(CANDIDATE.SOURCE_COMPOSE_MODE)
                    fixture.receipt["source_compose"]["digest"] = CANDIDATE.digest(
                        target.read_bytes()
                    )
                else:
                    target = fixture.candidate_path
                    target.write_bytes(target.read_bytes() + b"\n")
                    fixture.receipt["candidate_compose"]["digest"] = CANDIDATE.digest(
                        target.read_bytes()
                    )
                fixture.write_receipt()
                self.assert_invalid(fixture)

    def test_compose_allows_only_exact_relocations_and_reviewer_image(self) -> None:
        cases = (
            "wrong_backend_context",
            "wrong_reviewer_context",
            "wrong_ingress",
            "other_delta",
            "image_mismatch",
            "build_removed",
        )
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                document = deepcopy(fixture.candidate_document)
                if case == "wrong_backend_context":
                    document["services"]["backend"]["build"]["context"] = str(
                        fixture.repository / "services"
                    )
                elif case == "wrong_reviewer_context":
                    document["services"]["reviewer"]["build"]["context"] = str(
                        fixture.old_repository
                    )
                elif case == "wrong_ingress":
                    document["configs"]["tacua_loopback_ingress"]["file"] = str(
                        fixture.repository / "wrong.cfg"
                    )
                elif case == "other_delta":
                    document["services"]["backend"]["image"] = "changed"
                elif case == "image_mismatch":
                    document["services"]["reviewer"]["image"] = "tacua-reviewer-web:other"
                else:
                    del document["services"]["backend"]["build"]
                fixture.write_candidate(document)
                self.assert_invalid(fixture)

    def test_source_compose_requires_consistent_old_repository_root(self) -> None:
        fixture = self.fixture()
        changed = deepcopy(fixture.source_document)
        changed["services"]["reviewer"]["build"]["context"] = str(
            fixture.base
        )
        fixture.source_compose.chmod(0o600)
        fixture.source_compose.write_bytes(CANDIDATE.canonical_json(changed))
        fixture.source_compose.chmod(CANDIDATE.SOURCE_COMPOSE_MODE)
        fixture.receipt["source_compose"]["digest"] = CANDIDATE.digest(
            fixture.source_compose.read_bytes()
        )
        fixture.write_receipt()
        self.assert_invalid(fixture)

    def _assert_mid_read_rebind_rejected(
        self, fixture: ReleaseFixture, target: Path
    ) -> None:
        original_read = os.read
        original_identity = (target.lstat().st_dev, target.lstat().st_ino)
        payload = target.read_bytes()
        mode = stat.S_IMODE(target.lstat().st_mode)
        replacement = fixture.base / f".{target.name}.replacement"
        replaced = False

        def rebind(descriptor: int, amount: int) -> bytes:
            nonlocal replaced
            block = original_read(descriptor, amount)
            metadata = os.fstat(descriptor)
            if not replaced and (metadata.st_dev, metadata.st_ino) == original_identity:
                replacement.write_bytes(payload)
                replacement.chmod(mode)
                if target.parent == fixture.release:
                    fixture.make_root_writable()
                os.replace(replacement, target)
                if target.parent == fixture.release:
                    fixture.seal_root()
                replaced = True
            return block

        with mock.patch.object(CANDIDATE.os, "read", side_effect=rebind):
            self.assert_invalid(fixture)
        self.assertTrue(replaced)

    def test_source_compose_rebind_during_read_is_rejected(self) -> None:
        fixture = self.fixture()
        self._assert_mid_read_rebind_rejected(fixture, fixture.source_compose)

    def test_tool_rebind_during_read_is_rejected(self) -> None:
        fixture = self.fixture()
        self._assert_mid_read_rebind_rejected(fixture, fixture.tool_paths["git"])

    def test_candidate_rebind_during_read_is_rejected(self) -> None:
        fixture = self.fixture()
        self._assert_mid_read_rebind_rejected(fixture, fixture.candidate_path)

    def test_release_replacement_during_validation_is_rejected(self) -> None:
        fixture = self.fixture()
        replacement = fixture.releases / ("f" * 64)
        shutil.copytree(fixture.release, replacement)
        replacement.chmod(CANDIDATE.RELEASE_MODE)
        original_validate = CANDIDATE._validate_receipt

        def replace_after_validation(*args: object, **kwargs: object):
            result = original_validate(*args, **kwargs)
            parked = fixture.releases / ("e" * 64)
            os.rename(fixture.release, parked)
            os.rename(replacement, fixture.release)
            return result

        with mock.patch.object(
            CANDIDATE, "_validate_receipt", side_effect=replace_after_validation
        ):
            self.assert_invalid(fixture)

    def test_wrong_json_scalar_types_remain_content_free_failures(self) -> None:
        for case in ("manifest_digest", "receipt_digest", "tool_device"):
            with self.subTest(case=case):
                fixture = self.fixture()
                if case == "manifest_digest":
                    fixture.manifest["manifest_digest"] = 7
                    fixture.write_manifest(seal=False)
                elif case == "receipt_digest":
                    fixture.receipt["receipt_digest"] = 7
                    fixture.write_receipt(seal=False)
                else:
                    fixture.receipt["tools"]["python"]["device"] = 1.0
                    fixture.write_receipt()
                self.assert_invalid(fixture)

    def test_error_is_content_free_even_for_os_failures(self) -> None:
        fixture = self.fixture()
        fixture.make_root_writable()
        fixture.receipt_path.unlink()
        fixture.seal_root()
        self.assert_invalid(fixture)


if __name__ == "__main__":
    unittest.main()
