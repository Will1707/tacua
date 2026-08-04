#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure validation for content-addressed reviewer upgrade candidates.

The loader intentionally performs no subprocess, network, Docker, or daemon
work.  A prepared release is usable only when its immutable source tree,
Compose transition, image proof, tool bindings, and verification receipt all
still match the evidence published by the offline producer.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping, NoReturn
import unicodedata


SOURCE_MANIFEST_CONTRACT = "tacua.reviewer-upgrade-source-manifest@1.0.0"
PREPARATION_RECEIPT_CONTRACT = (
    "tacua.reviewer-upgrade-candidate-preparation@1.0.0"
)
RELEASE_GENERATION_CONTRACT = "tacua.reviewer-upgrade-release-generation@1.0.0"
SOURCE_DIRECTORY = "source"
SOURCE_MANIFEST_FILE = "source-manifest.json"
CANDIDATE_COMPOSE_FILE = "candidate-compose.json"
PREPARATION_RECEIPT_FILE = "preparation-receipt.json"

RELEASES_DIRECTORY = "releases"
SOURCE_FILE_MODE = 0o444
SOURCE_EXECUTABLE_MODE = 0o555
SOURCE_DIRECTORY_MODE = 0o555
RELEASE_MODE = 0o500
PRIVATE_DIRECTORY_MODE = 0o700
MANIFEST_MODE = 0o400
RECEIPT_MODE = 0o400
CANDIDATE_COMPOSE_MODE = 0o600
SOURCE_COMPOSE_MODE = 0o400

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_COMPOSE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_FILES = 10_000
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
MAX_JSON_COLLECTION = 20_000
MAX_JSON_STRING_BYTES = 2 * 1024 * 1024
MAX_SAFE_INTEGER = (1 << 63) - 1

_ERROR = "REVIEWER_UPGRADE_CANDIDATE_INVALID"
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_GENERATION = re.compile(r"^[a-f0-9]{64}$")
_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_REPOSITORY_IDENTITY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$"
)
_IMAGE_REF = re.compile(
    r"^tacua-reviewer-web:[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9])?$"
)
_ATTEMPT_ID = re.compile(r"^attempt-[0-9]{6}$")
_TOOLS = frozenset({"bash", "docker", "git", "node", "npm_cli", "python"})
_INGRESS_SUFFIX = PurePosixPath("services/backend/ingress/haproxy.cfg")

# The stable systemd resumer imports this closure after the mutable checkout is
# no longer authoritative.  Requiring the exact entry points and their dynamic
# contract/schema dependencies turns an accidental deletion into a preparation
# failure, rather than a reboot-only import or validation failure.
REQUIRED_RUNTIME_FILES = frozenset(
    {
        "services/backend/ingress/haproxy.cfg",
        "services/backend/scripts/reconcile_compose_deployment.py",
        "services/backend/scripts/verify_tailnet_private_pilot.py",
        "services/backend/scripts/reviewer_upgrade_backup.py",
        "services/backend/scripts/reviewer_upgrade_backup_docker.py",
        "services/backend/scripts/reviewer_upgrade_bootstrap.py",
        "services/backend/scripts/reviewer_upgrade_candidate.py",
        "services/backend/scripts/reviewer_upgrade_finalize.py",
        "services/backend/scripts/reviewer_upgrade_journal.py",
        "services/backend/scripts/reviewer_upgrade_launcher.py",
        "services/backend/scripts/reviewer_upgrade_manager.py",
        "services/backend/scripts/reviewer_upgrade_systemd.py",
        "services/backend/scripts/reviewer_upgrade_transaction.py",
        "services/backend/scripts/reviewer_upgrade_unit_artifacts.py",
        "services/backend/src/tacua_backend/__init__.py",
        "services/backend/src/tacua_backend/config.py",
        "services/backend/src/tacua_backend/contracts.py",
        "services/backend/src/tacua_backend/instance_lock.py",
        "services/backend/src/tacua_backend/operator_tool.py",
        "services/backend/systemd/tacua-reconcile-lock.service.in",
        "services/backend/systemd/tacua-reconcile.service.in",
        "services/backend/systemd/tacua-reconcile.timer",
        "services/backend/systemd/tacua-reviewer-upgrade-lock.service.in",
        "services/backend/systemd/tacua-reviewer-upgrade-resume.path.in",
        "services/backend/systemd/tacua-reviewer-upgrade-resume.service.in",
        "contracts/approved-handoff/src/handoff_contract.py",
        "contracts/approved-handoff/schemas/agent-trial.schema.json",
        "contracts/approved-handoff/schemas/approved-handoff.schema.json",
        "contracts/approved-handoff/schemas/build-identity.schema.json",
        "contracts/approved-handoff/schemas/evidence-item.schema.json",
        "contracts/approved-handoff/schemas/evidence-manifest.schema.json",
        "contracts/approved-handoff/schemas/execution-assertion.schema.json",
        "contracts/approved-handoff/schemas/execution-revocations.schema.json",
        "contracts/approved-handoff/schemas/registry-assertion.schema.json",
        "contracts/runtime/src/runtime_contract.py",
        "contracts/runtime/schemas/capture-upload-manifest.schema.json",
        "contracts/runtime/schemas/common.schema.json",
        "contracts/runtime/schemas/diagnostic-envelope.schema.json",
        "contracts/runtime/schemas/processing-job.schema.json",
        "contracts/runtime/schemas/ticket-candidate.schema.json",
        "contracts/sdk-backend-protocol/src/protocol_contract.py",
        "contracts/sdk-backend-protocol/schemas/build-identity.schema.json",
        "contracts/sdk-backend-protocol/schemas/capture-scope.schema.json",
        "contracts/sdk-backend-protocol/schemas/common.schema.json",
        "contracts/sdk-backend-protocol/schemas/completion-receipt.schema.json",
        "contracts/sdk-backend-protocol/schemas/completion-request.schema.json",
        "contracts/sdk-backend-protocol/schemas/deletion-request.schema.json",
        "contracts/sdk-backend-protocol/schemas/deletion-tombstone.schema.json",
        "contracts/sdk-backend-protocol/schemas/diagnostic-upload-receipt.schema.json",
        "contracts/sdk-backend-protocol/schemas/diagnostic-upload-request.schema.json",
        "contracts/sdk-backend-protocol/schemas/launch-exchange-receipt.schema.json",
        "contracts/sdk-backend-protocol/schemas/launch-exchange-request.schema.json",
        "contracts/sdk-backend-protocol/schemas/segment-upload-intent.schema.json",
        "contracts/sdk-backend-protocol/schemas/segment-upload-receipt.schema.json",
        "contracts/ticket-candidate/src/ticket_candidate_contract.py",
        "contracts/ticket-candidate/schemas/candidate-replacement-request.schema.json",
        "contracts/ticket-candidate/schemas/candidate-replacement-response.schema.json",
        "contracts/ticket-candidate/schemas/common.schema.json",
        "contracts/ticket-candidate/schemas/ticket-candidate.schema.json",
    }
)

_MANIFEST_KEYS = frozenset(
    {
        "contract_version",
        "manifest_digest",
        "candidate_commit",
        "repository_identity",
        "tree_digest",
        "files",
        "runtime_closure",
    }
)
_FILE_KEYS = frozenset({"path", "digest", "mode", "size"})
_CLOSURE_KEYS = frozenset({"closure_digest", "files"})
_RECEIPT_KEYS = frozenset(
    {
        "contract_version",
        "receipt_digest",
        "status",
        "generation_id",
        "candidate_commit",
        "installed_commit",
        "repository_identity",
        "release_binding",
        "source_manifest_digest",
        "source_compose",
        "candidate_compose",
        "reviewer_image",
        "tools",
        "verification",
    }
)
_RELEASE_BINDING_KEYS = frozenset({"device", "inode", "mode"})
_COMPOSE_RECORD_KEYS = frozenset({"digest", "path", "mode"})
_IMAGE_KEYS = frozenset({"ref", "id"})
_TOOL_KEYS = frozenset({"path", "digest", "device", "inode", "mode", "uid"})
_VERIFICATION_KEYS = frozenset({"attempt_id", "commands_digest", "status"})


class CandidateError(RuntimeError):
    """A stable, content-free prepared-release validation failure."""

    def __init__(self, code: str = _ERROR) -> None:
        super().__init__(code)
        self.code = code


def _fail() -> NoReturn:
    raise CandidateError(_ERROR)


@dataclass(frozen=True)
class PreparedRelease:
    """Validated paths and evidence for one retained reviewer release."""

    release_root: Path
    repository: Path
    candidate_compose: Path
    receipt: dict[str, Any]
    source_manifest: dict[str, Any]


def _bounded_copy(value: Any) -> Any:
    budget = [MAX_JSON_NODES]

    def visit(item: Any, depth: int) -> Any:
        if depth > MAX_JSON_DEPTH:
            _fail()
        budget[0] -= 1
        if budget[0] < 0:
            _fail()
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            if not -MAX_SAFE_INTEGER <= item <= MAX_SAFE_INTEGER:
                _fail()
            return item
        if type(item) is float:
            if not math.isfinite(item):
                _fail()
            return item
        if type(item) is str:
            try:
                encoded = item.encode("utf-8", "strict")
            except UnicodeError as error:
                raise CandidateError(_ERROR) from error
            if len(encoded) > MAX_JSON_STRING_BYTES:
                _fail()
            return item
        if type(item) is list:
            if len(item) > MAX_JSON_COLLECTION:
                _fail()
            return [visit(child, depth + 1) for child in item]
        if type(item) is dict:
            if len(item) > MAX_JSON_COLLECTION:
                _fail()
            copied: dict[str, Any] = {}
            for key, child in item.items():
                if type(key) is not str:
                    _fail()
                try:
                    encoded_key = key.encode("utf-8", "strict")
                except UnicodeError as error:
                    raise CandidateError(_ERROR) from error
                if len(encoded_key) > 512:
                    _fail()
                copied[key] = visit(child, depth + 1)
            return copied
        _fail()

    return visit(value, 0)


def canonical_json(value: Any) -> bytes:
    """Return the only accepted representation for prepared-release JSON."""

    try:
        return json.dumps(
            _bounded_copy(value),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except CandidateError:
        raise
    except (TypeError, ValueError, UnicodeError, OverflowError) as error:
        raise CandidateError(_ERROR) from error


def digest(payload: bytes) -> str:
    if type(payload) is not bytes:
        _fail()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def document_digest(document: Mapping[str, Any], field: str) -> str:
    if type(document) is not dict or type(field) is not str:
        _fail()
    subject = dict(document)
    subject.pop(field, None)
    return digest(canonical_json(subject))


def tree_digest(files: list[dict[str, Any]]) -> str:
    return digest(canonical_json(files))


def release_generation_id(
    *,
    candidate_commit: Any,
    installed_commit: Any,
    repository_identity: Any,
    tree_digest_value: Any,
    source_compose_path: Any,
    source_compose_digest: Any,
    tools: Any,
) -> str:
    """Bind a retained release to every pre-publication identity input."""

    if (
        not _matches(_COMMIT, candidate_commit)
        or not _matches(_COMMIT, installed_commit)
        or candidate_commit == installed_commit
        or not _matches(_REPOSITORY_IDENTITY, repository_identity)
        or not _matches(_DIGEST, tree_digest_value)
        or not _matches(_DIGEST, source_compose_digest)
        or type(tools) is not dict
        or frozenset(tools) != _TOOLS
    ):
        _fail()
    source_path = _string_path(source_compose_path)
    normalized_tools: dict[str, dict[str, Any]] = {}
    for name in sorted(tools):
        tool = _exact_mapping(tools[name], _TOOL_KEYS)
        path = _string_path(tool["path"])
        if not _matches(_DIGEST, tool.get("digest")):
            _fail()
        normalized_tools[name] = {
            "device": _integer(tool["device"]),
            "digest": tool["digest"],
            "inode": _integer(tool["inode"]),
            "mode": _integer(tool["mode"]),
            "path": str(path),
            "uid": _integer(tool["uid"]),
        }
    binding = {
        "candidate_commit": candidate_commit,
        "contract_version": RELEASE_GENERATION_CONTRACT,
        "installed_commit": installed_commit,
        "repository_identity": repository_identity,
        "source_compose": {
            "digest": source_compose_digest,
            "path": str(source_path),
        },
        "tools": normalized_tools,
        "tree_digest": tree_digest_value,
    }
    return digest(canonical_json(binding)).removeprefix("sha256:")


def closure_digest(
    files: list[dict[str, Any]],
    closure_paths: list[str],
) -> str:
    if type(files) is not list or type(closure_paths) is not list:
        _fail()
    by_path = {
        entry.get("path"): entry
        for entry in files
        if type(entry) is dict and type(entry.get("path")) is str
    }
    if len(by_path) != len(files):
        _fail()
    try:
        selected = [by_path[path] for path in closure_paths]
    except (KeyError, TypeError) as error:
        raise CandidateError(_ERROR) from error
    return digest(canonical_json(selected))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _parse_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise CandidateError(_ERROR) from error
    if not -MAX_SAFE_INTEGER <= parsed <= MAX_SAFE_INTEGER:
        _fail()
    return parsed


def _parse_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise CandidateError(_ERROR) from error
    if not math.isfinite(parsed):
        _fail()
    return parsed


def _reject_constant(_value: str) -> NoReturn:
    _fail()


def parse_canonical_json(payload: bytes, *, maximum: int) -> Any:
    if (
        type(payload) is not bytes
        or not payload
        or type(maximum) is not int
        or maximum <= 0
        or len(payload) > maximum
        or payload.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff"))
    ):
        _fail()
    try:
        decoded = payload.decode("ascii", "strict")
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
            parse_int=_parse_int,
        )
    except CandidateError:
        raise
    except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError) as error:
        raise CandidateError(_ERROR) from error
    bounded = _bounded_copy(parsed)
    if canonical_json(bounded) != payload:
        _fail()
    return bounded


def _exact_mapping(value: Any, keys: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        _fail()
    return value


def _integer(value: Any, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        _fail()
    return value


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _canonical_absolute(path: Path) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or str(path).startswith("//")
        or "\x00" in str(path)
        or any(part in {".", ".."} for part in path.parts)
    ):
        _fail()
    try:
        if path.resolve(strict=True) != path:
            _fail()
    except OSError as error:
        raise CandidateError(_ERROR) from error
    return path


def _directory(
    path: Path,
    *,
    mode: int,
    owner: int | None = None,
) -> os.stat_result:
    _canonical_absolute(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CandidateError(_ERROR) from error
    expected_owner = os.geteuid() if owner is None else owner
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        _fail()
    return metadata


def _read_regular(
    path: Path,
    *,
    mode: int,
    maximum: int,
    allowed_uids: frozenset[int] | None = None,
) -> tuple[bytes, os.stat_result]:
    _canonical_absolute(path)
    descriptor: int | None = None
    try:
        lexical = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        owners = allowed_uids or frozenset({os.geteuid()})
        for metadata in (lexical, opened):
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid not in owners
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != mode
                or not 0 <= metadata.st_size <= maximum
            ):
                _fail()
        if _metadata(lexical) != _metadata(opened):
            _fail()
        payload = bytearray()
        while True:
            block = os.read(descriptor, min(65_536, maximum + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
            if len(payload) > maximum:
                _fail()
        after = os.fstat(descriptor)
        current = path.lstat()
        if _metadata(after) != _metadata(opened) or _metadata(current) != _metadata(opened):
            _fail()
        return bytes(payload), opened
    except CandidateError:
        raise
    except OSError as error:
        raise CandidateError(_ERROR) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _relative_path(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "\x00" in value
        or "\n" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        _fail()
    path = PurePosixPath(value)
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        _fail()
    return value


def _validate_manifest(document: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    manifest = _exact_mapping(document, _MANIFEST_KEYS)
    if (
        manifest["contract_version"] != SOURCE_MANIFEST_CONTRACT
        or not _matches(_DIGEST, manifest.get("manifest_digest"))
        or not _matches(_COMMIT, manifest.get("candidate_commit"))
        or not _matches(
            _REPOSITORY_IDENTITY, manifest.get("repository_identity")
        )
        or not _matches(_DIGEST, manifest.get("tree_digest"))
        or manifest["manifest_digest"]
        != document_digest(manifest, "manifest_digest")
    ):
        _fail()
    raw_files = manifest["files"]
    if type(raw_files) is not list or not raw_files or len(raw_files) > MAX_FILES:
        _fail()
    files: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    previous = ""
    total = 0
    for raw in raw_files:
        entry = _exact_mapping(raw, _FILE_KEYS)
        path = _relative_path(entry["path"])
        size = _integer(entry["size"])
        mode = _integer(entry["mode"])
        if (
            path <= previous
            or path in by_path
            or mode not in {SOURCE_FILE_MODE, SOURCE_EXECUTABLE_MODE}
            or not _matches(_DIGEST, entry.get("digest"))
            or size > MAX_SOURCE_FILE_BYTES
        ):
            _fail()
        total += size
        if total > MAX_SOURCE_BYTES:
            _fail()
        previous = path
        copied = dict(entry)
        files.append(copied)
        by_path[path] = copied
    if manifest["tree_digest"] != tree_digest(files):
        _fail()
    if not REQUIRED_RUNTIME_FILES.issubset(by_path):
        _fail()
    closure = _exact_mapping(manifest["runtime_closure"], _CLOSURE_KEYS)
    closure_paths = closure["files"]
    if (
        type(closure_paths) is not list
        or closure_paths != [entry["path"] for entry in files]
        or closure.get("closure_digest") != closure_digest(files, closure_paths)
    ):
        _fail()
    return manifest, by_path


def _walk_and_validate_source(
    repository: Path,
    manifest_files: Mapping[str, Mapping[str, Any]],
) -> None:
    root_metadata = _directory(repository, mode=SOURCE_DIRECTORY_MODE)
    directories: dict[str, tuple[Path, tuple[int, ...]]] = {
        "": (repository, _metadata(root_metadata))
    }
    discovered: dict[str, tuple[Path, os.stat_result]] = {}

    def visit(directory: Path, prefix: PurePosixPath | None) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise CandidateError(_ERROR) from error
        for entry in entries:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise CandidateError(_ERROR) from error
            relative = entry.name if prefix is None else f"{prefix}/{entry.name}"
            relative = _relative_path(relative)
            path = directory / entry.name
            if entry.is_symlink():
                _fail()
            if stat.S_ISDIR(metadata.st_mode):
                if (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != SOURCE_DIRECTORY_MODE
                ):
                    _fail()
                directories[relative] = (path, _metadata(metadata))
                visit(path, PurePosixPath(relative))
            elif stat.S_ISREG(metadata.st_mode):
                if (
                    metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode)
                    not in {SOURCE_FILE_MODE, SOURCE_EXECUTABLE_MODE}
                ):
                    _fail()
                discovered[relative] = (path, metadata)
                if len(discovered) > MAX_FILES:
                    _fail()
            else:
                _fail()

    visit(repository, None)
    if set(discovered) != set(manifest_files):
        _fail()
    implied_directories = {""}
    for relative in manifest_files:
        parts = PurePosixPath(relative).parts[:-1]
        for index in range(1, len(parts) + 1):
            implied_directories.add("/".join(parts[:index]))
    if set(directories) != implied_directories:
        _fail()
    total = 0
    for relative in sorted(discovered):
        path, before = discovered[relative]
        expected = manifest_files[relative]
        payload, opened = _read_regular(
            path,
            mode=expected["mode"],
            maximum=MAX_SOURCE_FILE_BYTES,
        )
        if _metadata(before) != _metadata(opened):
            _fail()
        total += len(payload)
        if (
            total > MAX_SOURCE_BYTES
            or len(payload) != expected["size"]
            or digest(payload) != expected["digest"]
        ):
            _fail()
    for path, expected in directories.values():
        try:
            current = path.lstat()
        except OSError as error:
            raise CandidateError(_ERROR) from error
        if _metadata(current) != expected:
            _fail()


def _string_path(value: Any) -> Path:
    if type(value) is not str:
        _fail()
    return _canonical_absolute(Path(value))


def _validate_tool(name: str, record: Any) -> None:
    del name
    tool = _exact_mapping(record, _TOOL_KEYS)
    path = _string_path(tool["path"])
    expected_device = _integer(tool["device"])
    expected_inode = _integer(tool["inode"])
    expected_uid = _integer(tool["uid"])
    if expected_uid not in {0, os.geteuid()}:
        _fail()
    expected_mode = _integer(tool["mode"])
    if expected_mode & 0o022 or expected_mode > 0o7777:
        _fail()
    payload, metadata = _read_regular(
        path,
        mode=expected_mode,
        maximum=MAX_TOOL_BYTES,
        allowed_uids=frozenset({expected_uid}),
    )
    if (
        not _matches(_DIGEST, tool.get("digest"))
        or tool["digest"] != digest(payload)
        or expected_device != metadata.st_dev
        or expected_inode != metadata.st_ino
        or tool["uid"] != metadata.st_uid
    ):
        _fail()


def _repository_root_from_ingress(value: Any) -> Path:
    path = _string_path(value)
    suffix = _INGRESS_SUFFIX.parts
    if len(path.parts) <= len(suffix) or tuple(path.parts[-len(suffix) :]) != suffix:
        _fail()
    root = Path(*path.parts[: -len(suffix)])
    _canonical_absolute(root)
    return root


def _compose_build_context(document: Mapping[str, Any], service: str) -> str | None:
    try:
        service_document = document["services"][service]
    except (KeyError, TypeError) as error:
        raise CandidateError(_ERROR) from error
    if type(service_document) is not dict:
        _fail()
    if "build" not in service_document:
        return None
    build = service_document["build"]
    if build is None:
        return None
    if type(build) is not dict or type(build.get("context")) is not str:
        _fail()
    return build["context"]


def _validate_compose_transition(
    source: Any,
    prepared: Any,
    *,
    repository: Path,
    image_ref: str,
    manifest_files: Mapping[str, Mapping[str, Any]],
) -> None:
    if type(source) is not dict or type(prepared) is not dict:
        _fail()
    try:
        source_ingress = source["configs"]["tacua_loopback_ingress"]["file"]
        prepared_ingress = prepared["configs"]["tacua_loopback_ingress"]["file"]
        source_image = source["services"]["reviewer"]["image"]
        prepared_image = prepared["services"]["reviewer"]["image"]
    except (KeyError, TypeError) as error:
        raise CandidateError(_ERROR) from error
    source_ingress_path = _string_path(source_ingress)
    source_root = _repository_root_from_ingress(source_ingress)
    expected_ingress = repository / Path(*_INGRESS_SUFFIX.parts)
    _canonical_absolute(expected_ingress)
    try:
        source_ingress_mode = stat.S_IMODE(source_ingress_path.lstat().st_mode)
    except OSError as error:
        raise CandidateError(_ERROR) from error
    if (
        source_ingress_mode > 0o777
        or not source_ingress_mode & stat.S_IRUSR
        or source_ingress_mode & 0o111
        or source_ingress_mode & 0o022
    ):
        _fail()
    source_ingress_payload, _source_ingress_metadata = _read_regular(
        source_ingress_path,
        mode=source_ingress_mode,
        maximum=MAX_SOURCE_FILE_BYTES,
    )
    retained_ingress = manifest_files.get(str(_INGRESS_SUFFIX))
    if (
        source_root == repository
        or prepared_ingress != str(expected_ingress)
        or prepared_image != image_ref
        or source_image == image_ref
        or retained_ingress is None
        or retained_ingress.get("digest") != digest(source_ingress_payload)
        or retained_ingress.get("size") != len(source_ingress_payload)
    ):
        _fail()
    expected = deepcopy(source)
    expected["configs"]["tacua_loopback_ingress"]["file"] = str(expected_ingress)
    expected["services"]["reviewer"]["image"] = image_ref
    for service in ("backend", "reviewer"):
        source_context = _compose_build_context(source, service)
        prepared_context = _compose_build_context(prepared, service)
        if (source_context is None) != (prepared_context is None):
            _fail()
        if source_context is not None:
            if source_context != str(source_root) or prepared_context != str(repository):
                _fail()
            expected["services"][service]["build"]["context"] = str(repository)
    if prepared != expected:
        _fail()


def _validate_receipt(
    document: Any,
    *,
    release_root: Path,
    root_metadata: os.stat_result,
    manifest: Mapping[str, Any],
    manifest_files: Mapping[str, Mapping[str, Any]],
    candidate_compose_payload: bytes,
    candidate_compose_document: Any,
) -> dict[str, Any]:
    receipt = _exact_mapping(document, _RECEIPT_KEYS)
    if (
        receipt["contract_version"] != PREPARATION_RECEIPT_CONTRACT
        or receipt["status"] != "verified"
        or not _matches(_DIGEST, receipt.get("receipt_digest"))
        or receipt["receipt_digest"] != document_digest(receipt, "receipt_digest")
        or receipt["generation_id"] != release_root.name
        or receipt["candidate_commit"] != manifest["candidate_commit"]
        or not _matches(_COMMIT, receipt.get("installed_commit"))
        or receipt["installed_commit"] == receipt["candidate_commit"]
        or receipt["repository_identity"] != manifest["repository_identity"]
        or receipt["source_manifest_digest"] != manifest["manifest_digest"]
    ):
        _fail()
    binding = _exact_mapping(receipt["release_binding"], _RELEASE_BINDING_KEYS)
    if (
        _integer(binding["device"]) != root_metadata.st_dev
        or _integer(binding["inode"]) != root_metadata.st_ino
        or _integer(binding["mode"]) != RELEASE_MODE
    ):
        _fail()
    source_record = _exact_mapping(receipt["source_compose"], _COMPOSE_RECORD_KEYS)
    if _integer(source_record["mode"]) != SOURCE_COMPOSE_MODE:
        _fail()
    source_path = _string_path(source_record["path"])
    source_payload, _source_metadata = _read_regular(
        source_path,
        mode=SOURCE_COMPOSE_MODE,
        maximum=MAX_COMPOSE_BYTES,
    )
    if (
        not _matches(_DIGEST, source_record.get("digest"))
        or source_record["digest"] != digest(source_payload)
    ):
        _fail()
    source_document = parse_canonical_json(source_payload, maximum=MAX_COMPOSE_BYTES)
    prepared_record = _exact_mapping(
        receipt["candidate_compose"], _COMPOSE_RECORD_KEYS
    )
    if (
        prepared_record["path"] != CANDIDATE_COMPOSE_FILE
        or _integer(prepared_record["mode"]) != CANDIDATE_COMPOSE_MODE
        or not _matches(_DIGEST, prepared_record.get("digest"))
        or prepared_record["digest"] != digest(candidate_compose_payload)
    ):
        _fail()
    image = _exact_mapping(receipt["reviewer_image"], _IMAGE_KEYS)
    if (
        not _matches(_IMAGE_REF, image.get("ref"))
        or image["ref"].endswith(":latest")
        or not _matches(_DIGEST, image.get("id"))
    ):
        _fail()
    tools = receipt["tools"]
    if type(tools) is not dict or frozenset(tools) != _TOOLS:
        _fail()
    for name in sorted(tools):
        _validate_tool(name, tools[name])
    if receipt["generation_id"] != release_generation_id(
        candidate_commit=receipt["candidate_commit"],
        installed_commit=receipt["installed_commit"],
        repository_identity=receipt["repository_identity"],
        tree_digest_value=manifest["tree_digest"],
        source_compose_path=source_record["path"],
        source_compose_digest=source_record["digest"],
        tools=tools,
    ):
        _fail()
    verification = _exact_mapping(receipt["verification"], _VERIFICATION_KEYS)
    if (
        verification["status"] != "verified"
        or not _matches(_ATTEMPT_ID, verification.get("attempt_id"))
        or not _matches(_DIGEST, verification.get("commands_digest"))
    ):
        _fail()
    _validate_compose_transition(
        source_document,
        candidate_compose_document,
        repository=release_root / SOURCE_DIRECTORY,
        image_ref=image["ref"],
        manifest_files=manifest_files,
    )
    return receipt


def load_prepared_release(
    release_root: Path,
    *,
    expected_commit: str | None = None,
    expected_repository_identity: str | None = None,
) -> PreparedRelease:
    """Load and fully re-prove one immutable prepared release.

    The function is deliberately pure with respect to external systems.  It
    reads only the supplied release, the receipt-bound source Compose file,
    and the receipt-bound local tool binaries.
    """

    if not isinstance(release_root, Path):
        _fail()
    _canonical_absolute(release_root)
    if (
        release_root.parent.name != RELEASES_DIRECTORY
        or not _matches(_GENERATION, release_root.name)
        or expected_commit is not None
        and (type(expected_commit) is not str or not _matches(_COMMIT, expected_commit))
        or expected_repository_identity is not None
        and (
            type(expected_repository_identity) is not str
            or not _matches(_REPOSITORY_IDENTITY, expected_repository_identity)
        )
    ):
        _fail()
    _directory(release_root.parent, mode=PRIVATE_DIRECTORY_MODE)
    _directory(release_root.parent.parent, mode=PRIVATE_DIRECTORY_MODE)
    root_metadata = _directory(release_root, mode=RELEASE_MODE)
    try:
        names = {entry.name for entry in os.scandir(release_root)}
    except OSError as error:
        raise CandidateError(_ERROR) from error
    if names != {
        SOURCE_DIRECTORY,
        SOURCE_MANIFEST_FILE,
        CANDIDATE_COMPOSE_FILE,
        PREPARATION_RECEIPT_FILE,
    }:
        _fail()
    repository = release_root / SOURCE_DIRECTORY
    manifest_path = release_root / SOURCE_MANIFEST_FILE
    candidate_compose = release_root / CANDIDATE_COMPOSE_FILE
    receipt_path = release_root / PREPARATION_RECEIPT_FILE
    manifest_payload, manifest_metadata = _read_regular(
        manifest_path,
        mode=MANIFEST_MODE,
        maximum=MAX_MANIFEST_BYTES,
    )
    manifest, manifest_files = _validate_manifest(
        parse_canonical_json(manifest_payload, maximum=MAX_MANIFEST_BYTES)
    )
    if (
        expected_commit is not None
        and manifest["candidate_commit"] != expected_commit
        or expected_repository_identity is not None
        and manifest["repository_identity"] != expected_repository_identity
    ):
        _fail()
    _walk_and_validate_source(repository, manifest_files)
    candidate_payload, candidate_metadata = _read_regular(
        candidate_compose,
        mode=CANDIDATE_COMPOSE_MODE,
        maximum=MAX_COMPOSE_BYTES,
    )
    candidate_document = parse_canonical_json(
        candidate_payload,
        maximum=MAX_COMPOSE_BYTES,
    )
    receipt_payload, receipt_metadata = _read_regular(
        receipt_path,
        mode=RECEIPT_MODE,
        maximum=MAX_RECEIPT_BYTES,
    )
    receipt = _validate_receipt(
        parse_canonical_json(receipt_payload, maximum=MAX_RECEIPT_BYTES),
        release_root=release_root,
        root_metadata=root_metadata,
        manifest=manifest,
        manifest_files=manifest_files,
        candidate_compose_payload=candidate_payload,
        candidate_compose_document=candidate_document,
    )
    try:
        current_root = release_root.lstat()
        current_manifest = manifest_path.lstat()
        current_candidate = candidate_compose.lstat()
        current_receipt = receipt_path.lstat()
        current_names = {entry.name for entry in os.scandir(release_root)}
    except OSError as error:
        raise CandidateError(_ERROR) from error
    if (
        _metadata(current_root) != _metadata(root_metadata)
        or _metadata(current_manifest) != _metadata(manifest_metadata)
        or _metadata(current_candidate) != _metadata(candidate_metadata)
        or _metadata(current_receipt) != _metadata(receipt_metadata)
        or current_names != names
    ):
        _fail()
    return PreparedRelease(
        release_root=release_root,
        repository=repository,
        candidate_compose=candidate_compose,
        receipt=receipt,
        source_manifest=manifest,
    )
