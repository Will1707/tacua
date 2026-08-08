#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Attested, one-shot loader for a single legacy reviewer upgrade.

The profile is deliberately produced out of band.  This program accepts no
paths other than that one profile, emits no paths or operation identifiers,
and imports the legacy transaction from already verified source bytes.

The sandbox declaration is an attested input, not a live manager query.  A
separate exact controller must prove the stable service is still failed with
status 78 and the selector path has no job immediately before invoking run.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import sysconfig
from types import ModuleType
from typing import Any, Mapping, NoReturn, Sequence


CONTRACT = "tacua.reviewer-upgrade-legacy-recovery-profile@1.0.0"
PROFILE_DIGEST = "profile_digest"
MAX_PROFILE_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
SYSTEMCTL = Path("/usr/bin/systemctl")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
STABLE_UNIT = "tacua-reviewer-upgrade-resume.service"
PATH_UNIT = "tacua-reviewer-upgrade-resume.path"
FLAGS = (
    "--state-parent",
    "--serial-lock-file",
    "--unit-directory",
    "--lock-file",
    "--operation-directory",
)
MODULE_RELATIVE_PATHS = {
    "reconcile_compose_deployment": "services/backend/scripts/reconcile_compose_deployment.py",
    "reviewer_upgrade_backup": "services/backend/scripts/reviewer_upgrade_backup.py",
    "reviewer_upgrade_backup_docker": "services/backend/scripts/reviewer_upgrade_backup_docker.py",
    "reviewer_upgrade_finalize": "services/backend/scripts/reviewer_upgrade_finalize.py",
    "reviewer_upgrade_journal": "services/backend/scripts/reviewer_upgrade_journal.py",
    "reviewer_upgrade_manager": "services/backend/scripts/reviewer_upgrade_manager.py",
    "reviewer_upgrade_systemd": "services/backend/scripts/reviewer_upgrade_systemd.py",
    "reviewer_upgrade_transaction": "services/backend/scripts/reviewer_upgrade_transaction.py",
    "reviewer_upgrade_unit_artifacts": "services/backend/scripts/reviewer_upgrade_unit_artifacts.py",
    "verify_tailnet_private_pilot": "services/backend/scripts/verify_tailnet_private_pilot.py",
    "tacua_backend": "services/backend/src/tacua_backend/__init__.py",
    "tacua_backend.config": "services/backend/src/tacua_backend/config.py",
    "tacua_backend.contracts": "services/backend/src/tacua_backend/contracts.py",
    "tacua_backend.instance_lock": "services/backend/src/tacua_backend/instance_lock.py",
    "tacua_backend.operator_tool": "services/backend/src/tacua_backend/operator_tool.py",
}
REQUIRED_MODULES = frozenset(MODULE_RELATIVE_PATHS)
FILE_KEYS = frozenset(
    {
        "device",
        "gid",
        "inode",
        "mode",
        "mtime_ns",
        "nlink",
        "path",
        "sha256",
        "size",
        "uid",
    }
)
DOCUMENT_KEYS = frozenset(
    {
        "argv",
        "closure",
        "closure_root",
        "contract_version",
        "evidence",
        "fragment",
        "marker_path",
        "modules",
        "profile_digest",
        "profile_path",
        "sandbox",
        "sandbox_digest",
        "tools",
        "wrapper",
        "writer",
    }
)
SAFE_MODULE = re.compile(r"^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*$")
SAFE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
STAGE = "bootstrap"


class ProfileError(RuntimeError):
    pass


def _fail() -> NoReturn:
    raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID") from error


def _journal_canonical(value: object) -> bytes:
    """Return the legacy journal's canonical JSON representation.

    Profile documents, markers, and process output are newline-terminated.
    The transaction journal deliberately stores its active, plan, progress,
    and desired-state documents without that transport delimiter.
    """

    return _canonical(value)[:-1]


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _document_digest(document: Mapping[str, Any], key: str) -> str:
    candidate = deepcopy(dict(document))
    candidate[key] = ""
    return _digest(_canonical(candidate))


def _safe_absolute(value: object) -> Path:
    if type(value) is not str:
        _fail()
    path = Path(value)
    if (
        not path.is_absolute()
        or value.startswith("//")
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or any(character in value for character in "\x00\n\r\t")
    ):
        _fail()
    return path


def _identity(item: os.stat_result) -> tuple[int, ...]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
    )


def _read_regular(
    path: Path,
    *,
    mode: int | None,
    maximum: int,
    owner_uid: int | None = None,
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
        expected_uid = os.geteuid() if owner_uid is None else owner_uid
        if (
            path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
            or not 0 < before.st_size <= maximum
        ):
            _fail()
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            payload = bytearray()
            while len(payload) <= maximum:
                block = os.read(descriptor, min(65_536, maximum + 1 - len(payload)))
                if not block:
                    break
                payload.extend(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = path.lstat()
        if (
            len(payload) != before.st_size
            or len(payload) > maximum
            or _identity(before) != _identity(opened)
            or _identity(opened) != _identity(after)
            or _identity(after) != _identity(current)
        ):
            _fail()
        return bytes(payload), before
    except (OSError, ProfileError) as error:
        if isinstance(error, ProfileError):
            raise
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID") from error


def _binding(path: Path, payload: bytes, item: os.stat_result) -> dict[str, Any]:
    return {
        "device": item.st_dev,
        "gid": item.st_gid,
        "inode": item.st_ino,
        "mode": stat.S_IMODE(item.st_mode),
        "mtime_ns": item.st_mtime_ns,
        "nlink": item.st_nlink,
        "path": str(path),
        "sha256": _digest(payload),
        "size": item.st_size,
        "uid": item.st_uid,
    }


def _read_binding(value: object, *, maximum: int = MAX_FILE_BYTES) -> bytes:
    if type(value) is not dict or set(value) != FILE_KEYS:
        _fail()
    path = _safe_absolute(value.get("path"))
    payload, item = _read_regular(path, mode=int(value.get("mode", -1)), maximum=maximum)
    if _binding(path, payload, item) != value or SAFE_DIGEST.fullmatch(str(value.get("sha256"))) is None:
        _fail()
    return payload


def _parse_canonical(payload: bytes) -> Any:
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID") from error
    if _canonical(value) != payload:
        _fail()
    return value


def _parse_journal_canonical(payload: bytes) -> Any:
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID") from error
    if _journal_canonical(value) != payload:
        _fail()
    return value


def _directory(path: Path, *, mode: int | None = None) -> os.stat_result:
    try:
        item = path.lstat()
        if (
            path.resolve(strict=True) != path
            or not stat.S_ISDIR(item.st_mode)
            or item.st_uid != os.geteuid()
            or item.st_mode & 0o022
            or (mode is not None and stat.S_IMODE(item.st_mode) != mode)
        ):
            _fail()
        return item
    except OSError as error:
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID") from error


def _root_tool(value: object, launch: Path) -> None:
    if type(value) is not dict or set(value) != {"launch_path", "file"}:
        _fail()
    if _safe_absolute(value["launch_path"]) != launch:
        _fail()
    try:
        lexical = launch.lstat()
        resolved = launch.resolve(strict=True)
        payload, item = _read_regular(
            resolved,
            mode=None,
            maximum=MAX_FILE_BYTES,
            owner_uid=0,
        )
    except OSError as error:
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID") from error
    lexical_safe = (
        lexical.st_uid == 0
        and (
            stat.S_ISLNK(lexical.st_mode)
            or (
                stat.S_ISREG(lexical.st_mode)
                and not lexical.st_mode & 0o022
            )
        )
    )
    if (
        not lexical_safe
        or item.st_uid != 0
        or item.st_mode & 0o022
        or not item.st_mode & 0o111
        or value["file"] != _binding(resolved, payload, item)
    ):
        _fail()


def _sandbox(document: Mapping[str, Any], argv: tuple[str, ...]) -> None:
    sandbox = document.get("sandbox")
    if type(sandbox) is not dict or set(sandbox) != {"path_unit", "read_only_paths", "read_write_paths", "stable_unit"}:
        _fail()
    stable = sandbox["stable_unit"]
    path_unit = sandbox["path_unit"]
    if (
        type(stable) is not dict
        or stable != {
            "ActiveState": "failed",
            "DropInPaths": "",
            "ExecMainStatus": "78",
            "Job": "",
            "NeedDaemonReload": "no",
            "Result": "exit-code",
            "SubState": "failed",
            "name": STABLE_UNIT,
        }
        or type(path_unit) is not dict
        or path_unit != {
            "ActiveState": "failed",
            "Job": "",
            "SubState": "failed",
            "name": PATH_UNIT,
        }
        or type(sandbox["read_only_paths"]) is not list
        or type(sandbox["read_write_paths"]) is not list
        or not sandbox["read_only_paths"]
        or len(sandbox["read_write_paths"]) != 5
        or any(type(item) is not str or _safe_absolute(item) is None for item in sandbox["read_only_paths"] + sandbox["read_write_paths"])
        or tuple(sandbox["read_write_paths"]) != tuple(argv[5::2])
        or document.get("sandbox_digest") != _digest(_canonical(sandbox))
    ):
        _fail()


@dataclass(frozen=True)
class LoadedProfile:
    path: Path
    document: dict[str, Any]
    sources: dict[str, bytes]


def _load_profile(profile_path: Path, *, marker_required: bool) -> LoadedProfile:
    path = _safe_absolute(str(profile_path))
    payload, _item = _read_regular(path, mode=0o400, maximum=MAX_PROFILE_BYTES)
    document = _parse_canonical(payload)
    if (
        type(document) is not dict
        or set(document) != DOCUMENT_KEYS
        or document.get("contract_version") != CONTRACT
        or document.get("profile_path") != str(path)
        or document.get("profile_digest") != _document_digest(document, PROFILE_DIGEST)
        or _safe_absolute(document.get("marker_path")) != path.parent / "run.once"
    ):
        _fail()
    _directory(path.parent, mode=0o700)
    argv_value = document.get("argv")
    if (
        type(argv_value) is not list
        or len(argv_value) != 14
        or any(type(token) is not str or not token or any(c in token for c in "\x00\n\r\t") for token in argv_value)
    ):
        _fail()
    argv = tuple(argv_value)
    if (
        argv[1] != "-B"
        or Path(argv[2]).name != "reviewer_upgrade_transaction.py"
        or argv[3] != "resume"
        or tuple(argv[4::2]) != FLAGS
        or any(not Path(argv[index]).is_absolute() for index in (0, 2, 5, 7, 9, 11, 13))
    ):
        _fail()
    _sandbox(document, argv)
    fragment = document.get("fragment")
    _read_binding(fragment, maximum=1024 * 1024)
    if Path(fragment["path"]) != Path(argv[9]) / STABLE_UNIT:
        _fail()
    tools = document.get("tools")
    if type(tools) is not dict or set(tools) != {"python", "systemctl", "systemd_run"}:
        _fail()
    _root_tool(tools["python"], Path(argv[0]))
    _root_tool(tools["systemctl"], SYSTEMCTL)
    _root_tool(tools["systemd_run"], SYSTEMD_RUN)
    closure_root = _safe_absolute(document.get("closure_root"))
    _directory(closure_root)
    if str(closure_root) not in document["sandbox"]["read_only_paths"]:
        _fail()
    closure = document.get("closure")
    modules = document.get("modules")
    if (
        type(closure) is not dict
        or not closure
        or type(modules) is not dict
        or not REQUIRED_MODULES.issubset(modules)
        or any(modules.get(name) != relative for name, relative in MODULE_RELATIVE_PATHS.items())
    ):
        _fail()
    sources: dict[str, bytes] = {}
    for relative, binding in closure.items():
        if type(relative) is not str:
            _fail()
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            _fail()
        if _safe_absolute(binding.get("path")) != closure_root.joinpath(*pure.parts):
            _fail()
        sources[relative] = _read_binding(binding)
    for name, relative in modules.items():
        if SAFE_MODULE.fullmatch(str(name)) is None or type(relative) is not str or relative not in sources or not relative.endswith(".py"):
            _fail()
    if modules["reviewer_upgrade_transaction"] not in sources or Path(closure[modules["reviewer_upgrade_transaction"]]["path"]) != Path(argv[2]):
        _fail()
    evidence = document.get("evidence")
    if type(evidence) is not dict or set(evidence) != {"activation", "active", "desired", "plan", "progress"}:
        _fail()
    parsed: dict[str, Any] = {}
    for name in ("active", "plan", "progress", "desired"):
        parsed[name] = _parse_journal_canonical(
            _read_binding(evidence[name], maximum=8 * 1024 * 1024)
        )
        if type(parsed[name]) is not dict:
            _fail()
    active = parsed["active"]
    sealed_plan = parsed["plan"].get("plan")
    operation_id = active.get("operation_id")
    if (
        type(operation_id) is not str
        or not operation_id
        or "/" in operation_id
        or operation_id in {".", ".."}
        or type(sealed_plan) is not dict
        or type(sealed_plan.get("source_state_directory")) is not str
        or type(sealed_plan.get("candidate_repository_root")) is not str
        or parsed["active"].get("plan_digest") != parsed["plan"].get("plan_digest")
        or parsed["progress"].get("plan_digest") != parsed["plan"].get("plan_digest")
        or parsed["progress"].get("phase") != "quiescing"
        or type(parsed["progress"].get("sequence")) is not int
        or parsed["progress"].get("details", {}).get("gate_state") != "inhibitor_ready"
        or parsed["desired"].get("desired") != "running"
    ):
        _fail()
    state_parent = Path(argv[5])
    transaction = state_parent / "upgrades" / operation_id
    source_state = _safe_absolute(sealed_plan["source_state_directory"])
    candidate_repository = _safe_absolute(
        sealed_plan["candidate_repository_root"]
    )
    try:
        transaction_repository = Path(argv[2]).parents[3]
    except IndexError:
        _fail()
    if closure_root != transaction_repository or closure_root != candidate_repository:
        _fail()
    if (
        Path(evidence["active"]["path"])
        != state_parent / "upgrades" / "active.json"
        or Path(evidence["plan"]["path"]) != transaction / "plan.json"
        or Path(evidence["progress"]["path"]) != transaction / "progress.json"
        or Path(evidence["desired"]["path"])
        != source_state / "desired-state.json"
    ):
        _fail()
    activation = evidence["activation"]
    if type(activation) is not dict or set(activation) != {"parent", "path"}:
        _fail()
    activation_path = _safe_absolute(activation["path"])
    parent = _safe_absolute(activation["parent"])
    _directory(parent, mode=0o700)
    if activation_path != source_state / "activation.json" or parent != source_state:
        _fail()
    try:
        activation_path.lstat()
    except FileNotFoundError:
        pass
    else:
        _fail()
    wrapper = document.get("wrapper")
    _read_binding(wrapper, maximum=2 * 1024 * 1024)
    if Path(wrapper["path"]) != Path(__file__).resolve(strict=True):
        _fail()
    _read_binding(document.get("writer"), maximum=2 * 1024 * 1024)
    if Path(document["writer"]["path"]) != Path(wrapper["path"]).with_name(
        "reviewer_upgrade_legacy_recovery.py"
    ):
        _fail()
    marker = Path(document["marker_path"])
    if marker_required:
        expected_marker = _canonical(
            {
                "contract_version": "tacua.reviewer-upgrade-legacy-recovery-run@1.0.0",
                "profile_digest": document["profile_digest"],
            }
        )
        marker_payload, _marker_item = _read_regular(
            marker,
            mode=0o400,
            maximum=1024,
        )
        if marker_payload != expected_marker:
            _fail()
    else:
        try:
            marker.lstat()
        except FileNotFoundError:
            pass
        else:
            _fail()
    return LoadedProfile(path=path, document=document, sources=sources)


def load_profile(profile_path: Path) -> LoadedProfile:
    """Validate an unconsumed profile without mutating host state."""

    return _load_profile(profile_path, marker_required=False)


class _MemoryLoader(importlib.abc.Loader):
    def __init__(self, name: str, path: Path, source: bytes, package: bool) -> None:
        self.name, self.path, self.source, self.package = name, path, source, package

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        module.__file__ = str(self.path)
        if self.package:
            # The in-memory finder resolves every attested child.  An empty
            # search path prevents PathFinder from falling through to disk.
            module.__path__ = []
        exec(compile(self.source, str(self.path), "exec", dont_inherit=True), module.__dict__)


class _MemoryFinder(importlib.abc.MetaPathFinder):
    def __init__(self, profile: LoadedProfile) -> None:
        self.profile = profile
        self.loaded: set[str] = set()

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> Any:
        relative = self.profile.document["modules"].get(fullname)
        if relative is None:
            if fullname.startswith(
                (
                    "reconcile_compose_deployment",
                    "reviewer_upgrade_",
                    "tacua_backend",
                    "verify_tailnet_private_pilot",
                )
            ):
                raise ImportError("unprofiled legacy module")
            parts = fullname.split(".")
            root = Path(self.profile.document["closure_root"])
            for base in (
                root / "services" / "backend" / "scripts",
                root / "services" / "backend" / "src",
            ):
                candidate = base.joinpath(*parts)
                if candidate.with_suffix(".py").is_file() or (
                    candidate / "__init__.py"
                ).is_file():
                    raise ImportError("unprofiled closure module")
            return None
        binding = self.profile.document["closure"][relative]
        file_path = Path(binding["path"])
        package = file_path.name == "__init__.py"
        self.loaded.add(fullname)
        return importlib.util.spec_from_loader(
            fullname,
            _MemoryLoader(fullname, file_path, self.profile.sources[relative], package),
            origin=str(file_path),
            is_package=package,
        )


def _load_writer(profile: LoadedProfile) -> ModuleType:
    binding = profile.document["writer"]
    source = _read_binding(binding, maximum=2 * 1024 * 1024)
    name = "_tacua_attested_legacy_writer"
    spec = importlib.util.spec_from_loader(name, _MemoryLoader(name, Path(binding["path"]), source, False))
    if spec is None or spec.loader is None:
        _fail()
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _create_marker(profile: LoadedProfile) -> None:
    path = Path(profile.document["marker_path"])
    payload = _canonical({"contract_version": "tacua.reviewer-upgrade-legacy-recovery-run@1.0.0", "profile_digest": profile.document["profile_digest"]})
    parent = _directory(path.parent, mode=0o700)
    directory = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    descriptor: int | None = None
    try:
        opened_parent = os.fstat(directory)
        if (parent.st_dev, parent.st_ino) != (opened_parent.st_dev, opened_parent.st_ino):
            _fail()
        descriptor = os.open(
            path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
            dir_fd=directory,
        )
        created = os.fstat(descriptor)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_uid != os.geteuid()
            or created.st_nlink != 1
            or stat.S_IMODE(created.st_mode) != 0o400
            or created.st_size != 0
        ):
            _fail()
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                _fail()
            offset += written
        os.fsync(descriptor)
        published = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (
            (created.st_dev, created.st_ino)
            != (published.st_dev, published.st_ino)
            or published.st_size != len(payload)
            or published.st_uid != os.geteuid()
            or published.st_nlink != 1
            or stat.S_IMODE(published.st_mode) != 0o400
        ):
            _fail()
        os.fsync(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def _runtime_guard(python_path: str) -> None:
    safe_path = getattr(sys.flags, "safe_path", True)
    try:
        running = Path(sys.executable).resolve(strict=True)
        expected = Path(python_path).resolve(strict=True)
    except OSError as error:
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID") from error
    if (
        running != expected
        or sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or safe_path is not True
    ):
        _fail()


@contextmanager
def _suppressed_process_output():
    saved_out = os.dup(1)
    saved_error = os.dup(2)
    sink = os.open(
        "/dev/null",
        os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.dup2(sink, 1)
        os.dup2(sink, 2)
        yield
    finally:
        os.dup2(saved_out, 1)
        os.dup2(saved_error, 2)
        os.close(saved_out)
        os.close(saved_error)
        os.close(sink)


def _assert_loaded_modules(
    profile: LoadedProfile,
    finder: _MemoryFinder,
    before: set[str],
) -> None:
    if not REQUIRED_MODULES.issubset(finder.loaded):
        _fail()
    for name in finder.loaded:
        module = sys.modules.get(name)
        relative = profile.document["modules"][name]
        if module is None or Path(str(getattr(module, "__file__", ""))) != Path(
            profile.document["closure"][relative]["path"]
        ):
            _fail()
    stdlib_roots = {
        Path(value).resolve(strict=True)
        for key in ("stdlib", "platstdlib")
        if (value := sysconfig.get_paths().get(key))
    }
    for name in set(sys.modules) - before:
        if name in finder.loaded or name == "_tacua_attested_legacy_writer":
            continue
        module = sys.modules.get(name)
        location = getattr(module, "__file__", None)
        if location is None:
            continue
        try:
            resolved = Path(location).resolve(strict=True)
        except OSError:
            _fail()
        if not any(resolved == root or root in resolved.parents for root in stdlib_roots):
            _fail()


def _execute_profile(profile: LoadedProfile) -> None:
    if any(name in sys.modules for name in profile.document["modules"]):
        _fail()
    before_modules = set(sys.modules)
    writer = _load_writer(profile)
    finder = _MemoryFinder(profile)
    previous_path = list(sys.path)
    previous_modules = {name: sys.modules.get(name) for name in profile.document["modules"]}
    sys.meta_path.insert(0, finder)
    try:
        reconciler = importlib.import_module("reconcile_compose_deployment")
        original = reconciler._atomic_private_write

        def adapted(path: Path, payload: bytes, *, replace: bool, mode: int = 0o600) -> None:
            try:
                writer._atomic_private_write(path, payload, replace=replace, mode=mode)
            except writer.LegacyRecoveryWriteError as error:
                raise reconciler.ReconcileError(error.code) from error

        reconciler._atomic_private_write = adapted
        try:
            transaction = importlib.import_module("reviewer_upgrade_transaction")
            finalize = importlib.import_module("reviewer_upgrade_finalize")
            if transaction.reconciler is not reconciler or finalize.reconciler is not reconciler:
                _fail()
            _assert_loaded_modules(profile, finder, before_modules)
            argv = profile.document["argv"]
            result = transaction.resume(
                Path(argv[5]),
                serial_lock_file=Path(argv[7]),
                unit_directory=Path(argv[9]),
                lock_file=Path(argv[11]),
                operation_directory=Path(argv[13]),
            )
            if (
                type(result) is not dict
                or result.get("code") != "REVIEWER_UPGRADE_COMPLETE"
                or result.get("phase") != "complete"
                or result.get("status") != "complete"
            ):
                _fail()
            _assert_loaded_modules(profile, finder, before_modules)
        finally:
            reconciler._atomic_private_write = original
    finally:
        sys.meta_path.remove(finder)
        sys.path[:] = previous_path
        for name, old in previous_modules.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old
        sys.modules.pop("_tacua_attested_legacy_writer", None)


def run_profile(profile_path: Path) -> None:
    profile = load_profile(profile_path)
    _runtime_guard(profile.document["argv"][0])
    _create_marker(profile)
    # A second immutable read after arming binds the exact evidence used by the
    # importing process.  Marker refusal after this point is intentional.
    profile = _load_profile(profile_path, marker_required=True)
    with _suppressed_process_output():
        _execute_profile(profile)


def emit(value: object) -> None:
    os.write(1, _canonical(value))


class _QuietParser(argparse.ArgumentParser):
    def _print_message(self, message: str, file: object = None) -> None:
        return None

    def error(self, message: str) -> NoReturn:
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID")

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise ProfileError("LEGACY_RECOVERY_PROFILE_INVALID")


def main(argv: Sequence[str] | None = None) -> int:
    global STAGE
    STAGE = "parse"
    try:
        parser = _QuietParser(allow_abbrev=False, add_help=False)
        sub = parser.add_subparsers(
            dest="command",
            required=True,
            parser_class=_QuietParser,
        )
        for command in ("preflight", "run"):
            item = sub.add_parser(
                command,
                allow_abbrev=False,
                add_help=False,
            )
            item.add_argument("--profile", required=True, type=Path)
        args = parser.parse_args(argv)
        STAGE = "preflight"
        profile = load_profile(args.profile)
        _runtime_guard(profile.document["argv"][0])
        if args.command == "preflight":
            emit({"code": "LEGACY_RECOVERY_PREFLIGHT_READY", "status": "ready"})
            return 0
        STAGE = "run"
        run_profile(args.profile)
        emit({"code": "LEGACY_RECOVERY_COMPLETE", "status": "complete"})
        return 0
    except BaseException:
        emit({"code": "LEGACY_RECOVERY_FAILED", "stage": STAGE, "status": "failed"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["LoadedProfile", "load_profile", "run_profile"]
