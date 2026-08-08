from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import ModuleType
import unittest
from unittest import mock


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "reviewer_upgrade_legacy_profile.py"
)
SPEC = importlib.util.spec_from_file_location("legacy_profile_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROFILE = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = PROFILE
SPEC.loader.exec_module(PROFILE)


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"


def journal_canonical(value: object) -> bytes:
    return canonical(value)[:-1]


class LegacyProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        # The production runner starts under isolated Python and deliberately
        # refuses a process that has already imported any profiled legacy
        # module.  The repository-wide suite imports several of those modules
        # in earlier test files, so preserve and temporarily remove them to
        # model the real one-shot process without weakening the runtime guard.
        self.previous_profiled_modules = {
            name: sys.modules.pop(name, None)
            for name in PROFILE.REQUIRED_MODULES
        }
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.profile_directory = self.root / "profile"
        self.profile_directory.mkdir(mode=0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.upgrades = self.state / "upgrades"
        self.upgrades.mkdir(mode=0o700)
        self.transaction = self.upgrades / "legacy-operation"
        self.transaction.mkdir(mode=0o700)
        self.unit_directory = self.root / "units"
        self.unit_directory.mkdir(mode=0o700)
        self.operation = self.root / "operation"
        self.operation.mkdir(mode=0o700)
        self.closure = self.root / "closure"
        scripts = self.closure / "services" / "backend" / "scripts"
        scripts.mkdir(parents=True, mode=0o700)
        module_sources = {
            "reconcile_compose_deployment": b'''from pathlib import Path\nimport verify_tailnet_private_pilot\nfrom tacua_backend import config, contracts, instance_lock, operator_tool\nclass ReconcileError(RuntimeError):\n    def __init__(self, code):\n        super().__init__(code)\n        self.code = code\ndef _atomic_private_write(*args, **kwargs):\n    raise AssertionError("legacy writer was not patched")\n''',
            "reviewer_upgrade_finalize": b'''import reconcile_compose_deployment as reconciler\n''',
            "reviewer_upgrade_transaction": b'''from pathlib import Path\nimport reconcile_compose_deployment as reconciler\nimport reviewer_upgrade_backup as backup\nimport reviewer_upgrade_backup_docker as backup_docker\nimport reviewer_upgrade_finalize as finalize\nimport reviewer_upgrade_journal as journal\nimport reviewer_upgrade_manager as manager\nimport reviewer_upgrade_systemd as upgrade_systemd\nimport reviewer_upgrade_unit_artifacts as unit_artifacts\ndef resume(state_parent, *, serial_lock_file, unit_directory, lock_file, operation_directory):\n    reconciler._atomic_private_write(Path(state_parent) / "activation.json", b"{}\\n", replace=False)\n    return {"code":"REVIEWER_UPGRADE_COMPLETE","operation_id":"private","phase":"complete","status":"complete"}\n''',
        }
        for name, relative in PROFILE.MODULE_RELATIVE_PATHS.items():
            source = module_sources.get(name, b"VALUE = 1\n")
            path = self.closure / relative
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.write_bytes(source)
            path.chmod(0o444)
        for directory in sorted(
            [item for item in self.closure.rglob("*") if item.is_dir()],
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        self.closure.chmod(0o555)

        self.fragment = self.unit_directory / PROFILE.STABLE_UNIT
        self.fragment.write_bytes(b"[Service]\n")
        self.fragment.chmod(0o600)
        self.serial = self.root / "serial.lock"
        self.lock = self.root / "compose.lock"
        for path in (self.serial, self.lock):
            path.write_bytes(b"")
            path.chmod(0o600)
        self.active = self.upgrades / "active.json"
        self.plan = self.transaction / "plan.json"
        self.progress = self.transaction / "progress.json"
        self.desired = self.state / "desired-state.json"
        documents = {
            self.active: {
                "operation_id": "legacy-operation",
                "plan_digest": "sha256:" + "1" * 64,
            },
            self.plan: {
                "plan": {
                    "candidate_repository_root": str(self.closure),
                    "source_state_directory": str(self.state),
                },
                "plan_digest": "sha256:" + "1" * 64,
            },
            self.progress: {
                "details": {"gate_state": "inhibitor_ready"},
                "phase": "quiescing",
                "plan_digest": "sha256:" + "1" * 64,
                "sequence": 3,
            },
            self.desired: {"desired": "running"},
        }
        for path, document in documents.items():
            path.write_bytes(journal_canonical(document))
            path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()
        for name in PROFILE.REQUIRED_MODULES:
            sys.modules.pop(name, None)
        for name, module in self.previous_profiled_modules.items():
            if module is not None:
                sys.modules[name] = module

    @staticmethod
    def binding(path: Path) -> dict:
        payload, item = PROFILE._read_regular(
            path,
            mode=stat.S_IMODE(path.stat().st_mode),
            maximum=PROFILE.MAX_FILE_BYTES,
        )
        return PROFILE._binding(path, payload, item)

    def make_profile(self) -> Path:
        profile_path = self.profile_directory / "profile.json"
        modules = dict(PROFILE.MODULE_RELATIVE_PATHS)
        closure = {
            relative: self.binding(self.closure / relative)
            for relative in modules.values()
        }
        transaction = self.closure / modules["reviewer_upgrade_transaction"]
        argv = [
            "/usr/bin/python3",
            "-B",
            str(transaction),
            "resume",
            "--state-parent",
            str(self.state),
            "--serial-lock-file",
            str(self.serial),
            "--unit-directory",
            str(self.unit_directory),
            "--lock-file",
            str(self.lock),
            "--operation-directory",
            str(self.operation),
        ]
        sandbox = {
            "path_unit": {
                "ActiveState": "failed",
                "Job": "",
                "SubState": "failed",
                "name": PROFILE.PATH_UNIT,
            },
            "read_only_paths": [str(transaction), str(self.closure)],
            "read_write_paths": list(argv[5::2]),
            "stable_unit": {
                "ActiveState": "failed",
                "DropInPaths": "",
                "ExecMainStatus": "78",
                "Job": "",
                "NeedDaemonReload": "no",
                "Result": "exit-code",
                "SubState": "failed",
                "name": PROFILE.STABLE_UNIT,
            },
        }
        writer = SCRIPT.with_name("reviewer_upgrade_legacy_recovery.py")
        document = {
            "argv": argv,
            "closure": closure,
            "closure_root": str(self.closure),
            "contract_version": PROFILE.CONTRACT,
            "evidence": {
                "activation": {
                    "parent": str(self.state),
                    "path": str(self.state / "activation.json"),
                },
                "active": self.binding(self.active),
                "desired": self.binding(self.desired),
                "plan": self.binding(self.plan),
                "progress": self.binding(self.progress),
            },
            "fragment": self.binding(self.fragment),
            "marker_path": str(self.profile_directory / "run.once"),
            "modules": modules,
            "profile_digest": "",
            "profile_path": str(profile_path),
            "sandbox": sandbox,
            "sandbox_digest": PROFILE._digest(canonical(sandbox)),
            "tools": {
                "python": {"launch_path": argv[0], "file": {}},
                "systemctl": {"launch_path": str(PROFILE.SYSTEMCTL), "file": {}},
                "systemd_run": {"launch_path": str(PROFILE.SYSTEMD_RUN), "file": {}},
            },
            "wrapper": self.binding(SCRIPT),
            "writer": self.binding(writer),
        }
        document["profile_digest"] = PROFILE._document_digest(
            document,
            "profile_digest",
        )
        profile_path.write_bytes(canonical(document))
        profile_path.chmod(0o400)
        return profile_path

    @staticmethod
    def rewrite_profile(profile_path: Path, change) -> None:
        document = json.loads(profile_path.read_text(encoding="ascii"))
        change(document)
        document["profile_digest"] = PROFILE._document_digest(
            document,
            "profile_digest",
        )
        profile_path.chmod(0o600)
        profile_path.write_bytes(canonical(document))
        profile_path.chmod(0o400)

    def test_preflight_binds_canonical_profile_and_all_evidence(self) -> None:
        profile_path = self.make_profile()
        with mock.patch.object(PROFILE, "_root_tool", return_value=None):
            loaded = PROFILE.load_profile(profile_path)
        self.assertEqual(loaded.path, profile_path)
        self.assertEqual(set(loaded.sources), set(loaded.document["closure"]))

    def test_tampered_progress_is_rejected(self) -> None:
        profile_path = self.make_profile()
        self.progress.write_bytes(canonical({"phase": "complete"}))
        with mock.patch.object(PROFILE, "_root_tool", return_value=None):
            with self.assertRaises(PROFILE.ProfileError):
                PROFILE.load_profile(profile_path)

    def test_run_patches_shared_reconciler_and_is_one_shot(self) -> None:
        profile_path = self.make_profile()
        with mock.patch.object(PROFILE, "_root_tool", return_value=None), mock.patch.object(
            PROFILE, "_runtime_guard", return_value=None
        ):
            PROFILE.run_profile(profile_path)
            self.assertEqual((self.state / "activation.json").read_bytes(), b"{}\n")
            with self.assertRaises(PROFILE.ProfileError):
                PROFILE.run_profile(profile_path)

    def test_preflight_refuses_existing_marker_and_partial_writes_are_completed(self) -> None:
        profile_path = self.make_profile()
        with mock.patch.object(PROFILE, "_root_tool", return_value=None):
            loaded = PROFILE.load_profile(profile_path)
            original_write = os.write

            def one_byte(descriptor, payload):
                return original_write(descriptor, payload[:1])

            with mock.patch.object(PROFILE.os, "write", side_effect=one_byte):
                PROFILE._create_marker(loaded)
            with self.assertRaises(PROFILE.ProfileError):
                PROFILE.load_profile(profile_path)
        marker = self.profile_directory / "run.once"
        self.assertGreater(marker.stat().st_size, 1)
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o400)

    def test_wrapper_binding_cannot_be_redirected(self) -> None:
        profile_path = self.make_profile()
        alternate = self.root / "alternate.py"
        alternate.write_bytes(b"pass\n")
        alternate.chmod(0o600)
        self.rewrite_profile(
            profile_path,
            lambda document: document.__setitem__("wrapper", self.binding(alternate)),
        )
        with mock.patch.object(PROFILE, "_root_tool", return_value=None):
            with self.assertRaises(PROFILE.ProfileError):
                PROFILE.load_profile(profile_path)

    def test_preloaded_legacy_module_consumes_marker_without_import(self) -> None:
        profile_path = self.make_profile()
        sys.modules["reconcile_compose_deployment"] = ModuleType(
            "reconcile_compose_deployment"
        )
        try:
            with mock.patch.object(PROFILE, "_root_tool", return_value=None), mock.patch.object(
                PROFILE, "_runtime_guard", return_value=None
            ):
                with self.assertRaises(PROFILE.ProfileError):
                    PROFILE.run_profile(profile_path)
        finally:
            sys.modules.pop("reconcile_compose_deployment", None)
        self.assertTrue((self.profile_directory / "run.once").is_file())
        self.assertFalse((self.state / "activation.json").exists())

    def test_argument_errors_emit_only_fixed_result(self) -> None:
        emitted = []
        with mock.patch.object(PROFILE, "emit", side_effect=emitted.append):
            result = PROFILE.main(["run", "--unexpected", "/private/value"])
        self.assertEqual(result, 1)
        self.assertEqual(
            emitted,
            [
                {
                    "code": "LEGACY_RECOVERY_FAILED",
                    "stage": "parse",
                    "status": "failed",
                }
            ],
        )

    def test_evidence_cannot_be_rebound_to_byte_identical_decoy(self) -> None:
        profile_path = self.make_profile()
        decoy = self.root / "decoy-active.json"
        decoy.write_bytes(self.active.read_bytes())
        decoy.chmod(0o600)
        self.rewrite_profile(
            profile_path,
            lambda document: document["evidence"].__setitem__(
                "active",
                self.binding(decoy),
            ),
        )
        with mock.patch.object(PROFILE, "_root_tool", return_value=None):
            with self.assertRaises(PROFILE.ProfileError):
                PROFILE.load_profile(profile_path)

    def test_root_owned_python_symlink_or_regular_launcher_is_accepted(self) -> None:
        launch = Path("/usr/bin/python3")
        resolved = launch.resolve(strict=True)
        item = resolved.stat()
        payload = resolved.read_bytes()
        value = {
            "launch_path": str(launch),
            "file": PROFILE._binding(resolved, payload, item),
        }
        with mock.patch.object(
            PROFILE,
            "_read_regular",
            return_value=(payload, item),
        ):
            PROFILE._root_tool(value, launch)

    def test_unprofiled_legacy_import_is_blocked_before_resume(self) -> None:
        transaction_path = self.closure / PROFILE.MODULE_RELATIVE_PATHS[
            "reviewer_upgrade_transaction"
        ]
        transaction_path.chmod(0o600)
        transaction_path.write_bytes(
            b"import reviewer_upgrade_unprofiled\n"
            + transaction_path.read_bytes()
        )
        transaction_path.chmod(0o444)
        scripts = transaction_path.parent
        scripts.chmod(0o755)
        unprofiled = scripts / "reviewer_upgrade_unprofiled.py"
        unprofiled.write_bytes(b"raise AssertionError('must not execute')\n")
        unprofiled.chmod(0o444)
        scripts.chmod(0o555)
        profile_path = self.make_profile()
        with mock.patch.object(PROFILE, "_root_tool", return_value=None), mock.patch.object(
            PROFILE, "_runtime_guard", return_value=None
        ):
            with self.assertRaises(ImportError):
                PROFILE.run_profile(profile_path)
        self.assertFalse((self.state / "activation.json").exists())


if __name__ == "__main__":
    unittest.main()
