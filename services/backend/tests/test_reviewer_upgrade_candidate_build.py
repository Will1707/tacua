# SPDX-License-Identifier: Apache-2.0
"""No-daemon contracts for the prepared-release producer."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services/backend/scripts"
sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_candidate_build as BUILD  # noqa: E402


IMAGE_ID = "sha256:" + "a" * 64


class FakeRunner:
    def __init__(self, responses=None, effects=None):
        self.responses = dict(responses or {})
        self.effects = dict(effects or {})
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        label = kwargs["label"]
        if label in self.effects:
            self.effects[label](argv, kwargs)
        value = self.responses.get(label, BUILD.CommandResult())
        if callable(value):
            value = value(argv, kwargs)
        return value


class CandidateBuildContractTests(unittest.TestCase):
    def _fixture(self, base: Path) -> BUILD.BuildInputs:
        base = base.resolve()
        if not base.exists():
            base.mkdir(mode=0o700)
        base.chmod(0o700)
        installed = base / "installed"
        state = base / "state"
        preparations = base / "preparations"
        binary = base / "bin"
        for directory in (installed, state, preparations, binary):
            directory.mkdir(mode=0o700)
        tools = {}
        for name in ("git", "python3", "node", "docker", "bash"):
            path = binary / name
            path.write_bytes(b"#!/bin/sh\nexit 0\n")
            path.chmod(0o700)
            tools[name] = path
        npm_cli = binary / "npm-cli.js"
        npm_cli.write_bytes(b"process.exit(0);\n")
        npm_cli.chmod(0o600)
        return BUILD.BuildInputs(
            installed_repository=installed,
            installed_commit="1" * 40,
            candidate_commit="2" * 40,
            source_state_directory=state,
            preparations_parent=preparations,
            repository_identity="Will1707/tacua",
            git=tools["git"],
            python=tools["python3"],
            node=tools["node"],
            npm_cli=npm_cli,
            docker=tools["docker"],
            bash=tools["bash"],
            command_path=str(binary),
        )

    def _release_fixture(self, base: Path):
        base = base.resolve()
        base.mkdir(mode=0o700)
        inputs = self._fixture(base / "fixture")
        attempts = inputs.preparations_parent / BUILD.ATTEMPTS_DIRECTORY
        releases = inputs.preparations_parent / BUILD.RELEASES_DIRECTORY
        attempts.mkdir(mode=0o700)
        releases.mkdir(mode=0o700)
        attempt, attempt_number = BUILD._allocate_attempt(attempts, inputs)
        checkout = attempt / "fixture-checkout"
        index = write_required_runtime_tree(checkout)
        ingress = checkout / "services/backend/ingress/haproxy.cfg"
        staged = attempt / BUILD.STAGED_RELEASE_DIRECTORY
        staged.mkdir(mode=0o700)
        records = BUILD._materialize_source(
            checkout,
            staged / BUILD.candidate.SOURCE_DIRECTORY,
            index,
        )
        manifest = BUILD._source_manifest(inputs, records)
        old_root = inputs.installed_repository
        old_ingress = old_root / "services/backend/ingress/haproxy.cfg"
        old_ingress.parent.mkdir(parents=True, mode=0o700)
        old_ingress.write_bytes(ingress.read_bytes())
        old_ingress.chmod(0o644)
        source_document = {
            "configs": {
                "tacua_loopback_ingress": {"file": str(old_ingress)}
            },
            "services": {
                "backend": {
                    "build": {"context": str(old_root)},
                    "image": "tacua-backend:old",
                },
                "reviewer": {
                    "build": {"context": str(old_root)},
                    "image": "tacua-reviewer-web:old",
                },
            },
        }
        source_compose = base / "source-compose.json"
        source_payload = BUILD._canonical_json(source_document)
        source_compose.write_bytes(source_payload)
        source_compose.chmod(0o400)
        return {
            "attempt": attempt,
            "attempt_number": attempt_number,
            "inputs": inputs,
            "manifest": manifest,
            "releases": releases,
            "source_compose": source_compose,
            "source_document": source_document,
            "source_payload": source_payload,
            "staged": staged,
        }

    def test_module_imports(self) -> None:
        self.assertEqual(BUILD.BUILD_CODE, "REVIEWER_UPGRADE_CANDIDATE_BUILT")

    def test_build_inputs_accept_exact_private_paths_and_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._fixture(Path(temporary))

            self.assertIs(inputs.validate(), inputs)
            self.assertEqual(
                inputs.repository_url,
                "https://github.com/Will1707/tacua.git",
            )
            self.assertEqual(
                inputs.installed_origin_urls,
                {
                    "https://github.com/Will1707/tacua.git",
                    "git@github.com:Will1707/tacua.git",
                    "ssh://git@github.com/Will1707/tacua.git",
                },
            )

    def test_build_inputs_reject_same_or_noncanonical_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._fixture(Path(temporary))
            for changes in (
                {"candidate_commit": inputs.installed_commit},
                {"candidate_commit": "A" * 40},
                {"repository_identity": "https://github.com/Will1707/tacua"},
            ):
                with self.subTest(changes=changes), self.assertRaises(
                    BUILD.CandidateBuildError
                ):
                    BUILD.BuildInputs(
                        **{**inputs.__dict__, **changes}
                    ).validate()

    def test_build_inputs_reject_links_hardlinks_and_writable_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base)
            linked = base / "linked-git"
            linked.symlink_to(inputs.git)
            hard = base / "hard-git"
            os.link(inputs.git, hard)
            writable = base / "writable-git"
            writable.write_bytes(inputs.git.read_bytes())
            writable.chmod(0o722)
            for path in (linked, hard, writable):
                with self.subTest(path=path), self.assertRaises(
                    BUILD.CandidateBuildError
                ):
                    BUILD._canonical_tool(path, executable=True)

    def test_build_inputs_reject_nonprivate_preparation_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._fixture(Path(temporary))
            inputs.preparations_parent.chmod(0o750)

            with self.assertRaises(BUILD.CandidateBuildError):
                inputs.validate()

    def test_nonprivate_command_path_accepts_root_owned_system_directory(self) -> None:
        system = Path("/usr/bin")
        if not system.is_dir() or system.resolve() != system:
            self.skipTest("canonical /usr/bin is unavailable")
        self.assertEqual(BUILD._canonical_directory(system, private=False), system)
        with self.assertRaises(BUILD.CandidateBuildError):
            BUILD._canonical_directory(system, private=True)

    def test_command_path_must_resolve_exact_canonical_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base)
            earlier = base / "earlier"
            earlier.mkdir(mode=0o700)
            false_docker = earlier / "docker"
            false_docker.write_bytes(b"#!/bin/sh\nexit 0\n")
            false_docker.chmod(0o700)
            changed = BUILD.BuildInputs(
                **{
                    **inputs.__dict__,
                    "command_path": f"{earlier}{os.pathsep}{inputs.command_path}",
                }
            )

            with self.assertRaises(BUILD.CandidateBuildError):
                changed.validate()

    def test_restricted_diff_accepts_only_reviewer_and_upgrade_boundary(self) -> None:
        payload = b"\0".join(
            (
                b"apps/reviewer/src/app.tsx",
                b"services/reviewer-web/server.py",
                b"services/backend/scripts/reviewer_upgrade_candidate.py",
                b"services/backend/scripts/reconcile_compose_deployment.py",
                b"services/backend/systemd/tacua-reviewer-upgrade-resume.service.in",
                b"services/backend/OPERATIONS.md",
                b"",
            )
        )

        self.assertEqual(
            len(
                BUILD._validate_restricted_diff(
                    payload,
                    installed_commit="b" * 40,
                )
            ),
            6,
        )

    def test_restricted_diff_rejects_sensitive_and_non_reviewer_changes(self) -> None:
        forbidden = (
            "services/backend/src/tacua_backend/service.py",
            "services/backend/compose.yaml",
            "services/backend/Dockerfile",
            "services/reviewer-web/Dockerfile",
            "services/backend/ingress/haproxy.cfg",
            "contracts/runtime/schemas/session.schema.json",
            "packages/mobile-sdk/src/index.ts",
            ".github/workflows/verify.yml",
        )
        for value in forbidden:
            payload = f"apps/reviewer/src/app.tsx\0{value}\0".encode()
            with self.subTest(value=value), self.assertRaises(
                BUILD.CandidateBuildError
            ):
                BUILD._validate_restricted_diff(
                    payload,
                    installed_commit="b" * 40,
                )

    def test_restricted_diff_allows_host_upgrade_only_candidate(self) -> None:
        self.assertEqual(
            BUILD._validate_restricted_diff(
                b"services/backend/scripts/reviewer_upgrade_candidate.py\0",
                installed_commit="b" * 40,
            ),
            ("services/backend/scripts/reviewer_upgrade_candidate.py",),
        )

    def test_restricted_diff_pilot_baseline_exception_is_commit_and_path_exact(
        self,
    ) -> None:
        self.assertEqual(len(BUILD._PILOT_BASELINE_ALLOWED_EXACT), 15)
        for path in sorted(BUILD._PILOT_BASELINE_ALLOWED_EXACT):
            payload = f"{path}\0".encode("utf-8")
            with self.subTest(path=path, policy="pilot-baseline"):
                self.assertEqual(
                    BUILD._validate_restricted_diff(
                        payload,
                        installed_commit=BUILD._PILOT_BASELINE_COMMIT,
                    ),
                    (path,),
                )
            with (
                self.subTest(path=path, policy="future-installation"),
                self.assertRaises(BUILD.CandidateBuildError),
            ):
                BUILD._validate_restricted_diff(
                    payload,
                    installed_commit="b" * 40,
                )

        for path in (
            "experiments/ios-capture-spike/scripts/unreviewed.py",
            ".github/workflows/unreviewed.yml",
            "packages/mobile-sdk/src/index.ts",
        ):
            with self.subTest(path=path), self.assertRaises(
                BUILD.CandidateBuildError
            ):
                BUILD._validate_restricted_diff(
                    f"{path}\0".encode("utf-8"),
                    installed_commit=BUILD._PILOT_BASELINE_COMMIT,
                )

        with self.assertRaises(BUILD.CandidateBuildError):
            BUILD._validate_restricted_diff(
                b"services/backend/scripts/reviewer_upgrade_candidate.py\0",
                installed_commit="invalid",
            )

    def test_restricted_diff_rejects_malformed_duplicate_and_traversal(self) -> None:
        for payload in (
            b"apps/reviewer/src/app.tsx",
            b"apps/reviewer/src/app.tsx\0apps/reviewer/src/app.tsx\0",
            b"apps/reviewer/../secret\0",
            b"apps/reviewer/src/line\nname\0",
            b"\xff\0",
        ):
            with self.subTest(payload=payload), self.assertRaises(
                BUILD.CandidateBuildError
            ):
                BUILD._validate_restricted_diff(
                    payload,
                    installed_commit="b" * 40,
                )

    def test_subprocess_runner_has_no_shell_no_stdin_and_private_logs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            base.chmod(0o700)
            logs = base / "logs"
            logs.mkdir(mode=0o700)
            executable = base / "tool"
            executable.write_bytes(
                b"#!/bin/sh\nprintf 'bounded stdout'\nprintf 'bounded stderr' >&2\n"
            )
            executable.chmod(0o700)
            real_popen = BUILD.subprocess.Popen
            with mock.patch.object(
                BUILD.subprocess,
                "Popen",
                wraps=real_popen,
            ) as popen:
                result = BUILD.SubprocessRunner(logs)(
                    [str(executable), "argument"],
                    cwd=base,
                    env={"LC_ALL": "C"},
                    timeout=1,
                    label="unit-command",
                )

            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"bounded stdout")
            self.assertEqual(result.stderr, b"bounded stderr")
            kwargs = popen.call_args.kwargs
            self.assertIs(kwargs["stdin"], BUILD.subprocess.DEVNULL)
            self.assertIs(kwargs["shell"], False)
            self.assertIs(kwargs["start_new_session"], True)
            self.assertIs(kwargs["stdout"], BUILD.subprocess.PIPE)
            self.assertIs(kwargs["stderr"], BUILD.subprocess.PIPE)
            self.assertEqual(kwargs["bufsize"], 0)
            self.assertEqual(kwargs["umask"], BUILD.VERIFICATION_CHILD_UMASK)
            self.assertNotIn("preexec_fn", kwargs)
            modes = {
                stat.S_IMODE(path.stat().st_mode)
                for path in logs.iterdir()
            }
            self.assertEqual(modes, {0o600})

    def test_subprocess_runner_scopes_container_readable_umask_to_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            base.chmod(0o700)
            logs = base / "logs"
            logs.mkdir(mode=0o700)
            output = base / "export"
            executable = base / "export-tool"
            executable.write_bytes(
                b"#!/bin/sh\n"
                b"mkdir \"$1\"\n"
                b"printf artifact > \"$1/index.html\"\n"
            )
            executable.chmod(0o700)

            previous_umask = os.umask(BUILD.PRIVATE_PROCESS_UMASK)
            try:
                result = BUILD.SubprocessRunner(logs)(
                    [str(executable), str(output)],
                    cwd=base,
                    env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                    timeout=1,
                    label="readable-export",
                    umask=BUILD.VERIFICATION_CHILD_UMASK,
                )
                observed_parent_umask = os.umask(BUILD.PRIVATE_PROCESS_UMASK)
            finally:
                os.umask(previous_umask)

            self.assertEqual(result.returncode, 0)
            self.assertEqual(observed_parent_umask, BUILD.PRIVATE_PROCESS_UMASK)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o755)
            self.assertEqual(
                stat.S_IMODE((output / "index.html").stat().st_mode),
                0o644,
            )
            self.assertEqual(
                {stat.S_IMODE(path.stat().st_mode) for path in logs.iterdir()},
                {0o600},
            )

    def test_subprocess_runner_rejects_unapproved_child_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            base.chmod(0o700)
            logs = base / "logs"
            logs.mkdir(mode=0o700)
            with self.assertRaises(BUILD.CandidateBuildError) as raised:
                BUILD.SubprocessRunner(logs)(
                    ["/bin/true"],
                    cwd=base,
                    env={"LC_ALL": "C"},
                    timeout=1,
                    label="invalid-umask",
                    umask=0,
                )

            self.assertEqual(
                raised.exception.code,
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_INVALID",
            )

    def test_subprocess_runner_kills_noisy_process_before_logs_exceed_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            base.chmod(0o700)
            logs = base / "logs"
            logs.mkdir(mode=0o700)
            executable = base / "noisy-tool"
            executable.write_bytes(
                b"#!/bin/sh\n"
                b"trap '' TERM\n"
                b"while :; do printf '0123456789abcdef'; done\n"
            )
            executable.chmod(0o700)

            started = time.monotonic()
            with (
                mock.patch.object(BUILD, "MAX_COMMAND_OUTPUT_BYTES", 128),
                mock.patch.object(BUILD, "TERMINATION_GRACE_SECONDS", 0.1),
                mock.patch.object(BUILD, "TERMINATION_KILL_WAIT_SECONDS", 0.5),
                self.assertRaises(BUILD.CandidateBuildError) as raised,
            ):
                BUILD.SubprocessRunner(logs)(
                    [str(executable)],
                    cwd=base,
                    env={"LC_ALL": "C"},
                    timeout=2,
                    label="noisy-command",
                )

            self.assertEqual(
                raised.exception.code,
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED",
            )
            self.assertLess(time.monotonic() - started, 5)
            self.assertTrue(tuple(logs.iterdir()))
            self.assertTrue(all(path.stat().st_size <= 128 for path in logs.iterdir()))

    def test_subprocess_timeout_allows_bounded_exit_trap_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            base.chmod(0o700)
            logs = base / "logs"
            logs.mkdir(mode=0o700)
            marker = base / "cleanup-complete"
            executable = base / "trapped-tool"
            executable.write_bytes(
                b"#!/bin/sh\n"
                b"marker=$1\n"
                b"trap 'printf cleanup > \"$marker\"; exit 0' TERM\n"
                b"while :; do sleep 1; done\n"
            )
            executable.chmod(0o700)

            with (
                mock.patch.object(BUILD, "TERMINATION_GRACE_SECONDS", 2.0),
                self.assertRaises(BUILD.CandidateBuildError) as raised,
            ):
                BUILD.SubprocessRunner(logs)(
                    [str(executable), str(marker)],
                    cwd=base,
                    env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                    timeout=0.5,
                    label="trapped-command",
                )

            self.assertEqual(
                raised.exception.code,
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_COMMAND_FAILED",
            )
            self.assertEqual(marker.read_bytes(), b"cleanup")
            self.assertTrue(all(path.stat().st_size <= BUILD.MAX_COMMAND_OUTPUT_BYTES for path in logs.iterdir()))

    def test_command_validation_rejects_relative_binary_and_unbounded_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary).resolve()
            for argv, timeout in ((["git"], 1), (["/bin/echo"], 3_601)):
                with self.subTest(argv=argv), self.assertRaises(
                    BUILD.CandidateBuildError
                ):
                    BUILD._validate_command(
                        argv,
                        cwd=cwd,
                        env={"LC_ALL": "C"},
                        timeout=timeout,
                        label="invalid",
                    )

    def test_git_index_parser_accepts_only_sorted_regular_git_files(self) -> None:
        payload = (
            b"100644 " + b"a" * 40 + b" 0\tREADME.md\0"
            b"100755 " + b"b" * 40 + b" 0\tservices/backend/scripts/tool.py\0"
        )

        self.assertEqual(
            BUILD._parse_git_index(payload),
            (
                ("README.md", 0o444),
                ("services/backend/scripts/tool.py", 0o555),
            ),
        )

    def test_git_index_parser_rejects_links_submodules_outputs_and_unsorted(self) -> None:
        sha = b"a" * 40
        for payload in (
            b"120000 " + sha + b" 0\tlink\0",
            b"160000 " + sha + b" 0\tsubmodule\0",
            b"100644 " + sha + b" 0\t.git/config\0",
            b"100644 " + sha + b" 0\tb\0" + b"100644 " + sha + b" 0\ta\0",
            b"100644 " + sha + b" 1\tconflict\0",
        ):
            with self.subTest(payload=payload), self.assertRaises(
                BUILD.CandidateBuildError
            ):
                BUILD._parse_git_index(payload)

    def test_materialized_source_is_exact_read_only_and_has_no_git_indirection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            checkout = base / "checkout"
            checkout.mkdir(mode=0o700)
            (checkout / ".git").mkdir(mode=0o700)
            (checkout / "README.md").write_text("read me\n")
            script = checkout / "services/backend/scripts/tool.py"
            script.parent.mkdir(parents=True, mode=0o700)
            script.write_text("print('safe')\n")
            source = base / "source"

            records = BUILD._materialize_source(
                checkout,
                source,
                (
                    ("README.md", 0o444),
                    ("services/backend/scripts/tool.py", 0o555),
                ),
            )

            self.assertEqual([record["path"] for record in records], [
                "README.md",
                "services/backend/scripts/tool.py",
            ])
            self.assertFalse((source / ".git").exists())
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((source / "README.md").stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE((source / "services/backend/scripts/tool.py").stat().st_mode), 0o555)
            manifest = BUILD._source_manifest(
                self._fixture(base / "fixture"),
                records,
            )
            self.assertEqual(
                manifest["runtime_closure"]["files"],
                [record["path"] for record in records],
            )
            self.assertEqual(
                manifest["runtime_closure"]["closure_digest"],
                manifest["tree_digest"],
            )

    def test_candidate_compose_changes_only_image_and_authority_paths(self) -> None:
        old_root = Path("/srv/tacua/current")
        new_root = Path("/srv/tacua/preparations/releases") / ("a" * 64) / "source"
        source = {
            "services": {
                "backend": {"build": {"context": str(old_root)}, "image": "backend:old"},
                "reviewer": {
                    "build": {"context": str(old_root)},
                    "image": "tacua-reviewer-web:old",
                },
            },
            "configs": {
                "tacua_loopback_ingress": {
                    "file": str(old_root / "services/backend/ingress/haproxy.cfg")
                }
            },
            "x-extension": {"unchanged": True},
        }

        result = BUILD._candidate_compose(
            source,
            source_authority=old_root,
            source_repository=new_root,
            reviewer_image="tacua-reviewer-web:qa-candidate",
        )

        self.assertEqual(result["services"]["reviewer"]["image"], "tacua-reviewer-web:qa-candidate")
        self.assertEqual(result["services"]["backend"]["build"]["context"], str(new_root))
        self.assertEqual(result["services"]["reviewer"]["build"]["context"], str(new_root))
        self.assertEqual(
            result["configs"]["tacua_loopback_ingress"]["file"],
            str(new_root / "services/backend/ingress/haproxy.cfg"),
        )
        self.assertEqual(result["x-extension"], source["x-extension"])
        self.assertEqual(source["services"]["reviewer"]["image"], "tacua-reviewer-web:old")

    def test_candidate_compose_allows_absent_builds_but_rejects_split_authority(self) -> None:
        root = Path("/srv/tacua/current")
        source = {
            "services": {
                "backend": {"image": "backend:old"},
                "reviewer": {"image": "tacua-reviewer-web:old"},
            },
            "configs": {
                "tacua_loopback_ingress": {
                    "file": str(root / "services/backend/ingress/haproxy.cfg")
                }
            },
        }
        result = BUILD._candidate_compose(
            source,
            source_authority=root,
            source_repository=Path("/sealed/source"),
            reviewer_image="tacua-reviewer-web:new",
        )
        self.assertNotIn("build", result["services"]["backend"])
        changed = json_clone(source)
        changed["services"]["backend"]["build"] = {"context": "/other/root"}
        with self.assertRaises(BUILD.CandidateBuildError):
            BUILD._candidate_compose(
                changed,
                source_authority=root,
                source_repository=Path("/sealed/source"),
                reviewer_image="tacua-reviewer-web:new",
            )

    def test_source_authority_accepts_initial_checkout_and_exact_prior_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._release_fixture(Path(temporary).resolve() / "case")
            inputs = fixture["inputs"]

            self.assertEqual(
                BUILD._source_authority(inputs, fixture["source_document"]),
                inputs.installed_repository,
            )
            prior = BUILD._publish_release(
                inputs,
                fixture["attempt"],
                fixture["attempt_number"],
                fixture["staged"],
                fixture["releases"],
                fixture["manifest"],
                fixture["source_compose"],
                fixture["source_payload"],
                fixture["source_document"],
                inputs.installed_repository,
                "tacua-reviewer-web:qa-fixture-000001",
                IMAGE_ID,
                BUILD._tool_bindings(inputs),
                [],
            )
            next_inputs = BUILD.BuildInputs(
                **{
                    **inputs.__dict__,
                    "installed_commit": inputs.candidate_commit,
                    "candidate_commit": "3" * 40,
                }
            )
            next_source = json_clone(fixture["source_document"])
            for service in ("backend", "reviewer"):
                next_source["services"][service]["build"]["context"] = str(
                    prior.repository
                )
            next_source["configs"]["tacua_loopback_ingress"]["file"] = str(
                prior.repository / "services/backend/ingress/haproxy.cfg"
            )

            self.assertEqual(
                BUILD._source_authority(next_inputs, next_source),
                prior.repository,
            )
            wrong_lineage = BUILD.BuildInputs(
                **{**next_inputs.__dict__, "installed_commit": "4" * 40}
            )
            with self.assertRaises(BUILD.CandidateBuildError):
                BUILD._source_authority(wrong_lineage, next_source)

    def test_source_authority_rejects_unmanaged_compose_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            unmanaged = base / "unmanaged"
            source = {
                "configs": {
                    "tacua_loopback_ingress": {
                        "file": str(
                            unmanaged / "services/backend/ingress/haproxy.cfg"
                        )
                    }
                },
                "services": {
                    "backend": {"image": "backend:old"},
                    "reviewer": {"image": "tacua-reviewer-web:old"},
                },
            }

            with self.assertRaises(BUILD.CandidateBuildError) as raised:
                BUILD._source_authority(inputs, source)
            self.assertEqual(
                raised.exception.code,
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID",
            )

    def test_initial_git_authority_cannot_squat_below_managed_releases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            squatting = (
                inputs.preparations_parent
                / BUILD.RELEASES_DIRECTORY
                / ("a" * 64)
                / BUILD.candidate.SOURCE_DIRECTORY
            )
            changed_inputs = BUILD.BuildInputs(
                **{**inputs.__dict__, "installed_repository": squatting}
            )
            source = {
                "configs": {
                    "tacua_loopback_ingress": {
                        "file": str(
                            squatting / "services/backend/ingress/haproxy.cfg"
                        )
                    }
                },
                "services": {
                    "backend": {"build": {"context": str(squatting)}},
                    "reviewer": {
                        "build": {"context": str(squatting)},
                        "image": "tacua-reviewer-web:old",
                    },
                },
            }

            with self.assertRaises(BUILD.CandidateBuildError) as raised:
                BUILD._source_authority(changed_inputs, source)
            self.assertEqual(
                raised.exception.code,
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_SOURCE_INVALID",
            )

    def test_verification_command_order_environment_and_no_live_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            attempt = base / "attempt"
            checkout = attempt / BUILD.BUILD_SOURCE_DIRECTORY
            checkout.mkdir(parents=True, mode=0o700)
            home = base / "home"
            runtime = base / "xdg"
            home.mkdir(mode=0o700)
            runtime.mkdir(mode=0o700)
            manifest = {
                "commands": {"docker": str(inputs.docker)},
                "runtime": {
                    "docker_host": "unix:///private/docker.sock",
                    "home": str(home),
                    "xdg_runtime_directory": str(runtime),
                },
            }
            runner = FakeRunner(
                {
                    "node-version": BUILD.CommandResult(0, b"v22.22.2\n"),
                    "npm-version": BUILD.CommandResult(0, b"10.9.4\n"),
                    "reviewer-image-absent": BUILD.CommandResult(1),
                    "backend-image-absent": BUILD.CommandResult(1),
                    "reviewer-image-id": BUILD.CommandResult(0, f"{IMAGE_ID}\n".encode()),
                }
            )
            commands = []
            with mock.patch.object(BUILD, "_allocate_test_port", return_value=49152):
                image, image_id = BUILD._run_verification(
                    inputs,
                    manifest,
                    attempt,
                    7,
                    checkout,
                    runner,
                    commands,
                )

            self.assertEqual(image, f"tacua-reviewer-web:qa-{'2' * 10}-000007")
            self.assertEqual(image_id, IMAGE_ID)
            labels = [kwargs["label"] for _argv, kwargs in runner.calls]
            self.assertEqual(
                labels,
                [
                    "node-version",
                    "npm-version",
                    "backend-tests",
                    "reviewer-npm-ci",
                    "reviewer-notices",
                    "reviewer-tests",
                    "reviewer-typecheck",
                    "reviewer-export-ios",
                    "reviewer-export-web",
                    "reviewer-validator-tests",
                    "reviewer-validator",
                    "reviewer-web-tests",
                    "reviewer-image-absent",
                    "backend-image-absent",
                    "isolated-container-verification",
                    "reviewer-image-id",
                    "verified-worktree-clean",
                    "verified-index-clean",
                ],
            )
            verifier = next(
                (argv, kwargs)
                for argv, kwargs in runner.calls
                if kwargs["label"] == "isolated-container-verification"
            )
            self.assertEqual(
                verifier[0],
                [str(inputs.bash), ".github/scripts/verify-backend-container.sh"],
            )
            self.assertTrue(
                all(
                    kwargs["umask"] == BUILD.VERIFICATION_CHILD_UMASK
                    for _argv, kwargs in runner.calls
                )
            )
            self.assertTrue(
                all(
                    command["umask"] == BUILD.VERIFICATION_CHILD_UMASK
                    for command in commands
                )
            )
            self.assertEqual(verifier[1]["env"]["TACUA_KEEP_VERIFIED_IMAGES"], "true")
            self.assertEqual(verifier[1]["env"]["TACUA_CONTAINER_TEST_PORT"], "49152")
            self.assertNotIn("DOCKER_CONTEXT", verifier[1]["env"])
            flattened = [value for argv, _kwargs in runner.calls for value in argv]
            self.assertFalse(any("systemctl" in value for value in flattened))
            self.assertFalse(any("tailscale" in value for value in flattened))
            self.assertFalse(any("compose" == value for value in flattened))

    def test_verification_rejects_preexisting_image_without_running_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            attempt = base / "attempt"
            checkout = attempt / BUILD.BUILD_SOURCE_DIRECTORY
            checkout.mkdir(parents=True, mode=0o700)
            home = base / "home"
            runtime = base / "runtime"
            home.mkdir(mode=0o700)
            runtime.mkdir(mode=0o700)
            manifest = {
                "commands": {"docker": str(inputs.docker)},
                "runtime": {
                    "docker_host": "unix:///docker.sock",
                    "home": str(home),
                    "xdg_runtime_directory": str(runtime),
                },
            }
            runner = FakeRunner({"reviewer-image-absent": BUILD.CommandResult(0, f"{IMAGE_ID}\n".encode())})
            runner.responses.update(
                {
                    "node-version": BUILD.CommandResult(0, b"v22.22.2\n"),
                    "npm-version": BUILD.CommandResult(0, b"10.9.4\n"),
                }
            )

            with self.assertRaises(BUILD.CandidateBuildError):
                BUILD._run_verification(inputs, manifest, attempt, 1, checkout, runner, [])
            self.assertNotIn(
                "isolated-container-verification",
                [kwargs["label"] for _argv, kwargs in runner.calls],
            )

    def test_image_reproof_rejects_rebound_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            attempt = base / "attempt"
            checkout = attempt / "checkout"
            checkout.mkdir(parents=True, mode=0o700)
            home = base / "home"
            runtime = base / "runtime"
            home.mkdir(mode=0o700)
            runtime.mkdir(mode=0o700)
            manifest = {
                "commands": {"docker": str(inputs.docker)},
                "runtime": {
                    "docker_host": "unix:///docker.sock",
                    "home": str(home),
                    "xdg_runtime_directory": str(runtime),
                },
            }
            runner = FakeRunner(
                {"reviewer-image-reproof": BUILD.CommandResult(0, ("sha256:" + "b" * 64 + "\n").encode())}
            )

            with self.assertRaises(BUILD.CandidateBuildError) as raised:
                BUILD._reinspect_image(
                    inputs,
                    manifest,
                    attempt,
                    checkout,
                    "tacua-reviewer-web:qa-test",
                    IMAGE_ID,
                    runner,
                    [],
                )
            self.assertEqual(raised.exception.code, "REVIEWER_UPGRADE_CANDIDATE_BUILD_IMAGE_REBOUND")

    def test_git_preflight_fetches_public_main_and_pins_exact_clean_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            attempt = base / "attempt"
            attempt.mkdir(mode=0o700)
            home = base / "home"
            home.mkdir(mode=0o700)
            checkout = attempt / BUILD.BUILD_SOURCE_DIRECTORY

            def cloned(_argv, _kwargs):
                checkout.mkdir(mode=0o700)
                app = checkout / "apps/reviewer/src/app.tsx"
                app.parent.mkdir(parents=True, mode=0o700)
                app.write_text("export {};\n")

            index = (
                b"100644 "
                + b"a" * 40
                + b" 0\tapps/reviewer/src/app.tsx\0"
            )
            responses = {
                "installed-root": BUILD.CommandResult(0, f"{inputs.installed_repository}\n".encode()),
                "installed-head": BUILD.CommandResult(0, f"{inputs.installed_commit}\n".encode()),
                "installed-origin": BUILD.CommandResult(
                    0,
                    f"git@github.com:{inputs.repository_identity}.git\n".encode(),
                ),
                "candidate-origin": BUILD.CommandResult(0, f"{inputs.repository_url}\n".encode()),
                "candidate-fetch-head": BUILD.CommandResult(0, f"{inputs.candidate_commit}\n".encode()),
                "candidate-head": BUILD.CommandResult(0, f"{inputs.candidate_commit}\n".encode()),
                "candidate-restricted-diff": BUILD.CommandResult(0, b"apps/reviewer/src/app.tsx\0"),
                "candidate-index": BUILD.CommandResult(0, index),
            }
            runner = FakeRunner(responses, {"candidate-clone": cloned})
            commands = []

            selected, parsed_index, changes = BUILD._git_preflight_and_checkout(
                inputs,
                attempt,
                runner,
                commands,
                home,
            )

            self.assertEqual(selected, checkout)
            self.assertEqual(parsed_index, (("apps/reviewer/src/app.tsx", 0o444),))
            self.assertEqual(changes, ("apps/reviewer/src/app.tsx",))
            labels = [kwargs["label"] for _argv, kwargs in runner.calls]
            self.assertEqual(
                labels,
                [
                    "installed-root",
                    "installed-head",
                    "installed-clean",
                    "installed-origin",
                    "candidate-clone",
                    "candidate-origin",
                    "candidate-fetch",
                    "candidate-fetch-head",
                    "candidate-commit",
                    "candidate-checkout",
                    "candidate-head",
                    "candidate-lineage",
                    "candidate-worktree-clean",
                    "candidate-index-clean",
                    "candidate-untracked-clean",
                    "candidate-restricted-diff",
                    "candidate-index",
                ],
            )
            fetch = next(argv for argv, kwargs in runner.calls if kwargs["label"] == "candidate-fetch")
            self.assertEqual(fetch[-5:], ["fetch", "--no-tags", "--force", "origin", "main"])
            clone = next(argv for argv, kwargs in runner.calls if kwargs["label"] == "candidate-clone")
            self.assertIn("--no-hardlinks", clone)
            self.assertEqual(clone[-2], inputs.repository_url)
            for _argv, kwargs in runner.calls:
                self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
                self.assertNotIn("DOCKER_HOST", kwargs["env"])

    def test_git_preflight_rejects_noncanonical_origin_lookalikes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            home = base / "home"
            home.mkdir(mode=0o700)
            common = {
                "installed-root": BUILD.CommandResult(
                    0,
                    f"{inputs.installed_repository}\n".encode(),
                ),
                "installed-head": BUILD.CommandResult(
                    0,
                    f"{inputs.installed_commit}\n".encode(),
                ),
            }
            for sequence, origin in enumerate(
                (
                    "git@github.com:Will1707/tacua",
                    "git@github.com:Will1707/tacua.git/",
                    "ssh://github.com/Will1707/tacua.git",
                    "https://github.com/Will1707/tacua",
                    "https://github.com/Will1707/tacua.git?ref=main",
                    "https://github.com/Will1707/tacua.git\nextra",
                ),
                start=1,
            ):
                with self.subTest(origin=origin):
                    attempt = base / f"attempt-{sequence}"
                    attempt.mkdir(mode=0o700)
                    runner = FakeRunner(
                        {
                            **common,
                            "installed-origin": BUILD.CommandResult(
                                0,
                                f"{origin}\n".encode(),
                            ),
                        }
                    )
                    with self.assertRaises(BUILD.CandidateBuildError):
                        BUILD._git_preflight_and_checkout(
                            inputs,
                            attempt,
                            runner,
                            [],
                            home,
                        )
                    self.assertNotIn(
                        "candidate-clone",
                        [kwargs["label"] for _argv, kwargs in runner.calls],
                    )

    def test_git_preflight_rejects_fetch_head_or_dirty_installed_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            attempt = base / "attempt"
            attempt.mkdir(mode=0o700)
            home = base / "home"
            home.mkdir(mode=0o700)
            common = {
                "installed-root": BUILD.CommandResult(0, f"{inputs.installed_repository}\n".encode()),
                "installed-head": BUILD.CommandResult(0, f"{inputs.installed_commit}\n".encode()),
                "installed-origin": BUILD.CommandResult(0, f"{inputs.repository_url}\n".encode()),
            }
            dirty = FakeRunner({**common, "installed-clean": BUILD.CommandResult(0, b"?? local\n")})
            with self.assertRaises(BUILD.CandidateBuildError):
                BUILD._git_preflight_and_checkout(inputs, attempt, dirty, [], home)
            self.assertNotIn("candidate-clone", [kwargs["label"] for _argv, kwargs in dirty.calls])

            checkout = attempt / BUILD.BUILD_SOURCE_DIRECTORY
            def clone(_argv, _kwargs):
                checkout.mkdir(mode=0o700)
            rebound = FakeRunner(
                {
                    **common,
                    "candidate-origin": BUILD.CommandResult(0, f"{inputs.repository_url}\n".encode()),
                    "candidate-fetch-head": BUILD.CommandResult(0, ("3" * 40 + "\n").encode()),
                },
                {"candidate-clone": clone},
            )
            with self.assertRaises(BUILD.CandidateBuildError):
                BUILD._git_preflight_and_checkout(inputs, attempt, rebound, [], home)

    def test_attempts_are_append_only_and_partial_attempt_gets_fresh_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            attempts = base / "attempts"
            attempts.mkdir(mode=0o700)

            first, first_number = BUILD._allocate_attempt(attempts, inputs)
            (first / "partial-build-output").write_text("quarantined\n")
            second, second_number = BUILD._allocate_attempt(attempts, inputs)

            self.assertEqual((first_number, second_number), (1, 2))
            self.assertNotEqual(first, second)
            self.assertTrue((first / "partial-build-output").is_file())
            self.assertTrue((second / BUILD.JOURNAL_DIRECTORY / "000001.json").is_file())

    def test_tampered_journal_and_unknown_attempt_entry_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            attempts = base / "attempts"
            attempts.mkdir(mode=0o700)
            attempt, _number = BUILD._allocate_attempt(attempts, inputs)
            journal = attempt / BUILD.JOURNAL_DIRECTORY / "000001.json"
            journal.write_bytes(journal.read_bytes() + b" ")
            with self.assertRaises(BUILD.CandidateBuildError):
                BUILD._append_journal(attempt, phase="next")

            for kind in ("symlink", "hardlink"):
                with self.subTest(kind=kind):
                    link_attempts = base / f"{kind}-attempts"
                    link_attempts.mkdir(mode=0o700)
                    link_attempt, _sequence = BUILD._allocate_attempt(
                        link_attempts,
                        inputs,
                    )
                    link_journal = (
                        link_attempt
                        / BUILD.JOURNAL_DIRECTORY
                        / "000001.json"
                    )
                    external = base / f"{kind}-journal.json"
                    external.write_bytes(link_journal.read_bytes())
                    external.chmod(0o600)
                    link_journal.unlink()
                    if kind == "symlink":
                        link_journal.symlink_to(external)
                    else:
                        os.link(external, link_journal)
                    with self.assertRaises(BUILD.CandidateBuildError):
                        BUILD._append_journal(link_attempt, phase="next")

            unknown = attempts / "operator-data"
            unknown.mkdir(mode=0o700)
            with self.assertRaises(BUILD.CandidateBuildError):
                BUILD._allocate_attempt(attempts, inputs)

    def test_cleanup_targets_only_named_attempt_artifacts_and_never_follows_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            attempt = base / "attempt"
            attempt.mkdir(mode=0o700)
            outside = base / "outside"
            outside.mkdir(mode=0o700)
            protected = outside / "operator-data"
            protected.write_text("keep\n")
            build_source = attempt / BUILD.BUILD_SOURCE_DIRECTORY
            build_source.mkdir(mode=0o700)
            (build_source / "outside-link").symlink_to(outside, target_is_directory=True)
            staged = attempt / BUILD.STAGED_RELEASE_DIRECTORY
            staged.mkdir(mode=0o700)
            sealed = staged / "sealed"
            sealed.mkdir(mode=0o700)
            (sealed / "file").write_text("generated\n")
            (sealed / "file").chmod(0o444)
            sealed.chmod(0o555)
            journal = attempt / BUILD.JOURNAL_DIRECTORY
            journal.mkdir(mode=0o700)

            BUILD._cleanup_attempt_artifacts(attempt)

            self.assertTrue(protected.is_file())
            self.assertTrue(journal.is_dir())
            self.assertFalse(build_source.exists())
            self.assertFalse(staged.exists())

            linked_root = attempt / BUILD.BUILD_SOURCE_DIRECTORY
            linked_root.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(BUILD.CandidateBuildError):
                BUILD._cleanup_attempt_artifacts(attempt)
            self.assertTrue(protected.is_file())

    def test_publisher_creates_loader_accepted_exact_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._release_fixture(Path(temporary).resolve() / "case")

            prepared = BUILD._publish_release(
                fixture["inputs"],
                fixture["attempt"],
                fixture["attempt_number"],
                fixture["staged"],
                fixture["releases"],
                fixture["manifest"],
                fixture["source_compose"],
                fixture["source_payload"],
                fixture["source_document"],
                fixture["inputs"].installed_repository,
                "tacua-reviewer-web:qa-fixture-000001",
                IMAGE_ID,
                BUILD._tool_bindings(fixture["inputs"]),
                [],
            )

            self.assertEqual(stat.S_IMODE(prepared.release_root.stat().st_mode), 0o500)
            self.assertEqual(
                {entry.name for entry in prepared.release_root.iterdir()},
                {
                    BUILD.candidate.SOURCE_DIRECTORY,
                    BUILD.candidate.SOURCE_MANIFEST_FILE,
                    BUILD.candidate.CANDIDATE_COMPOSE_FILE,
                    BUILD.candidate.PREPARATION_RECEIPT_FILE,
                },
            )
            self.assertEqual(
                stat.S_IMODE((prepared.release_root / BUILD.candidate.SOURCE_MANIFEST_FILE).stat().st_mode),
                0o400,
            )
            self.assertEqual(stat.S_IMODE(prepared.candidate_compose.stat().st_mode), 0o600)
            self.assertEqual(prepared.receipt["verification"]["attempt_id"], "attempt-000001")
            self.assertEqual(prepared.receipt["verification"]["status"], "verified")
            self.assertEqual(
                prepared.receipt["verification"]["commands_digest"],
                BUILD._digest((fixture["attempt"] / BUILD.COMMANDS_FILE).read_bytes()),
            )
            self.assertEqual(
                prepared.receipt["generation_id"],
                fixture_release_generation(fixture),
            )

    def test_release_generation_separates_reverts_and_source_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._release_fixture(Path(temporary).resolve() / "case")
            first = fixture_release_generation(fixture)
            next_inputs = BUILD.BuildInputs(
                **{
                    **fixture["inputs"].__dict__,
                    "candidate_commit": "3" * 40,
                }
            )
            reverted_tree = BUILD._release_generation_id(
                next_inputs,
                fixture["manifest"],
                fixture["source_compose"],
                fixture["source_payload"],
                BUILD._tool_bindings(next_inputs),
            )
            alternate_compose = fixture["source_compose"].with_name(
                "alternate-source-compose.json"
            )
            alternate_compose.write_bytes(fixture["source_payload"])
            alternate_compose.chmod(0o400)
            alternate_source = BUILD._release_generation_id(
                fixture["inputs"],
                fixture["manifest"],
                alternate_compose,
                fixture["source_payload"],
                BUILD._tool_bindings(fixture["inputs"]),
            )

            self.assertNotEqual(first, reverted_tree)
            self.assertNotEqual(first, alternate_source)

    def test_existing_tampered_or_partial_release_is_never_adopted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._release_fixture(Path(temporary).resolve() / "case")
            prepared = BUILD._publish_release(
                fixture["inputs"],
                fixture["attempt"],
                fixture["attempt_number"],
                fixture["staged"],
                fixture["releases"],
                fixture["manifest"],
                fixture["source_compose"],
                fixture["source_payload"],
                fixture["source_document"],
                fixture["inputs"].installed_repository,
                "tacua-reviewer-web:qa-fixture-000001",
                IMAGE_ID,
                BUILD._tool_bindings(fixture["inputs"]),
                [],
            )
            prepared.candidate_compose.write_bytes(b"{}")
            with self.assertRaises(BUILD.CandidateBuildError) as raised:
                BUILD._matching_existing_release(
                    prepared.release_root,
                    fixture["inputs"],
                    fixture["source_compose"],
                    BUILD._digest(fixture["source_payload"]),
                    BUILD._tool_bindings(fixture["inputs"]),
                )
            self.assertEqual(
                raised.exception.code,
                "REVIEWER_UPGRADE_CANDIDATE_BUILD_RELEASE_CONFLICT",
            )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._release_fixture(Path(temporary).resolve() / "case")
            release = fixture["releases"] / fixture_release_generation(fixture)
            release.mkdir(mode=0o500)
            with self.assertRaises(BUILD.CandidateBuildError):
                BUILD._publish_release(
                    fixture["inputs"],
                    fixture["attempt"],
                    fixture["attempt_number"],
                    fixture["staged"],
                    fixture["releases"],
                    fixture["manifest"],
                    fixture["source_compose"],
                    fixture["source_payload"],
                    fixture["source_document"],
                    fixture["inputs"].installed_repository,
                    "tacua-reviewer-web:qa-fixture-000001",
                    IMAGE_ID,
                    BUILD._tool_bindings(fixture["inputs"]),
                    [],
                )

    def test_rename_before_final_chmod_crash_is_exactly_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._release_fixture(Path(temporary).resolve() / "case")
            real_rename = BUILD.os.rename

            def crash_after_rename(source, destination):
                real_rename(source, destination)
                raise OSError("injected crash after durable directory rename")

            with mock.patch.object(BUILD.os, "rename", side_effect=crash_after_rename):
                with self.assertRaises(BUILD.CandidateBuildError):
                    BUILD._publish_release(
                        fixture["inputs"],
                        fixture["attempt"],
                        fixture["attempt_number"],
                        fixture["staged"],
                        fixture["releases"],
                        fixture["manifest"],
                        fixture["source_compose"],
                        fixture["source_payload"],
                        fixture["source_document"],
                        fixture["inputs"].installed_repository,
                        "tacua-reviewer-web:qa-fixture-000001",
                        IMAGE_ID,
                        BUILD._tool_bindings(fixture["inputs"]),
                        [],
                    )
            release = fixture["releases"] / fixture_release_generation(fixture)
            self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o700)

            prepared = BUILD._matching_existing_release(
                release,
                fixture["inputs"],
                fixture["source_compose"],
                BUILD._digest(fixture["source_payload"]),
                BUILD._tool_bindings(fixture["inputs"]),
            )

            self.assertEqual(stat.S_IMODE(prepared.release_root.stat().st_mode), 0o500)
            self.assertEqual(prepared.receipt["candidate_commit"], fixture["inputs"].candidate_commit)

    def test_build_prepared_release_runs_end_to_end_with_fake_commands_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            inputs = self._fixture(base / "fixture")
            old_root = inputs.installed_repository
            old_ingress = old_root / "services/backend/ingress/haproxy.cfg"
            old_ingress.parent.mkdir(parents=True, mode=0o700)
            old_ingress.write_bytes(b"global\n  daemon\n")
            old_ingress.chmod(0o644)
            source_document = {
                "configs": {"tacua_loopback_ingress": {"file": str(old_ingress)}},
                "services": {
                    "backend": {
                        "build": {"context": str(old_root)},
                        "image": "tacua-backend:old",
                    },
                    "reviewer": {
                        "build": {"context": str(old_root)},
                        "image": "tacua-reviewer-web:old",
                    },
                },
            }
            source_compose = base / "source-compose.json"
            source_payload = BUILD._canonical_json(source_document)
            source_compose.write_bytes(source_payload)
            source_compose.chmod(0o400)
            home = base / "home"
            xdg = base / "xdg"
            home.mkdir(mode=0o700)
            xdg.mkdir(mode=0o700)
            desired = {"desired": "running", "compose_digest": BUILD._digest(source_payload)}
            manifest = {
                "commands": {"docker": str(inputs.docker)},
                "compose_digest": BUILD._digest(source_payload),
                "runtime": {
                    "docker_host": "unix:///private/docker.sock",
                    "home": str(home),
                    "xdg_runtime_directory": str(xdg),
                },
            }
            def cloned(argv, _kwargs):
                checkout = Path(argv[-1])
                write_required_runtime_tree(checkout)

            index = git_index_for_required_runtime()

            responses = {
                "installed-root": BUILD.CommandResult(0, f"{inputs.installed_repository}\n".encode()),
                "installed-head": BUILD.CommandResult(0, f"{inputs.installed_commit}\n".encode()),
                "installed-origin": BUILD.CommandResult(0, f"{inputs.repository_url}\n".encode()),
                "candidate-origin": BUILD.CommandResult(0, f"{inputs.repository_url}\n".encode()),
                "candidate-fetch-head": BUILD.CommandResult(0, f"{inputs.candidate_commit}\n".encode()),
                "candidate-head": BUILD.CommandResult(0, f"{inputs.candidate_commit}\n".encode()),
                "candidate-restricted-diff": BUILD.CommandResult(
                    0,
                    b"services/backend/scripts/reviewer_upgrade_transaction.py\0",
                ),
                "candidate-index": BUILD.CommandResult(0, index),
                "reviewer-image-absent": BUILD.CommandResult(1),
                "backend-image-absent": BUILD.CommandResult(1),
                "node-version": BUILD.CommandResult(0, b"v22.22.2\n"),
                "npm-version": BUILD.CommandResult(0, b"10.9.4\n"),
                "reviewer-image-id": BUILD.CommandResult(0, f"{IMAGE_ID}\n".encode()),
                "reviewer-image-reproof": BUILD.CommandResult(0, f"{IMAGE_ID}\n".encode()),
                "installed-head-reproof": BUILD.CommandResult(0, f"{inputs.installed_commit}\n".encode()),
            }
            runner = FakeRunner(responses, {"candidate-clone": cloned})
            source_state = (desired, manifest, source_compose, source_payload, source_document)
            with mock.patch.object(
                BUILD,
                "_read_source_compose",
                return_value=source_state,
            ) as read_source, mock.patch.object(
                BUILD,
                "_allocate_test_port",
                return_value=49152,
            ):
                prepared = BUILD.build_prepared_release(inputs, runner=runner)

            self.assertEqual(read_source.call_count, 3)
            self.assertEqual(prepared.receipt["candidate_commit"], inputs.candidate_commit)
            self.assertEqual(prepared.receipt["verification"]["attempt_id"], "attempt-000001")
            self.assertEqual(prepared.receipt["reviewer_image"]["id"], IMAGE_ID)
            labels = [kwargs["label"] for _argv, kwargs in runner.calls]
            self.assertIn("candidate-fetch", labels)
            self.assertIn("isolated-container-verification", labels)
            self.assertLess(labels.index("reviewer-image-id"), labels.index("reviewer-image-reproof"))
            self.assertLess(labels.index("reviewer-image-reproof"), labels.index("installed-head-reproof"))
            flattened = [argument for argv, _kwargs in runner.calls for argument in argv]
            self.assertFalse(any("systemctl" in argument for argument in flattened))
            self.assertFalse(any("tailscale" in argument for argument in flattened))


def fixture_release_generation(fixture) -> str:
    return BUILD._release_generation_id(
        fixture["inputs"],
        fixture["manifest"],
        fixture["source_compose"],
        fixture["source_payload"],
        BUILD._tool_bindings(fixture["inputs"]),
    )


def write_required_runtime_tree(root: Path):
    root.mkdir(mode=0o700)
    records = []
    for relative in sorted(BUILD.candidate.REQUIRED_RUNTIME_FILES):
        path = root / relative
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if relative == "services/backend/ingress/haproxy.cfg":
            payload = b"global\n  daemon\n"
        else:
            payload = f"# retained fixture: {relative}\n".encode()
        path.write_bytes(payload)
        path.chmod(0o600)
        records.append((relative, 0o444))
    return tuple(records)


def git_index_for_required_runtime():
    values = []
    for relative in sorted(BUILD.candidate.REQUIRED_RUNTIME_FILES):
        values.append(
            b"100644 " + b"a" * 40 + b" 0\t" + relative.encode() + b"\0"
        )
    return b"".join(values)


def json_clone(value):
    import json

    return json.loads(json.dumps(value))


if __name__ == "__main__":
    unittest.main()
