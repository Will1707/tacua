# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import inspect
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    ROOT
    / "services"
    / "backend"
    / "scripts"
    / "reviewer_upgrade_legacy_recovery.py"
)


def _load_script():
    specification = importlib.util.spec_from_file_location(
        "tacua_reviewer_upgrade_legacy_recovery_test",
        SCRIPT,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("legacy recovery writer cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RECOVERY = _load_script()


class LegacyRecoveryWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.directory.chmod(0o700)
        self.target = self.directory / "activation.json"

    def _staging(self) -> list[Path]:
        return sorted(self.directory.glob(".activation.json.next-*"))

    def test_signature_matches_legacy_writer(self) -> None:
        self.assertEqual(
            str(inspect.signature(RECOVERY._atomic_private_write)),
            "(path: 'Path', payload: 'bytes', *, replace: 'bool', "
            "mode: 'int' = 384) -> 'None'",
        )

    def test_replace_publishes_exact_payload_mode_and_cleans_staging(self) -> None:
        self.target.write_bytes(b"old")
        self.target.chmod(0o600)

        RECOVERY._atomic_private_write(
            self.target,
            b"sealed",
            replace=True,
            mode=0o400,
        )

        self.assertEqual(self.target.read_bytes(), b"sealed")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o400)
        self.assertEqual(self._staging(), [])

    def test_no_clobber_publication_uses_link_and_cleans_staging(self) -> None:
        RECOVERY._atomic_private_write(
            self.target,
            b"new",
            replace=False,
        )

        self.assertEqual(self.target.read_bytes(), b"new")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o600)
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.assertEqual(self._staging(), [])

    def test_staging_descriptor_remains_open_through_publication(self) -> None:
        real_create = RECOVERY._create_owned_staging
        real_require = RECOVERY._require_owned_staging
        real_replace = os.replace
        captured: list[int] = []

        def capture_create(
            directory_descriptor: int,
            target_name: str,
        ) -> tuple[str, int, tuple[int, int]]:
            created = real_create(directory_descriptor, target_name)
            captured.append(created[1])
            return created

        def require_while_open(*args, **kwargs) -> None:
            os.fstat(captured[0])
            real_require(*args, **kwargs)

        def replace_while_open(*args, **kwargs) -> None:
            os.fstat(captured[0])
            real_replace(*args, **kwargs)

        with mock.patch.object(
            RECOVERY,
            "_create_owned_staging",
            side_effect=capture_create,
        ):
            with mock.patch.object(
                RECOVERY,
                "_require_owned_staging",
                side_effect=require_while_open,
            ):
                with mock.patch.object(
                    RECOVERY.os,
                    "replace",
                    side_effect=replace_while_open,
                ):
                    RECOVERY._atomic_private_write(
                        self.target,
                        b"published",
                        replace=True,
                    )

        self.assertEqual(self.target.read_bytes(), b"published")
        with self.assertRaises(OSError):
            os.fstat(captured[0])

    def test_partial_writes_are_retried_until_payload_is_complete(self) -> None:
        real_write = os.write

        def partial_write(descriptor: int, payload: bytes) -> int:
            return real_write(descriptor, payload[:2])

        with mock.patch.object(
            RECOVERY.os,
            "write",
            side_effect=partial_write,
        ):
            RECOVERY._atomic_private_write(
                self.target,
                b"complete payload",
                replace=False,
            )

        self.assertEqual(self.target.read_bytes(), b"complete payload")
        self.assertEqual(self._staging(), [])

    def test_metadata_or_file_fsync_failure_cleans_owned_staging(self) -> None:
        for operation in ("fchmod", "fsync"):
            with self.subTest(operation=operation):
                with mock.patch.object(
                    RECOVERY.os,
                    operation,
                    side_effect=OSError("synthetic durability failure"),
                ):
                    with self.assertRaises(
                        RECOVERY.LegacyRecoveryWriteError
                    ) as raised:
                        RECOVERY._atomic_private_write(
                            self.target,
                            b"payload",
                            replace=True,
                        )
                self.assertEqual(
                    raised.exception.code,
                    "RECONCILE_STATE_INVALID",
                )
                self.assertFalse(self.target.exists())
                self.assertEqual(self._staging(), [])

    def test_existing_target_is_not_clobbered_and_owned_staging_is_removed(
        self,
    ) -> None:
        self.target.write_bytes(b"foreign target")
        self.target.chmod(0o600)

        with self.assertRaises(RECOVERY.LegacyRecoveryWriteError) as raised:
            RECOVERY._atomic_private_write(
                self.target,
                b"new",
                replace=False,
            )

        self.assertEqual(raised.exception.code, "RECONCILE_STATE_EXISTS")
        self.assertEqual(self.target.read_bytes(), b"foreign target")
        self.assertEqual(self._staging(), [])

    def test_random_decimal_collision_is_preserved_and_next_nonce_succeeds(
        self,
    ) -> None:
        collision = self.directory / ".activation.json.next-00000000000000000007"
        collision.write_bytes(b"foreign staging")
        collision.chmod(0o600)

        with mock.patch.object(
            RECOVERY.secrets,
            "randbelow",
            side_effect=[7, 11],
        ):
            RECOVERY._atomic_private_write(
                self.target,
                b"published",
                replace=True,
            )

        self.assertEqual(collision.read_bytes(), b"foreign staging")
        self.assertEqual(self.target.read_bytes(), b"published")
        self.assertEqual(self._staging(), [collision])
        self.assertRegex(
            collision.name,
            re.compile(r"^\.activation\.json\.next-[0-9]+$"),
        )

    def test_exhausted_collisions_are_all_preserved(self) -> None:
        collision = self.directory / ".activation.json.next-00000000000000000003"
        collision.write_bytes(b"foreign staging")
        collision.chmod(0o600)

        with mock.patch.object(
            RECOVERY.secrets,
            "randbelow",
            return_value=3,
        ):
            with self.assertRaises(RECOVERY.LegacyRecoveryWriteError) as raised:
                RECOVERY._atomic_private_write(
                    self.target,
                    b"never published",
                    replace=True,
                )

        self.assertEqual(raised.exception.code, "RECONCILE_STATE_INVALID")
        self.assertEqual(collision.read_bytes(), b"foreign staging")
        self.assertFalse(self.target.exists())

    def test_foreign_inode_swapped_into_staging_name_is_never_deleted(
        self,
    ) -> None:
        real_replace = os.replace

        def replace_with_foreign(
            source: str,
            destination: str,
            *,
            src_dir_fd: int,
            dst_dir_fd: int,
        ) -> None:
            del destination, dst_dir_fd
            os.unlink(source, dir_fd=src_dir_fd)
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            try:
                os.write(descriptor, b"foreign replacement")
            finally:
                os.close(descriptor)
            raise OSError("synthetic replace failure")

        self.addCleanup(setattr, RECOVERY.os, "replace", real_replace)
        with mock.patch.object(RECOVERY.secrets, "randbelow", return_value=19):
            with mock.patch.object(
                RECOVERY.os,
                "replace",
                side_effect=replace_with_foreign,
            ):
                with self.assertRaises(
                    RECOVERY.LegacyRecoveryWriteError
                ) as raised:
                    RECOVERY._atomic_private_write(
                        self.target,
                        b"owned payload",
                        replace=True,
                    )

        foreign = self.directory / ".activation.json.next-00000000000000000019"
        self.assertEqual(raised.exception.code, "RECONCILE_STATE_INVALID")
        self.assertEqual(foreign.read_bytes(), b"foreign replacement")
        self.assertFalse(self.target.exists())

    def test_foreign_inode_substituted_before_publication_is_not_published(
        self,
    ) -> None:
        real_require = RECOVERY._require_owned_staging

        def substitute_then_require(
            directory_descriptor: int,
            temporary: str,
            identity: tuple[int, int],
            *,
            mode: int,
            size: int,
            links: int,
        ) -> None:
            os.unlink(temporary, dir_fd=directory_descriptor)
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_descriptor,
            )
            try:
                os.write(descriptor, b"foreign before publication")
            finally:
                os.close(descriptor)
            real_require(
                directory_descriptor,
                temporary,
                identity,
                mode=mode,
                size=size,
                links=links,
            )

        for replace in (False, True):
            with self.subTest(replace=replace):
                nonce = 29 if replace else 23
                foreign = self.directory / (
                    f".activation.json.next-{nonce:020d}"
                )
                with mock.patch.object(
                    RECOVERY.secrets,
                    "randbelow",
                    return_value=nonce,
                ):
                    with mock.patch.object(
                        RECOVERY,
                        "_require_owned_staging",
                        side_effect=substitute_then_require,
                    ):
                        with self.assertRaises(
                            RECOVERY.LegacyRecoveryWriteError
                        ) as raised:
                            RECOVERY._atomic_private_write(
                                self.target,
                                b"owned payload",
                                replace=replace,
                            )
                self.assertEqual(
                    raised.exception.code,
                    "RECONCILE_STATE_INVALID",
                )
                self.assertEqual(
                    foreign.read_bytes(),
                    b"foreign before publication",
                )
                self.assertFalse(self.target.exists())
                foreign.unlink()

    def test_failed_post_create_validation_removes_only_created_inode(
        self,
    ) -> None:
        real_fstat = os.fstat
        calls = 0

        def invalid_second_fstat(descriptor: int) -> os.stat_result:
            nonlocal calls
            calls += 1
            observed = real_fstat(descriptor)
            if calls != 2:
                return observed
            values = list(observed)
            values[0] = (observed.st_mode & ~0o777) | 0o644
            return os.stat_result(values)

        with mock.patch.object(
            RECOVERY.os,
            "fstat",
            side_effect=invalid_second_fstat,
        ):
            with self.assertRaises(RECOVERY.LegacyRecoveryWriteError) as raised:
                RECOVERY._atomic_private_write(
                    self.target,
                    b"payload",
                    replace=True,
                )

        self.assertEqual(raised.exception.code, "RECONCILE_STATE_INVALID")
        self.assertFalse(self.target.exists())
        self.assertEqual(self._staging(), [])

    def test_parent_rebinding_before_publication_is_rejected(self) -> None:
        bound = self.directory / "bound"
        bound.mkdir(mode=0o700)
        target = bound / "activation.json"
        detached = self.directory / "detached"
        real_require = RECOVERY._require_parent_binding
        rebound = False

        def rebind_then_require(parent: Path, descriptor: int) -> None:
            nonlocal rebound
            if not rebound:
                rebound = True
                parent.rename(detached)
                parent.mkdir(mode=0o700)
            real_require(parent, descriptor)

        with mock.patch.object(
            RECOVERY,
            "_require_parent_binding",
            side_effect=rebind_then_require,
        ):
            with self.assertRaises(RECOVERY.LegacyRecoveryWriteError) as raised:
                RECOVERY._atomic_private_write(
                    target,
                    b"must not publish",
                    replace=True,
                )

        self.assertEqual(raised.exception.code, "RECONCILE_STATE_INVALID")
        self.assertFalse(target.exists())
        self.assertEqual(list(bound.iterdir()), [])
        self.assertEqual(list(detached.iterdir()), [])

    def test_symlink_parent_and_non_private_parent_are_rejected(self) -> None:
        real = self.directory / "real"
        real.mkdir(mode=0o700)
        alias = self.directory / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(RECOVERY.LegacyRecoveryWriteError):
            RECOVERY._atomic_private_write(
                alias / "activation.json",
                b"payload",
                replace=True,
            )
        self.assertEqual(list(real.iterdir()), [])

        real.chmod(0o755)
        with self.assertRaises(RECOVERY.LegacyRecoveryWriteError):
            RECOVERY._atomic_private_write(
                real / "activation.json",
                b"payload",
                replace=True,
            )
        self.assertEqual(list(real.iterdir()), [])

    def test_parent_validation_preserves_stable_error_if_close_fails(self) -> None:
        self.directory.chmod(0o755)
        with mock.patch.object(
            RECOVERY.os,
            "close",
            side_effect=OSError("synthetic close failure"),
        ):
            with self.assertRaises(RECOVERY.LegacyRecoveryWriteError) as raised:
                RECOVERY._atomic_private_write(
                    self.target,
                    b"payload",
                    replace=True,
                )

        self.assertEqual(raised.exception.code, "RECONCILE_STATE_INVALID")
        self.assertFalse(self.target.exists())
        self.assertEqual(self._staging(), [])

    def test_invalid_inputs_cannot_create_staging(self) -> None:
        cases = (
            (bytearray(b"payload"), True, 0o600),
            (b"payload", 1, 0o600),
            (b"payload", True, 0o644),
        )
        for payload, replace, mode in cases:
            with self.subTest(payload=payload, replace=replace, mode=mode):
                with self.assertRaises(RECOVERY.LegacyRecoveryWriteError):
                    RECOVERY._atomic_private_write(
                        self.target,
                        payload,
                        replace=replace,
                        mode=mode,
                    )
                self.assertEqual(self._staging(), [])


if __name__ == "__main__":
    unittest.main()
