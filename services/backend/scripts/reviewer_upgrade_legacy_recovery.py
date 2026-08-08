#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Narrow recovery primitives for legacy reviewer-upgrade transactions.

This module is intentionally not a transaction runner.  It provides the
collision-resistant, directory-descriptor-relative writer needed by a
separately attested one-shot recovery process.  A caller that installs the
writer into a legacy reconciler is responsible for translating
``LegacyRecoveryWriteError`` to that reconciler's stable error type.
"""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import sys
from typing import NoReturn


_MAX_STAGING_ATTEMPTS = 32
_STAGING_RANDOM_BOUND = 10**20


class LegacyRecoveryWriteError(RuntimeError):
    """Content-free failure raised by the hardened recovery writer."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str = "RECONCILE_STATE_INVALID") -> NoReturn:
    raise LegacyRecoveryWriteError(code)


def _validated_parent(path: Path) -> tuple[Path, int]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or str(path).startswith("//")
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or path.name in {"", ".", ".."}
    ):
        _fail()
    parent = path.parent
    descriptor: int | None = None
    try:
        if parent.resolve(strict=True) != parent:
            _fail()
        lexical = parent.lstat()
        descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(lexical.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or lexical.st_uid != os.geteuid()
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(lexical.st_mode) != 0o700
            or stat.S_IMODE(opened.st_mode) != 0o700
            or (lexical.st_dev, lexical.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            _fail()
        return parent, descriptor
    except LegacyRecoveryWriteError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                # Preserve the stable validation error; the descriptor was
                # never returned to the caller and no publication occurred.
                pass
        raise
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise LegacyRecoveryWriteError("RECONCILE_STATE_INVALID") from error


def _require_parent_binding(parent: Path, descriptor: int) -> None:
    try:
        lexical = parent.lstat()
        opened = os.fstat(descriptor)
    except OSError as error:
        raise LegacyRecoveryWriteError("RECONCILE_STATE_INVALID") from error
    if (
        not stat.S_ISDIR(lexical.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or lexical.st_uid != os.geteuid()
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(lexical.st_mode) != 0o700
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (lexical.st_dev, lexical.st_ino)
        != (opened.st_dev, opened.st_ino)
    ):
        _fail()


def _create_owned_staging(
    directory_descriptor: int,
    target_name: str,
) -> tuple[str, int, tuple[int, int]]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _attempt in range(_MAX_STAGING_ATTEMPTS):
        # The legacy state scanner accepts only ``.name.next-<digits>``.  A
        # fixed-width decimal nonce retains that grammar while removing the
        # deterministic-PID collision that blocked the original transaction.
        nonce = secrets.randbelow(_STAGING_RANDOM_BOUND)
        temporary = f".{target_name}.next-{nonce:020d}"
        try:
            descriptor = os.open(
                temporary,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError:
            # This name is foreign.  Never inspect, truncate, or remove it.
            continue
        try:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != 0
            ):
                # Clean the failed creation only if its directory entry still
                # names the exact inode returned by this open.  A replacement
                # raced into the same name is foreign and must remain.  Keep
                # the descriptor open through this check so the owned inode
                # cannot be recycled into a newly-created foreign entry.
                _remove_owned_staging(
                    directory_descriptor,
                    temporary,
                    identity,
                )
                _fail()
        except BaseException:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    # Preserve the original stable validation failure.
                    pass
            raise
        return temporary, descriptor, identity
    _fail()


def _owned_staging_metadata(
    directory_descriptor: int,
    temporary: str,
    identity: tuple[int, int],
) -> os.stat_result | None:
    try:
        current = os.stat(
            temporary,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.geteuid()
        or (current.st_dev, current.st_ino) != identity
    ):
        return None
    return current


def _require_owned_staging(
    directory_descriptor: int,
    temporary: str,
    identity: tuple[int, int],
    *,
    mode: int,
    size: int,
    links: int,
) -> None:
    current = _owned_staging_metadata(
        directory_descriptor,
        temporary,
        identity,
    )
    if (
        current is None
        or current.st_nlink != links
        or stat.S_IMODE(current.st_mode) != mode
        or current.st_size != size
    ):
        _fail()


def _remove_owned_staging(
    directory_descriptor: int,
    temporary: str,
    identity: tuple[int, int],
) -> bool:
    if _owned_staging_metadata(
        directory_descriptor,
        temporary,
        identity,
    ) is None:
        return False
    os.unlink(temporary, dir_fd=directory_descriptor)
    os.fsync(directory_descriptor)
    return True


def _atomic_private_write(
    path: Path,
    payload: bytes,
    *,
    replace: bool,
    mode: int = 0o600,
) -> None:
    """Publish one private file without touching foreign staging entries.

    The call signature deliberately matches the legacy reconciler function so
    an attested one-shot runner can install it for exactly one in-process
    transaction attempt.
    """

    if (
        type(payload) is not bytes
        or type(replace) is not bool
        or type(mode) is not int
        or mode not in {0o400, 0o600}
    ):
        _fail()
    parent, directory_descriptor = _validated_parent(path)
    temporary: str | None = None
    temporary_identity: tuple[int, int] | None = None
    temporary_present = False
    staging_descriptor: int | None = None
    try:
        temporary, staging_descriptor, temporary_identity = (
            _create_owned_staging(directory_descriptor, path.name)
        )
        temporary_present = True
        offset = 0
        while offset < len(payload):
            written = os.write(staging_descriptor, payload[offset:])
            if written <= 0:
                raise OSError("atomic recovery write stopped")
            offset += written
        os.fchmod(staging_descriptor, mode)
        os.fsync(staging_descriptor)

        # Do not publish a same-name inode substituted after our O_EXCL open.
        # The system is same-EUID trusted in V1, but this check makes the
        # recovery primitive's foreign-inode boundary explicit and testable.
        # The open descriptor pins the inode until publication or cleanup, so
        # a removed inode cannot be recycled into a foreign same-name entry.
        _require_owned_staging(
            directory_descriptor,
            temporary,
            temporary_identity,
            mode=mode,
            size=len(payload),
            links=1,
        )
        _require_parent_binding(parent, directory_descriptor)

        if replace:
            os.replace(
                temporary,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_present = False
            os.fsync(directory_descriptor)
            _require_parent_binding(parent, directory_descriptor)
        else:
            try:
                os.link(
                    temporary,
                    path.name,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise LegacyRecoveryWriteError(
                    "RECONCILE_STATE_EXISTS"
                ) from error
            # Persist the no-clobber publication before removing its staging
            # hard link, then persist that cleanup as a separate directory
            # mutation.  Both names refer to the exact inode we created.
            os.fsync(directory_descriptor)
            _require_parent_binding(parent, directory_descriptor)
            if not _remove_owned_staging(
                directory_descriptor,
                temporary,
                temporary_identity,
            ):
                _fail()
            temporary_present = False
            _require_parent_binding(parent, directory_descriptor)
    except LegacyRecoveryWriteError:
        raise
    except OSError as error:
        raise LegacyRecoveryWriteError("RECONCILE_STATE_INVALID") from error
    finally:
        primary_error_active = sys.exc_info()[0] is not None
        cleanup_error: OSError | None = None
        if (
            temporary_present
            and temporary is not None
            and temporary_identity is not None
        ):
            try:
                # A same-name entry with a different inode is foreign and is
                # intentionally retained, even when the main operation fails.
                _remove_owned_staging(
                    directory_descriptor,
                    temporary,
                    temporary_identity,
                )
            except OSError as error:
                cleanup_error = error
        if staging_descriptor is not None:
            try:
                os.close(staging_descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        try:
            os.close(directory_descriptor)
        except OSError as error:
            if cleanup_error is None:
                cleanup_error = error
        if cleanup_error is not None and not primary_error_active:
            raise LegacyRecoveryWriteError(
                "RECONCILE_STATE_INVALID"
            ) from cleanup_error


__all__ = ["LegacyRecoveryWriteError", "_atomic_private_write"]
