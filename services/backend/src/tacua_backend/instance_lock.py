# SPDX-License-Identifier: Apache-2.0

"""One-process ownership for a Tacua single-node state directory."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
from types import TracebackType


LOCK_FILE_NAME = ".tacua-instance.lock"


class InstanceLockError(RuntimeError):
    """Raised when the state volume is unsafe or already has an owner."""


class StateInstanceLock:
    def __init__(self, descriptor: int, path: Path):
        self._descriptor = descriptor
        self.path = path

    def close(self) -> None:
        descriptor = self._descriptor
        if descriptor < 0:
            return
        self._descriptor = -1
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> StateInstanceLock:
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()


def acquire_state_instance_lock(
    state_directory: Path,
    *,
    create_directory: bool,
) -> StateInstanceLock:
    """Acquire the non-blocking advisory lock shared by server and operator tools."""

    if not state_directory.is_absolute() or state_directory == Path(
        state_directory.anchor
    ):
        raise InstanceLockError("state directory must be an absolute non-root path")
    if create_directory:
        try:
            state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            raise InstanceLockError("state directory cannot be created") from exc
    try:
        metadata = state_directory.lstat()
    except OSError as exc:
        raise InstanceLockError("state directory cannot be inspected") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise InstanceLockError("state directory must be a real directory")
    if metadata.st_uid != os.geteuid():
        raise InstanceLockError("state directory must be owned by the service user")
    try:
        state_directory.chmod(0o700)
    except OSError as exc:
        raise InstanceLockError("state directory permissions cannot be secured") from exc

    lock_path = state_directory / LOCK_FILE_NAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow:
        flags |= no_follow
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise InstanceLockError("instance lock file cannot be opened safely") from exc
    try:
        lock_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_uid != os.geteuid()
            or lock_metadata.st_nlink != 1
        ):
            raise InstanceLockError(
                "instance lock file must be one service-owned regular file"
            )
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstanceLockError(
                "another Tacua backend or operator action owns this state directory"
            ) from exc
        return StateInstanceLock(descriptor, lock_path)
    except Exception:
        os.close(descriptor)
        raise
