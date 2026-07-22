# SPDX-License-Identifier: Apache-2.0

"""Opt-in, shell-free local processing adapter.

The adapter is deliberately absent from normal backend startup.  A worker must
load one explicit command document and inject :class:`LocalProcessingAdapter`
into :class:`~tacua_backend.service.PilotBackend`.  The child receives no SDK
credential, admin secret, launch code, processing lease token, or inherited
environment.  Its only Tacua inputs are one sealed JSON document and read-only
descriptors for evidence that was reverified under the backend deletion lock.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import unicodedata
from typing import Any, Iterator, TYPE_CHECKING

from .contracts import (
    canonical_json,
    digest,
    digest_without,
    validate as protocol_validate,
    validate_operation_pair,
)
from .processing_jobs import (
    JOB_STAGES,
    ProcessingJobClaim,
    ProcessingJobStoreError,
    ProcessingResult,
    PublicationCandidate,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for static tooling
    from .service import PilotBackend


COMMAND_CONTRACT = "tacua.local-processing-command@1.0.0"
INPUT_CONTRACT = "tacua.local-processing-input@1.0.0"
RESULT_CONTRACT = "tacua.local-processing-result@1.0.0"
INPUT_PLACEHOLDER = "{input}"
OUTPUT_DIRECTORY_PLACEHOLDER = "{output_directory}"
MAX_COMMAND_FILE_BYTES = 65_536
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 32_768
MAX_RESULT_BYTES = 16_777_216
MAX_INPUT_BYTES = 16_777_216
MAX_INPUT_EVIDENCE_FILES = 512
MAX_INPUT_EVIDENCE_BYTES = 4_294_967_296
MAX_STDERR_BYTES = 1_048_576
MAX_PREVIEW_BYTES = 2_097_152
MAX_PREVIEW_FILES = 512
MAX_PREVIEW_TOTAL_BYTES = 67_108_864
MAX_PROCESSING_SECONDS = 240
_SAFE_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ProcessingAdapterError(RuntimeError):
    """A content-free processor configuration or execution failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LocalProcessorCommand:
    """One exact, bounded, shell-free command template."""

    argv: tuple[str, ...]
    timeout_seconds: int
    max_stdout_bytes: int
    max_stderr_bytes: int

    def __post_init__(self) -> None:
        argv = self.argv
        if (
            not isinstance(argv, tuple)
            or not 3 <= len(argv) <= MAX_ARGUMENTS
            or any(not isinstance(argument, str) for argument in argv)
            or any(not argument or "\x00" in argument for argument in argv)
            or any(
                unicodedata.normalize("NFC", argument) != argument
                for argument in argv
            )
            or sum(len(argument.encode("utf-8")) for argument in argv)
            > MAX_ARGUMENT_BYTES
            or argv.count(INPUT_PLACEHOLDER) != 1
            or argv.count(OUTPUT_DIRECTORY_PLACEHOLDER) != 1
            or any(
                ("{" in argument or "}" in argument)
                and argument
                not in {INPUT_PLACEHOLDER, OUTPUT_DIRECTORY_PLACEHOLDER}
                for argument in argv
            )
            or not Path(argv[0]).is_absolute()
            or isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 1 <= self.timeout_seconds <= MAX_PROCESSING_SECONDS
            or isinstance(self.max_stdout_bytes, bool)
            or not isinstance(self.max_stdout_bytes, int)
            or not 1_024 <= self.max_stdout_bytes <= MAX_RESULT_BYTES
            or isinstance(self.max_stderr_bytes, bool)
            or not isinstance(self.max_stderr_bytes, int)
            or not 1_024 <= self.max_stderr_bytes <= MAX_STDERR_BYTES
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_COMMAND_INVALID", "processor command is invalid"
            )
        try:
            executable = Path(argv[0])
            executable_metadata = executable.stat()
        except OSError as error:
            raise ProcessingAdapterError(
                "PROCESSOR_EXECUTABLE_UNAVAILABLE",
                "processor executable is unavailable",
            ) from error
        if not stat.S_ISREG(executable_metadata.st_mode) or not os.access(
            executable, os.X_OK
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_EXECUTABLE_UNSAFE",
                "processor executable is not executable",
            )

    def expand(self, *, input_path: str, output_directory: Path) -> list[str]:
        return [
            input_path
            if argument == INPUT_PLACEHOLDER
            else str(output_directory)
            if argument == OUTPUT_DIRECTORY_PLACEHOLDER
            else argument
            for argument in self.argv
        ]


@dataclass
class _ProcessingInput:
    document: dict[str, Any]
    encoded: bytes
    input_descriptor: int
    evidence_descriptors: tuple[int, ...]
    work_directory: Path
    output_directory: Path
    output_directory_descriptor: int
    output_directory_identity: tuple[int, int]

    @property
    def inherited_descriptors(self) -> tuple[int, ...]:
        return (self.input_descriptor, *self.evidence_descriptors)

    @property
    def input_path(self) -> str:
        return f"/dev/fd/{self.input_descriptor}"


def _strict_object(raw: bytes) -> dict[str, Any]:
    """Decode exact canonical JSON through the backend's strict decoder."""

    from .service import strict_json_loads

    try:
        value = strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise ProcessingAdapterError(
            "PROCESSOR_JSON_INVALID", "processor JSON is invalid"
        ) from error
    if not isinstance(value, dict) or canonical_json(value).encode("utf-8") != raw:
        raise ProcessingAdapterError(
            "PROCESSOR_JSON_NOT_CANONICAL", "processor JSON is not canonical"
        )
    return value


def _read_secure_command_file(path: Path) -> bytes:
    if not path.is_absolute():
        raise ProcessingAdapterError(
            "PROCESSOR_COMMAND_PATH_INVALID",
            "processor command document path must be absolute",
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProcessingAdapterError(
            "PROCESSOR_COMMAND_UNAVAILABLE",
            "processor command document is unavailable",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & 0o022
            or metadata.st_size < 2
            or metadata.st_size > MAX_COMMAND_FILE_BYTES
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_COMMAND_UNSAFE",
                "processor command document is not a safe immutable file",
            )
        chunks: list[bytes] = []
        remaining = MAX_COMMAND_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size or len(payload) > MAX_COMMAND_FILE_BYTES:
            raise ProcessingAdapterError(
                "PROCESSOR_COMMAND_CHANGED",
                "processor command document changed while being read",
            )
        final = os.fstat(descriptor)
        if (final.st_dev, final.st_ino, final.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_COMMAND_CHANGED",
                "processor command document changed while being read",
            )
        return payload
    finally:
        os.close(descriptor)


def load_local_processor_command(path: Path) -> LocalProcessorCommand:
    """Load one exact command document; the document's presence is opt-in."""

    document = _strict_object(_read_secure_command_file(path))
    if set(document) != {
        "contract_version",
        "argv",
        "timeout_seconds",
        "max_stdout_bytes",
        "max_stderr_bytes",
    } or document["contract_version"] != COMMAND_CONTRACT:
        raise ProcessingAdapterError(
            "PROCESSOR_COMMAND_INVALID", "processor command fields are invalid"
        )
    argv = document["argv"]
    if (
        not isinstance(argv, list)
        or not 3 <= len(argv) <= MAX_ARGUMENTS
        or any(not isinstance(argument, str) for argument in argv)
        or any(not argument or "\x00" in argument for argument in argv)
        or any(unicodedata.normalize("NFC", argument) != argument for argument in argv)
        or sum(len(argument.encode("utf-8")) for argument in argv)
        > MAX_ARGUMENT_BYTES
        or argv.count(INPUT_PLACEHOLDER) != 1
        or argv.count(OUTPUT_DIRECTORY_PLACEHOLDER) != 1
        or any(
            ("{" in argument or "}" in argument)
            and argument not in {INPUT_PLACEHOLDER, OUTPUT_DIRECTORY_PLACEHOLDER}
            for argument in argv
        )
        or not Path(argv[0]).is_absolute()
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_ARGV_INVALID", "processor argv is invalid"
        )
    executable = Path(argv[0])
    try:
        executable_metadata = executable.stat()
    except OSError as error:
        raise ProcessingAdapterError(
            "PROCESSOR_EXECUTABLE_UNAVAILABLE",
            "processor executable is unavailable",
        ) from error
    if not stat.S_ISREG(executable_metadata.st_mode) or not os.access(
        executable, os.X_OK
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_EXECUTABLE_UNSAFE", "processor executable is not executable"
        )

    timeout = document["timeout_seconds"]
    stdout_limit = document["max_stdout_bytes"]
    stderr_limit = document["max_stderr_bytes"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= MAX_PROCESSING_SECONDS
        or isinstance(stdout_limit, bool)
        or not isinstance(stdout_limit, int)
        or not 1_024 <= stdout_limit <= MAX_RESULT_BYTES
        or isinstance(stderr_limit, bool)
        or not isinstance(stderr_limit, int)
        or not 1_024 <= stderr_limit <= MAX_STDERR_BYTES
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_LIMIT_INVALID", "processor limits are invalid"
        )
    return LocalProcessorCommand(
        argv=tuple(argv),
        timeout_seconds=timeout,
        max_stdout_bytes=stdout_limit,
        max_stderr_bytes=stderr_limit,
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    # The command leader may exit after forking a descendant.  Checking only
    # ``process.poll()`` would then leave that descendant alive with inherited
    # evidence descriptors after the backend releases its deletion lock.
    # Every command gets a fresh session/process group, so retire the whole
    # group even when its original leader has already exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()


def _run_bounded_command(
    command: LocalProcessorCommand,
    argv: list[str],
    *,
    cwd: Path,
    pass_fds: tuple[int, ...],
) -> bytes:
    """Run without a shell or inherited environment and cap both pipes."""

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
            umask=0o077,
        )
    except OSError as error:
        raise ProcessingAdapterError(
            "PROCESSOR_START_FAILED", "processor could not be started"
        ) from error
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_descriptor = process.stdout.fileno()
    streams = {
        stdout_descriptor: (process.stdout, bytearray(), command.max_stdout_bytes),
        process.stderr.fileno(): (process.stderr, bytearray(), command.max_stderr_bytes),
    }
    selector = selectors.DefaultSelector()
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + command.timeout_seconds
    failure: ProcessingAdapterError | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = ProcessingAdapterError(
                    "PROCESSOR_TIMEOUT", "processor exceeded its configured timeout"
                )
                break
            events = selector.select(timeout=min(remaining, 0.1))
            for key, _event in events:
                descriptor = int(key.fd)
                stream, buffer, limit = streams[descriptor]
                try:
                    chunk = os.read(descriptor, min(65_536, limit + 1 - len(buffer)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > limit:
                    failure = ProcessingAdapterError(
                        "PROCESSOR_OUTPUT_LIMIT",
                        "processor exceeded a configured output limit",
                    )
                    break
            if failure is not None:
                break
        if failure is not None:
            _kill_process_group(process)
            raise failure
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if return_code != 0:
            raise ProcessingAdapterError(
                "PROCESSOR_EXIT_FAILED", "processor exited unsuccessfully"
            )
        return bytes(streams[stdout_descriptor][1])
    except subprocess.TimeoutExpired as error:
        _kill_process_group(process)
        raise ProcessingAdapterError(
            "PROCESSOR_TIMEOUT", "processor exceeded its configured timeout"
        ) from error
    finally:
        selector.close()
        for stream, _buffer, _limit in streams.values():
            if not stream.closed:
                stream.close()
        # A successful leader is not permission for forked descendants to
        # retain evidence FDs or race output verification.
        _kill_process_group(process)


def _source_file_descriptor(
    backend: PilotBackend,
    *,
    relative_path: str,
    session_id: str,
    category: str,
    size_bytes: int,
    content_digest: str,
) -> int:
    relative = Path(relative_path)
    if (
        relative.is_absolute()
        or len(relative.parts) != 4
        or relative.parts[:3] != ("objects", session_id, category)
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_EVIDENCE_PATH_INVALID",
            "verified evidence path is invalid",
        )
    path = backend.state_dir.joinpath(*relative.parts)
    root = backend.objects_dir.resolve(strict=True)
    try:
        path.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise ProcessingAdapterError(
            "PROCESSOR_EVIDENCE_PATH_INVALID",
            "verified evidence path escaped storage",
        ) from error
    current = backend.state_dir
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ProcessingAdapterError(
                "PROCESSOR_EVIDENCE_UNAVAILABLE", "verified evidence is unavailable"
            ) from error
        if current == path:
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ProcessingAdapterError(
                    "PROCESSOR_EVIDENCE_UNSAFE", "verified evidence is not a regular file"
                )
        elif not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ProcessingAdapterError(
                "PROCESSOR_EVIDENCE_UNSAFE", "verified evidence parent is unsafe"
            )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProcessingAdapterError(
            "PROCESSOR_EVIDENCE_UNAVAILABLE", "verified evidence is unavailable"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size != size_bytes
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_EVIDENCE_CHANGED", "verified evidence metadata changed"
            )
        hasher = hashlib.sha256()
        remaining = size_bytes
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            hasher.update(chunk)
            remaining -= len(chunk)
        if (
            remaining != 0
            or os.read(descriptor, 1)
            or not hmac.compare_digest(
                "sha256:" + hasher.hexdigest(), content_digest
            )
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_EVIDENCE_CHANGED", "verified evidence bytes changed"
            )
        # Stored capture objects are immutable after admission.  Removing the
        # owner write bit makes the descriptor path read-only for an ordinary
        # local child as well as opening the inherited descriptor O_RDONLY.
        os.fchmod(descriptor, 0o400)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _validate_segment_row(
    backend: PilotBackend,
    row: Any,
    *,
    session_id: str,
) -> tuple[dict[str, Any], int]:
    try:
        request = backend._decode_protocol_object(row["request_json"])
        receipt = backend._decode_protocol_object(bytes(row["response_bytes"]))
        protocol_validate(request)
        protocol_validate(receipt)
        validate_operation_pair(request, receipt)
        runtime = receipt["runtime_receipt"]
        expected = (
            request["message_type"] == "segment_upload_intent"
            and request["session_id"] == session_id == row["session_id"]
            and request["upload_id"] == row["upload_id"] == receipt["upload_id"]
            and request["sequence"] == row["sequence"] == receipt["sequence"]
            and request["segment_id"] == row["segment_id"] == receipt["segment_id"]
            and request["intent_digest"] == row["request_digest"]
            and request["transport"]["content_type"]
            == row["content_type"]
            == receipt["content_type"]
            and request["transport"]["size_bytes"]
            == row["size_bytes"]
            == runtime["size_bytes"]
            and request["transport"]["content_digest"]
            == row["content_digest"]
            == runtime["content_digest"]
            == receipt["transport_digest"]
            and request["sidecar_digest"]
            == row["sidecar_digest"]
            == receipt["sidecar_digest"]
            and row["object_id"] == runtime["object_id"]
            and row["accepted_at"] == runtime["received_at"]
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProcessingAdapterError(
            "PROCESSOR_EVIDENCE_BINDING_INVALID",
            "segment evidence binding is invalid",
        ) from error
    if not expected:
        raise ProcessingAdapterError(
            "PROCESSOR_EVIDENCE_BINDING_INVALID",
            "segment evidence binding is invalid",
        )
    descriptor = _source_file_descriptor(
        backend,
        relative_path=row["relative_path"],
        session_id=session_id,
        category="segments",
        size_bytes=row["size_bytes"],
        content_digest=row["content_digest"],
    )
    return (
        {
            "segment_id": row["segment_id"],
            "sequence": row["sequence"],
            "content_type": row["content_type"],
            "size_bytes": row["size_bytes"],
            "content_digest": row["content_digest"],
            "sidecar_digest": row["sidecar_digest"],
            "received_at": row["accepted_at"],
            "read_only_path": f"/dev/fd/{descriptor}",
        },
        descriptor,
    )


def _validate_diagnostic_row(
    backend: PilotBackend,
    row: Any,
    *,
    session_id: str,
) -> tuple[dict[str, Any], int]:
    try:
        request = backend._decode_protocol_object(row["request_json"])
        receipt = backend._decode_protocol_object(bytes(row["response_bytes"]))
        protocol_validate(request)
        protocol_validate(receipt)
        validate_operation_pair(request, receipt)
        envelope = request["envelope"]
        expected = (
            request["message_type"] == "diagnostic_upload_request"
            and request["session_id"] == session_id == row["session_id"]
            and request["upload_id"] == row["upload_id"] == receipt["upload_id"]
            and request["request_digest"] == row["request_digest"]
            and row["envelope_id"] == envelope["envelope_id"] == receipt["envelope_id"]
            and row["object_id"] == receipt["object_id"]
            and row["size_bytes"] == receipt["size_bytes"]
            and row["content_digest"] == receipt["transport_digest"]
            and envelope["envelope_digest"] == receipt["envelope_digest"]
            and envelope["organization_id"] == backend.config.organization_id
            and envelope["project_id"] == backend.config.project_id
            and envelope["session_id"] == session_id
            and envelope["build_id"] == backend.config.build_id
            and envelope["build_identity_digest"]
            == backend.config.build_identity_digest
            and row["accepted_at"] == receipt["received_at"]
            and row["size_bytes"] == len(canonical_json(envelope).encode("utf-8"))
            and row["content_digest"]
            == digest(canonical_json(envelope).encode("utf-8"))
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProcessingAdapterError(
            "PROCESSOR_EVIDENCE_BINDING_INVALID",
            "diagnostic evidence binding is invalid",
        ) from error
    if not expected:
        raise ProcessingAdapterError(
            "PROCESSOR_EVIDENCE_BINDING_INVALID",
            "diagnostic evidence binding is invalid",
        )
    descriptor = _source_file_descriptor(
        backend,
        relative_path=row["relative_path"],
        session_id=session_id,
        category="diagnostics",
        size_bytes=row["size_bytes"],
        content_digest=row["content_digest"],
    )
    return (
        {
            "envelope_id": row["envelope_id"],
            "envelope_digest": request["envelope"]["envelope_digest"],
            "size_bytes": row["size_bytes"],
            "content_digest": row["content_digest"],
            "received_at": row["accepted_at"],
            "read_only_path": f"/dev/fd/{descriptor}",
        },
        descriptor,
    )


def _remove_workspace(path: Path, expected_parent: Path) -> None:
    """Remove one exact generated workspace without following child symlinks."""

    try:
        if path.parent != expected_parent or not path.name.startswith("processing-"):
            raise ProcessingAdapterError(
                "PROCESSOR_WORKSPACE_INVALID", "processor workspace is invalid"
            )
        if path.is_symlink():
            path.unlink(missing_ok=True)
            return
        if not path.exists():
            return
        for root, directories, files in os.walk(path, topdown=False, followlinks=False):
            root_path = Path(root)
            for name in files:
                (root_path / name).unlink(missing_ok=True)
            for name in directories:
                child = root_path / name
                if child.is_symlink():
                    child.unlink(missing_ok=True)
                else:
                    child.rmdir()
        path.rmdir()
    except ProcessingAdapterError:
        raise
    except OSError as error:
        raise ProcessingAdapterError(
            "PROCESSOR_WORKSPACE_CLEANUP_FAILED",
            "processor workspace could not be removed",
        ) from error


def _create_input_descriptor(work_directory: Path, payload: bytes) -> int:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="input-", suffix=".json", dir=work_directory
    )
    temporary = Path(temporary_name)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.close(descriptor)
        descriptor = -1
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        read_descriptor = os.open(temporary, flags)
        temporary.unlink()
        return read_descriptor
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


@contextmanager
def _processing_input(
    backend: PilotBackend, claim: ProcessingJobClaim
) -> Iterator[_ProcessingInput]:
    """Hold deletion exclusion while verified read-only evidence is exposed."""

    descriptors: list[int] = []
    input_descriptor = -1
    output_directory_descriptor = -1
    work_directory = backend.temp_dir / (
        f"processing-{claim.job['job_id']}-{claim.job['job_version']}-{claim.stage_name}"
    )
    with backend._lock:
        try:
            work_directory.mkdir(mode=0o700)
            output_directory = work_directory / "output"
            output_directory.mkdir(mode=0o700)
            output_directory_descriptor = os.open(
                output_directory,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            output_metadata = os.fstat(output_directory_descriptor)
            with backend._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    job, worker_id = backend._processing_job_store(
                        connection
                    ).validate_stage_lease(
                        claim.job["job_id"], claim.stage_name, claim.lease_token
                    )
                except ProcessingJobStoreError as error:
                    backend._raise_processing_job_error(error)
                if (
                    canonical_json(job) != canonical_json(claim.job)
                    or worker_id != claim.worker_id
                ):
                    raise ProcessingAdapterError(
                        "PROCESSOR_CLAIM_CHANGED",
                        "processing claim changed before evidence admission",
                    )
                session = connection.execute(
                    """SELECT state,build_identity_json,created_at,completed_at,
                              raw_media_expires_at,derived_data_expires_at
                         FROM sessions WHERE session_id = ?""",
                    (job["session_id"],),
                ).fetchone()
                completion = connection.execute(
                    """SELECT request_json,response_bytes,relative_path,size_bytes,
                              content_digest,accepted_at
                         FROM completions WHERE session_id = ?""",
                    (job["session_id"],),
                ).fetchone()
                if session is None or completion is None or session["state"] != "completed":
                    raise ProcessingAdapterError(
                        "PROCESSOR_SESSION_UNAVAILABLE",
                        "processing session is unavailable",
                    )
                completion_request = backend._decode_protocol_object(
                    completion["request_json"]
                )
                completion_receipt = backend._decode_protocol_object(
                    bytes(completion["response_bytes"])
                )
                try:
                    protocol_validate(completion_request)
                    protocol_validate(completion_receipt)
                    validate_operation_pair(completion_request, completion_receipt)
                except (KeyError, TypeError, ValueError) as error:
                    raise ProcessingAdapterError(
                        "PROCESSOR_COMPLETION_BINDING_INVALID",
                        "processing completion binding is invalid",
                    ) from error
                completion_bytes = canonical_json(completion_request).encode("utf-8")
                if (
                    completion_request["session_id"] != job["session_id"]
                    or completion_receipt["session_id"] != job["session_id"]
                    or completion_receipt["processing_job"]["job_id"]
                    != job["job_id"]
                    or completion["accepted_at"] != job["requested_at"]
                    or completion["size_bytes"] != len(completion_bytes)
                    or completion["content_digest"] != digest(completion_bytes)
                ):
                    raise ProcessingAdapterError(
                        "PROCESSOR_COMPLETION_BINDING_INVALID",
                        "processing completion binding is invalid",
                    )
                completion_descriptor = _source_file_descriptor(
                    backend,
                    relative_path=completion["relative_path"],
                    session_id=job["session_id"],
                    category="completion",
                    size_bytes=completion["size_bytes"],
                    content_digest=completion["content_digest"],
                )
                os.close(completion_descriptor)

                segment_documents: list[dict[str, Any]] = []
                segment_rows = connection.execute(
                    "SELECT * FROM segments WHERE session_id = ? ORDER BY sequence",
                    (job["session_id"],),
                ).fetchall()
                diagnostic_rows = connection.execute(
                    """SELECT * FROM diagnostics WHERE session_id = ?
                         ORDER BY accepted_at,upload_id""",
                    (job["session_id"],),
                ).fetchall()
                if (
                    len(segment_rows) + len(diagnostic_rows)
                    > MAX_INPUT_EVIDENCE_FILES
                    or sum(
                        row["size_bytes"]
                        for row in (*segment_rows, *diagnostic_rows)
                    )
                    > MAX_INPUT_EVIDENCE_BYTES
                ):
                    raise ProcessingAdapterError(
                        "PROCESSOR_INPUT_TOO_LARGE",
                        "processing input evidence exceeds a bound",
                    )
                for row in segment_rows:
                    document, descriptor = _validate_segment_row(
                        backend, row, session_id=job["session_id"]
                    )
                    segment_documents.append(document)
                    descriptors.append(descriptor)

                diagnostic_documents: list[dict[str, Any]] = []
                for row in diagnostic_rows:
                    document, descriptor = _validate_diagnostic_row(
                        backend, row, session_id=job["session_id"]
                    )
                    diagnostic_documents.append(document)
                    descriptors.append(descriptor)

                build_identity = backend._decode_protocol_object(
                    session["build_identity_json"]
                )
                protocol_validate(build_identity)
                processing_document = {
                    "contract_version": INPUT_CONTRACT,
                    "input_digest": "sha256:" + "0" * 64,
                    "binding": {
                        "organization_id": job["organization_id"],
                        "project_id": job["project_id"],
                        "session_id": job["session_id"],
                        "build_id": job["build_id"],
                        "build_identity_digest": job["build_identity_digest"],
                        "job_id": job["job_id"],
                        "job_version": job["job_version"],
                        "job_digest": job["job_digest"],
                        "stage_name": claim.stage_name,
                        "worker_id": claim.worker_id,
                    },
                    "job": job,
                    "capture": {
                        "build_identity": build_identity,
                        "manifest": completion_request["capture_manifest"],
                        "session_created_at": session["created_at"],
                        "session_completed_at": session["completed_at"],
                        "raw_media_expires_at": session["raw_media_expires_at"],
                        "derived_data_expires_at": session[
                            "derived_data_expires_at"
                        ],
                        "segments": segment_documents,
                        "diagnostics": diagnostic_documents,
                    },
                }
                processing_document["input_digest"] = digest_without(
                    processing_document, "input_digest"
                )
                encoded = canonical_json(processing_document).encode("utf-8")
                if len(encoded) > MAX_INPUT_BYTES:
                    raise ProcessingAdapterError(
                        "PROCESSOR_INPUT_TOO_LARGE",
                        "processing input exceeds the byte bound",
                    )
                input_descriptor = _create_input_descriptor(work_directory, encoded)

            # Refresh the five-minute lease after potentially hashing a large
            # recording.  The child timeout leaves at least sixty seconds for
            # exact output validation and atomic publication.
            from .service import ApiError

            try:
                backend.renew_processing_lease(
                    claim.job["job_id"], claim.stage_name, claim.lease_token
                )
            except ApiError as error:
                # A same-second claim is already at the maximum rolling
                # horizon.  Every other heartbeat failure invalidates the run.
                if getattr(error, "code", None) != "PROCESSING_LEASE_RENEWAL_EARLY":
                    raise
            yield _ProcessingInput(
                document=processing_document,
                encoded=encoded,
                input_descriptor=input_descriptor,
                evidence_descriptors=tuple(descriptors),
                work_directory=work_directory,
                output_directory=output_directory,
                output_directory_descriptor=output_directory_descriptor,
                output_directory_identity=(
                    output_metadata.st_dev,
                    output_metadata.st_ino,
                ),
            )
        finally:
            if input_descriptor >= 0:
                os.close(input_descriptor)
            for descriptor in descriptors:
                os.close(descriptor)
            if output_directory_descriptor >= 0:
                os.close(output_directory_descriptor)
            _remove_workspace(work_directory, backend.temp_dir)


def _preview_body(
    snapshot: _ProcessingInput,
    descriptor: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    if set(descriptor) != {
        "evidence_id",
        "preview_revision_id",
        "content_type",
        "size_bytes",
        "content_digest",
        "body_file",
    }:
        raise ProcessingAdapterError(
            "PROCESSOR_RESULT_INVALID", "processor preview fields are invalid"
        )
    body_file = descriptor["body_file"]
    size_bytes = descriptor["size_bytes"]
    if (
        not isinstance(body_file, str)
        or _SAFE_FILE_NAME.fullmatch(body_file) is None
        or isinstance(size_bytes, bool)
        or not isinstance(size_bytes, int)
        or not 1 <= size_bytes <= MAX_PREVIEW_BYTES
        or not isinstance(descriptor["content_digest"], str)
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_RESULT_INVALID", "processor preview fields are invalid"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        file_descriptor = os.open(
            body_file,
            flags,
            dir_fd=snapshot.output_directory_descriptor,
        )
    except OSError as error:
        raise ProcessingAdapterError(
            "PROCESSOR_PREVIEW_UNAVAILABLE", "processor preview is unavailable"
        ) from error
    try:
        metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size != size_bytes
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_PREVIEW_INVALID", "processor preview metadata is invalid"
            )
        chunks: list[bytes] = []
        remaining = size_bytes
        while remaining:
            chunk = os.read(file_descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        if (
            remaining
            or os.read(file_descriptor, 1)
            or not hmac.compare_digest(digest(body), descriptor["content_digest"])
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_PREVIEW_INVALID", "processor preview bytes are invalid"
            )
    finally:
        os.close(file_descriptor)
    preview = dict(descriptor)
    preview.pop("body_file")
    preview["body"] = body
    return preview, body_file


def _output_names(snapshot: _ProcessingInput) -> set[str]:
    """List output entries through the retained directory descriptor."""

    metadata = os.fstat(snapshot.output_directory_descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != snapshot.output_directory_identity
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_OUTPUT_DIRECTORY_CHANGED",
            "processor output directory changed",
        )
    try:
        path_metadata = snapshot.output_directory.lstat()
    except OSError as error:
        raise ProcessingAdapterError(
            "PROCESSOR_OUTPUT_DIRECTORY_CHANGED",
            "processor output directory changed",
        ) from error
    if (
        not stat.S_ISDIR(path_metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or (path_metadata.st_dev, path_metadata.st_ino)
        != snapshot.output_directory_identity
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_OUTPUT_DIRECTORY_CHANGED",
            "processor output directory changed",
        )
    names = set(os.listdir(snapshot.output_directory_descriptor))
    for name in names:
        try:
            entry = os.stat(
                name,
                dir_fd=snapshot.output_directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ProcessingAdapterError(
                "PROCESSOR_OUTPUT_INVALID", "processor output entry changed"
            ) from error
        if (
            _SAFE_FILE_NAME.fullmatch(name) is None
            or not stat.S_ISREG(entry.st_mode)
            or entry.st_uid != os.geteuid()
            or entry.st_nlink != 1
        ):
            raise ProcessingAdapterError(
                "PROCESSOR_OUTPUT_INVALID", "processor output contains an unsafe entry"
            )
    return names


def _parse_result(raw: bytes, snapshot: _ProcessingInput) -> ProcessingResult | None:
    document = _strict_object(raw)
    if set(document) != {
        "contract_version",
        "input_digest",
        "job_id",
        "job_digest",
        "session_id",
        "stage_name",
        "disposition",
        "result",
    }:
        raise ProcessingAdapterError(
            "PROCESSOR_RESULT_INVALID", "processor result fields are invalid"
        )
    binding = snapshot.document["binding"]
    if (
        document["contract_version"] != RESULT_CONTRACT
        or document["input_digest"] != snapshot.document["input_digest"]
        or document["job_id"] != binding["job_id"]
        or document["job_digest"] != binding["job_digest"]
        or document["session_id"] != binding["session_id"]
        or document["stage_name"] != binding["stage_name"]
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_RESULT_BINDING_MISMATCH",
            "processor result binding differs from its input",
        )
    final_stage = binding["stage_name"] == JOB_STAGES[-1]
    if not final_stage:
        if document["disposition"] != "checkpoint" or document["result"] is not None:
            raise ProcessingAdapterError(
                "PROCESSOR_RESULT_INVALID",
                "non-final processor result must be an exact checkpoint",
            )
        if _output_names(snapshot):
            raise ProcessingAdapterError(
                "PROCESSOR_RESULT_INVALID",
                "checkpoint processor left unexpected output files",
            )
        return None
    if document["disposition"] != "terminal" or not isinstance(
        document["result"], dict
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_RESULT_INVALID",
            "final processor result must be terminal",
        )
    result = document["result"]
    if set(result) != {"disposition", "summary", "candidates"} or not isinstance(
        result["candidates"], list
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_RESULT_INVALID", "terminal processor result is invalid"
        )
    bundles: list[PublicationCandidate] = []
    referenced_files: set[str] = set()
    total_preview_bytes = 0
    for bundle in result["candidates"]:
        if not isinstance(bundle, dict) or set(bundle) != {
            "candidate",
            "evidence_manifest",
            "previews",
        } or not isinstance(bundle["previews"], list):
            raise ProcessingAdapterError(
                "PROCESSOR_RESULT_INVALID", "processor candidate bundle is invalid"
            )
        previews: list[dict[str, Any]] = []
        for preview_descriptor in bundle["previews"]:
            if not isinstance(preview_descriptor, dict):
                raise ProcessingAdapterError(
                    "PROCESSOR_RESULT_INVALID", "processor preview is invalid"
                )
            preview, file_name = _preview_body(snapshot, preview_descriptor)
            if file_name in referenced_files:
                raise ProcessingAdapterError(
                    "PROCESSOR_RESULT_INVALID",
                    "processor preview file was referenced more than once",
                )
            referenced_files.add(file_name)
            total_preview_bytes += preview["size_bytes"]
            if (
                len(referenced_files) > MAX_PREVIEW_FILES
                or total_preview_bytes > MAX_PREVIEW_TOTAL_BYTES
            ):
                raise ProcessingAdapterError(
                    "PROCESSOR_RESULT_INVALID", "processor previews exceed the bound"
                )
            previews.append(preview)
        bundles.append(
            PublicationCandidate(
                candidate=bundle["candidate"],
                evidence_manifest=bundle["evidence_manifest"],
                previews=tuple(previews),
            )
        )
    actual_files = _output_names(snapshot)
    if actual_files != referenced_files:
        raise ProcessingAdapterError(
            "PROCESSOR_OUTPUT_INVALID",
            "processor output files differ from the terminal result",
        )
    return ProcessingResult(
        disposition=result["disposition"],
        summary=result["summary"],
        candidates=tuple(bundles),
    )


class LocalProcessingAdapter:
    """Provider-neutral command adapter for one explicitly configured worker."""

    def __init__(self, command: LocalProcessorCommand):
        if not isinstance(command, LocalProcessorCommand):
            raise TypeError("command must be a LocalProcessorCommand")
        self.command = command
        self._backend: PilotBackend | None = None

    def bind_backend(self, backend: PilotBackend) -> None:
        if self._backend is not None:
            raise RuntimeError("local processing adapter is already bound")
        self._backend = backend

    def process_stage(self, claim: ProcessingJobClaim) -> ProcessingResult | None:
        backend = self._backend
        if backend is None:
            raise ProcessingAdapterError(
                "PROCESSOR_NOT_BOUND", "local processing adapter is not bound"
            )
        with _processing_input(backend, claim) as snapshot:
            argv = self.command.expand(
                input_path=snapshot.input_path,
                output_directory=snapshot.output_directory,
            )
            raw = _run_bounded_command(
                self.command,
                argv,
                cwd=snapshot.work_directory,
                pass_fds=snapshot.inherited_descriptors,
            )
            return _parse_result(raw, snapshot)
