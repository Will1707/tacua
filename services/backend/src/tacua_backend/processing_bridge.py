# SPDX-License-Identifier: Apache-2.0

"""Narrow Unix-socket client for the host-side Compose processing bridge.

The exclusive processing worker runs in a one-shot container that owns the
deployment state volume.  This module sends only the adapter's already-open
read-only input/evidence descriptors to a trusted host broker with
``SCM_RIGHTS``.  The broker, not this container, owns Docker authority.
"""

from __future__ import annotations

import argparse
from array import array
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import tempfile
from typing import Any, Sequence
import unicodedata


REQUEST_CONTRACT = "tacua.compose-processing-bridge-request@1.0.0"
RESPONSE_CONTRACT = "tacua.compose-processing-bridge-response@1.0.0"
MAX_HEADER_BYTES = 262_144
MAX_INPUT_BYTES = 16_777_216
MAX_EVIDENCE_FILES = 512
MAX_RESULT_BYTES = 16_777_216
MAX_PREVIEW_FILES = 512
MAX_PREVIEW_BYTES = 2_097_152
MAX_OUTPUT_BYTES = 67_108_864
MAX_JSON_DEPTH = 64
MAX_JSON_VALUES = 1_000_000
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
MAX_ADAPTER_DESCRIPTOR = 1_023
FD_BATCH_SIZE = 64
BRIDGE_TIMEOUT_SECONDS = 225
DESCRIPTOR_PATH = re.compile(r"^/dev/fd/([0-9]+)$")
SAFE_OUTPUT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


class ProcessingBridgeError(RuntimeError):
    """Stable, content-free bridge failure."""

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(detail)


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProcessingBridgeError(
                "BRIDGE_JSON_INVALID",
                "bridge JSON contains a duplicate key",
            )
        result[key] = value
    return result


def _reject_float(_value: str) -> None:
    raise ProcessingBridgeError(
        "BRIDGE_JSON_INVALID",
        "bridge JSON does not admit floating point values",
    )


def _parse_integer(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_JSON_INTEGER:
        raise ProcessingBridgeError(
            "BRIDGE_JSON_INVALID",
            "bridge JSON integer is outside the safe range",
        )
    return parsed


def _validate_json_value(value: Any) -> None:
    pending: list[tuple[Any, int]] = [(value, 1)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if count > MAX_JSON_VALUES or depth > MAX_JSON_DEPTH:
            raise ProcessingBridgeError(
                "BRIDGE_JSON_INVALID",
                "bridge JSON exceeds its structural bound",
            )
        if current is None or type(current) in {bool, int}:
            if type(current) is int and abs(current) > MAX_SAFE_JSON_INTEGER:
                raise ProcessingBridgeError(
                    "BRIDGE_JSON_INVALID",
                    "bridge JSON integer is outside the safe range",
                )
            continue
        if type(current) is str:
            if unicodedata.normalize("NFC", current) != current:
                raise ProcessingBridgeError(
                    "BRIDGE_JSON_INVALID",
                    "bridge JSON string is not NFC",
                )
            try:
                current.encode("utf-8")
            except UnicodeError as error:
                raise ProcessingBridgeError(
                    "BRIDGE_JSON_INVALID",
                    "bridge JSON string is not valid UTF-8",
                ) from error
            continue
        if type(current) is list:
            pending.extend((item, depth + 1) for item in current)
            continue
        if type(current) is dict:
            for key, item in current.items():
                if (
                    type(key) is not str
                    or unicodedata.normalize("NFC", key) != key
                ):
                    raise ProcessingBridgeError(
                        "BRIDGE_JSON_INVALID",
                        "bridge JSON key is not an NFC string",
                    )
                pending.append((item, depth + 1))
            continue
        raise ProcessingBridgeError(
            "BRIDGE_JSON_INVALID",
            "bridge JSON contains an unsupported value",
        )


def canonical_json(value: Any) -> bytes:
    _validate_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_canonical_object(payload: bytes, *, maximum: int) -> dict[str, Any]:
    if not payload or len(payload) > maximum:
        raise ProcessingBridgeError(
            "BRIDGE_JSON_INVALID",
            "bridge JSON violates its byte bound",
        )
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
        _validate_json_value(value)
        encoded = canonical_json(value)
    except (
        ProcessingBridgeError,
        UnicodeError,
        ValueError,
        RecursionError,
        json.JSONDecodeError,
    ) as error:
        if isinstance(error, ProcessingBridgeError):
            raise
        raise ProcessingBridgeError(
            "BRIDGE_JSON_INVALID",
            "bridge JSON is invalid",
        ) from error
    if not isinstance(value, dict) or encoded != payload:
        raise ProcessingBridgeError(
            "BRIDGE_JSON_INVALID",
            "bridge JSON must be one canonical object",
        )
    return value


def _descriptor_number(path: str) -> int:
    match = DESCRIPTOR_PATH.fullmatch(path)
    if match is None:
        raise ProcessingBridgeError(
            "BRIDGE_DESCRIPTOR_INVALID",
            "adapter input did not use a descriptor capability",
        )
    descriptor = int(match.group(1))
    if not 3 <= descriptor <= MAX_ADAPTER_DESCRIPTOR:
        raise ProcessingBridgeError(
            "BRIDGE_DESCRIPTOR_INVALID",
            "adapter descriptor is outside the bridge bound",
        )
    return descriptor


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    try:
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise ProcessingBridgeError(
            "BRIDGE_INPUT_INVALID",
            "adapter input descriptor is unavailable",
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        raise ProcessingBridgeError(
            "BRIDGE_INPUT_INVALID",
            "adapter input descriptor violates its bound",
        )
    blocks: list[bytes] = []
    offset = 0
    while offset < metadata.st_size:
        try:
            block = os.pread(
                descriptor,
                min(1_048_576, metadata.st_size - offset),
                offset,
            )
        except OSError as error:
            raise ProcessingBridgeError(
                "BRIDGE_INPUT_INVALID",
                "adapter input descriptor could not be read",
            ) from error
        if not block:
            raise ProcessingBridgeError(
                "BRIDGE_INPUT_INVALID",
                "adapter input descriptor ended early",
            )
        blocks.append(block)
        offset += len(block)
    final = os.fstat(descriptor)
    if (
        final.st_size != metadata.st_size
        or final.st_mtime_ns != metadata.st_mtime_ns
        or final.st_ctime_ns != metadata.st_ctime_ns
    ):
        raise ProcessingBridgeError(
            "BRIDGE_INPUT_INVALID",
            "adapter input changed while it was read",
        )
    return b"".join(blocks)


def adapter_descriptor_targets(input_path: Path) -> tuple[int, ...]:
    """Validate one canonical adapter input and return input/evidence FD targets."""

    input_descriptor = _descriptor_number(str(input_path))
    payload = _read_descriptor(input_descriptor, MAX_INPUT_BYTES)
    document = parse_canonical_object(payload, maximum=MAX_INPUT_BYTES)
    capture = document.get("capture")
    if not isinstance(capture, dict):
        raise ProcessingBridgeError(
            "BRIDGE_INPUT_INVALID",
            "adapter input capture is missing",
        )
    references: list[Any] = []
    for field in ("segments", "diagnostics"):
        entries = capture.get(field)
        if not isinstance(entries, list):
            raise ProcessingBridgeError(
                "BRIDGE_INPUT_INVALID",
                "adapter evidence list is invalid",
            )
        references.extend(entries)
    if len(references) > MAX_EVIDENCE_FILES:
        raise ProcessingBridgeError(
            "BRIDGE_INPUT_INVALID",
            "adapter evidence count exceeds the bridge bound",
        )
    targets = [input_descriptor]
    for reference in references:
        if not isinstance(reference, dict):
            raise ProcessingBridgeError(
                "BRIDGE_INPUT_INVALID",
                "adapter evidence reference is invalid",
            )
        read_only_path = reference.get("read_only_path")
        if not isinstance(read_only_path, str):
            raise ProcessingBridgeError(
                "BRIDGE_INPUT_INVALID",
                "adapter evidence descriptor is missing",
            )
        targets.append(_descriptor_number(read_only_path))
    if len(set(targets)) != len(targets):
        raise ProcessingBridgeError(
            "BRIDGE_DESCRIPTOR_INVALID",
            "adapter descriptor capabilities are not unique",
        )
    for descriptor in targets:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProcessingBridgeError(
                "BRIDGE_DESCRIPTOR_INVALID",
                "adapter capability is not a regular file",
            )
    return tuple(targets)


def send_frame(stream: socket.socket, document: dict[str, Any]) -> None:
    payload = canonical_json(document)
    if len(payload) > MAX_HEADER_BYTES:
        raise ProcessingBridgeError(
            "BRIDGE_PROTOCOL_INVALID",
            "bridge frame exceeds its byte bound",
        )
    stream.sendall(struct.pack("!I", len(payload)) + payload)


def _receive_exact(stream: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        block = stream.recv(size - len(result))
        if not block:
            raise ProcessingBridgeError(
                "BRIDGE_PROTOCOL_INVALID",
                "bridge stream ended early",
            )
        result.extend(block)
    return bytes(result)


def receive_frame(stream: socket.socket) -> dict[str, Any]:
    length = struct.unpack("!I", _receive_exact(stream, 4))[0]
    if not 1 <= length <= MAX_HEADER_BYTES:
        raise ProcessingBridgeError(
            "BRIDGE_PROTOCOL_INVALID",
            "bridge frame length is invalid",
        )
    return parse_canonical_object(
        _receive_exact(stream, length),
        maximum=MAX_HEADER_BYTES,
    )


def send_descriptor_batches(
    stream: socket.socket,
    descriptors: Sequence[int],
) -> None:
    for offset in range(0, len(descriptors), FD_BATCH_SIZE):
        batch = array("i", descriptors[offset : offset + FD_BATCH_SIZE])
        sent = stream.sendmsg(
            [b"F"],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, batch)],
        )
        if sent != 1:
            raise ProcessingBridgeError(
                "BRIDGE_PROTOCOL_INVALID",
                "bridge descriptor batch was not transferred",
            )


def receive_descriptor_batches(
    stream: socket.socket,
    count: int,
) -> tuple[int, ...]:
    if not 1 <= count <= MAX_EVIDENCE_FILES + 1:
        raise ProcessingBridgeError(
            "BRIDGE_PROTOCOL_INVALID",
            "bridge descriptor count is invalid",
        )
    received: list[int] = []
    try:
        while len(received) < count:
            expected = min(FD_BATCH_SIZE, count - len(received))
            message, ancillary, flags, _address = stream.recvmsg(
                1,
                socket.CMSG_SPACE(expected * array("i").itemsize),
                getattr(socket, "MSG_CMSG_CLOEXEC", 0),
            )
            batch: list[int] = []
            try:
                ancillary_invalid = False
                for level, kind, data in ancillary:
                    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                        ancillary_invalid = True
                        continue
                    values = array("i")
                    usable = len(data) - (len(data) % values.itemsize)
                    if usable != len(data):
                        ancillary_invalid = True
                    values.frombytes(data[:usable])
                    batch.extend(values.tolist())
                if (
                    message != b"F"
                    or flags & (
                        getattr(socket, "MSG_CTRUNC", 0)
                        | getattr(socket, "MSG_TRUNC", 0)
                    )
                    or ancillary_invalid
                    or len(batch) != expected
                ):
                    raise ProcessingBridgeError(
                        "BRIDGE_PROTOCOL_INVALID",
                        "bridge descriptor batch is truncated or invalid",
                    )
            except Exception:
                for descriptor in batch:
                    os.close(descriptor)
                raise
            received.extend(batch)
        return tuple(received)
    except Exception:
        for descriptor in received:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _copy_response_file(
    stream: socket.socket,
    output_directory: Path,
    descriptor: dict[str, Any],
) -> tuple[Path, Path]:
    if set(descriptor) != {"content_digest", "name", "size_bytes"}:
        raise ProcessingBridgeError(
            "BRIDGE_RESPONSE_INVALID",
            "bridge preview descriptor shape differs",
        )
    name = descriptor["name"]
    size = descriptor["size_bytes"]
    expected_digest = descriptor["content_digest"]
    if (
        not isinstance(name, str)
        or SAFE_OUTPUT_NAME.fullmatch(name) is None
        or name == "result.json"
        or type(size) is not int
        or not 1 <= size <= MAX_PREVIEW_BYTES
        or not isinstance(expected_digest, str)
        or DIGEST.fullmatch(expected_digest) is None
    ):
        raise ProcessingBridgeError(
            "BRIDGE_RESPONSE_INVALID",
            "bridge preview descriptor is invalid",
        )
    output_fd, temporary_name = tempfile.mkstemp(
        dir=output_directory,
        prefix=".tacua-bridge-preview-",
    )
    temporary = Path(temporary_name)
    hasher = hashlib.sha256()
    remaining = size
    try:
        with os.fdopen(output_fd, "wb") as destination:
            while remaining:
                block = stream.recv(min(1_048_576, remaining))
                if not block:
                    raise ProcessingBridgeError(
                        "BRIDGE_PROTOCOL_INVALID",
                        "bridge preview stream ended early",
                    )
                destination.write(block)
                hasher.update(block)
                remaining -= len(block)
            destination.flush()
            os.fsync(destination.fileno())
        if "sha256:" + hasher.hexdigest() != expected_digest:
            raise ProcessingBridgeError(
                "BRIDGE_RESPONSE_INVALID",
                "bridge preview digest differs",
            )
        temporary.chmod(0o600)
        return temporary, output_directory / name
    except Exception:
        try:
            os.close(output_fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def receive_success_response(
    stream: socket.socket,
    response: dict[str, Any],
    output_directory: Path,
) -> bytes:
    if set(response) != {
        "contract_version",
        "files",
        "result_digest",
        "result_size",
        "status",
    }:
        raise ProcessingBridgeError(
            "BRIDGE_RESPONSE_INVALID",
            "bridge success response shape differs",
        )
    files = response["files"]
    result_size = response["result_size"]
    result_digest = response["result_digest"]
    if (
        response["contract_version"] != RESPONSE_CONTRACT
        or response["status"] != "ok"
        or type(result_size) is not int
        or not 1 <= result_size <= MAX_RESULT_BYTES
        or not isinstance(result_digest, str)
        or DIGEST.fullmatch(result_digest) is None
        or not isinstance(files, list)
        or len(files) > MAX_PREVIEW_FILES
    ):
        raise ProcessingBridgeError(
            "BRIDGE_RESPONSE_INVALID",
            "bridge success response is invalid",
        )
    names = [
        item.get("name") if isinstance(item, dict) else None
        for item in files
    ]
    if (
        any(not isinstance(name, str) for name in names)
        or names != sorted(names)
        or len(set(names)) != len(names)
    ):
        raise ProcessingBridgeError(
            "BRIDGE_RESPONSE_INVALID",
            "bridge preview names are invalid",
        )
    total = result_size
    for item in files:
        if (
            not isinstance(item, dict)
            or set(item) != {"content_digest", "name", "size_bytes"}
            or not isinstance(item.get("name"), str)
            or SAFE_OUTPUT_NAME.fullmatch(item["name"]) is None
            or item["name"] == "result.json"
            or type(item.get("size_bytes")) is not int
            or not 1 <= item["size_bytes"] <= MAX_PREVIEW_BYTES
            or not isinstance(item.get("content_digest"), str)
            or DIGEST.fullmatch(item["content_digest"]) is None
        ):
            raise ProcessingBridgeError(
                "BRIDGE_RESPONSE_INVALID",
                "bridge preview metadata is invalid",
            )
        total += item["size_bytes"]
    if total > MAX_OUTPUT_BYTES:
        raise ProcessingBridgeError(
            "BRIDGE_RESPONSE_INVALID",
            "bridge output exceeds its aggregate bound",
        )
    result = _receive_exact(stream, result_size)
    if "sha256:" + hashlib.sha256(result).hexdigest() != result_digest:
        raise ProcessingBridgeError(
            "BRIDGE_RESPONSE_INVALID",
            "bridge result digest differs",
        )
    parse_canonical_object(result, maximum=MAX_RESULT_BYTES)
    try:
        output_metadata = output_directory.lstat()
    except OSError as error:
        raise ProcessingBridgeError(
            "BRIDGE_OUTPUT_INVALID",
            "adapter output directory is unavailable",
        ) from error
    if (
        not stat.S_ISDIR(output_metadata.st_mode)
        or stat.S_ISLNK(output_metadata.st_mode)
        or output_metadata.st_uid != os.geteuid()
        or any(output_directory.iterdir())
    ):
        raise ProcessingBridgeError(
            "BRIDGE_OUTPUT_INVALID",
            "adapter output directory is unsafe or non-empty",
        )
    staged: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for item in files:
            assert isinstance(item, dict)
            staged.append(_copy_response_file(stream, output_directory, item))
        if set(output_directory.iterdir()) != {
            temporary for temporary, _destination in staged
        }:
            raise ProcessingBridgeError(
                "BRIDGE_OUTPUT_INVALID",
                "adapter output directory changed during transfer",
            )
        for temporary, destination in staged:
            os.replace(temporary, destination)
            published.append(destination)
        return result
    except Exception:
        for temporary, _destination in staged:
            temporary.unlink(missing_ok=True)
        for destination in published:
            destination.unlink(missing_ok=True)
        raise


def run_client(
    socket_path: Path,
    input_path: Path,
    output_directory: Path,
) -> bytes:
    if not socket_path.is_absolute():
        raise ProcessingBridgeError(
            "BRIDGE_SOCKET_INVALID",
            "bridge socket path must be absolute",
        )
    targets = adapter_descriptor_targets(input_path)
    request = {
        "contract_version": REQUEST_CONTRACT,
        "descriptor_targets": list(targets),
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(BRIDGE_TIMEOUT_SECONDS)
        try:
            stream.connect(str(socket_path))
            send_frame(stream, request)
            send_descriptor_batches(stream, targets)
            response = receive_frame(stream)
        except (OSError, TimeoutError, socket.timeout) as error:
            raise ProcessingBridgeError(
                "BRIDGE_UNAVAILABLE",
                "trusted host bridge is unavailable",
            ) from error
        if response.get("contract_version") != RESPONSE_CONTRACT:
            raise ProcessingBridgeError(
                "BRIDGE_RESPONSE_INVALID",
                "bridge response contract differs",
            )
        if response.get("status") == "error":
            if (
                set(response) != {"code", "contract_version", "status"}
                or not isinstance(response.get("code"), str)
                or ERROR_CODE.fullmatch(response["code"]) is None
            ):
                raise ProcessingBridgeError(
                    "BRIDGE_RESPONSE_INVALID",
                    "bridge error response is invalid",
                )
            raise ProcessingBridgeError(
                response["code"],
                "trusted host processor rejected the request",
            )
        if response.get("status") != "ok":
            raise ProcessingBridgeError(
                "BRIDGE_RESPONSE_INVALID",
                "bridge response status differs",
            )
        result = receive_success_response(stream, response, output_directory)
        stream.settimeout(5)
        try:
            trailing = stream.recv(1)
        except (OSError, TimeoutError, socket.timeout) as error:
            raise ProcessingBridgeError(
                "BRIDGE_RESPONSE_INVALID",
                "bridge response did not terminate exactly",
            ) from error
        if trailing:
            raise ProcessingBridgeError(
                "BRIDGE_RESPONSE_INVALID",
                "bridge response contained trailing bytes",
            )
        return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Use the trusted host Compose processing bridge",
    )
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    args = _parser().parse_args(argv)
    try:
        result = run_client(
            args.socket,
            args.input,
            args.output_directory,
        )
    except (ProcessingBridgeError, OSError) as error:
        code = (
            error.code
            if isinstance(error, ProcessingBridgeError)
            else "BRIDGE_IO_FAILED"
        )
        print(code, file=sys.stderr)
        return 1
    except Exception:
        print("BRIDGE_FAILED", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
