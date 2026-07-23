#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a canonical synthetic isolated-runner input around one local MOV.

This is verification tooling only. It reuses the repository's frozen synthetic
terminal-stage fixtures and replaces their media/diagnostic object bindings
with exact bytes supplied by the operator. It creates no production session.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import stat
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
LOCAL_INPUT = (
    ROOT
    / "contracts"
    / "local-processing"
    / "fixtures"
    / "positive"
    / "adapter-v1.0-terminal-preview"
    / "input.json"
)
DIAGNOSTIC_REQUEST = (
    ROOT
    / "contracts"
    / "sdk-backend-protocol"
    / "fixtures"
    / "positive"
    / "diagnostic-upload-request.json"
)
MAX_MEDIA_BYTES = 256 * 1_024 * 1_024


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_without(value: Mapping[str, Any], field: str) -> str:
    subject = copy.deepcopy(dict(value))
    subject.pop(field, None)
    return digest_bytes(canonical_bytes(subject))


def regular_bytes(path: Path, maximum: int) -> bytes:
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 1
        or metadata.st_size > maximum
    ):
        raise ValueError("fixture input file is unsafe")
    return path.read_bytes()


def write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = path.open("xb")
    try:
        descriptor.write(payload)
        descriptor.flush()
    finally:
        descriptor.close()
    path.chmod(0o400)


def build(media: bytes) -> tuple[bytes, bytes]:
    source = json.loads(LOCAL_INPUT.read_bytes())
    envelope = json.loads(DIAGNOSTIC_REQUEST.read_bytes())["envelope"]
    envelope["envelope_digest"] = digest_without(envelope, "envelope_digest")
    diagnostic = canonical_bytes(envelope)
    media_digest = digest_bytes(media)
    sidecar_digest = digest_bytes(b"synthetic processor smoke sidecar\n")

    manifest = source["capture"]["manifest"]
    manifest_segment = manifest["segments"][0]
    manifest_segment["content"] = {
        "content_digest": media_digest,
        "content_type": "video/quicktime",
        "sidecar_digest": sidecar_digest,
        "size_bytes": len(media),
    }
    receipt = manifest["upload"]["receipts"][0]
    receipt["content_digest"] = media_digest
    receipt["size_bytes"] = len(media)
    receipt["receipt_digest"] = digest_without(receipt, "receipt_digest")
    manifest["manifest_digest"] = digest_without(manifest, "manifest_digest")

    segment = source["capture"]["segments"][0]
    segment.update(
        {
            "content_digest": media_digest,
            "content_type": "video/quicktime",
            "read_only_path": "/dev/fd/9",
            "sidecar_digest": sidecar_digest,
            "size_bytes": len(media),
        }
    )
    diagnostic_reference = source["capture"]["diagnostics"][0]
    diagnostic_reference.update(
        {
            "content_digest": digest_bytes(diagnostic),
            "envelope_digest": envelope["envelope_digest"],
            "read_only_path": "/dev/fd/10",
            "size_bytes": len(diagnostic),
        }
    )
    job = source["job"]
    job["inputs"]["capture_manifest_digest"] = manifest["manifest_digest"]
    job["inputs"]["diagnostic_envelope_digests"] = [envelope["envelope_digest"]]
    job["job_digest"] = digest_without(job, "job_digest")
    source["binding"]["job_digest"] = job["job_digest"]
    source["input_digest"] = digest_without(source, "input_digest")
    return canonical_bytes(source), diagnostic


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--media", type=Path, required=True)
    parser.add_argument("--input-output", type=Path, required=True)
    parser.add_argument("--diagnostic-output", type=Path, required=True)
    args = parser.parse_args()
    media = regular_bytes(args.media, MAX_MEDIA_BYTES)
    source, diagnostic = build(media)
    write_new(args.input_output, source)
    try:
        write_new(args.diagnostic_output, diagnostic)
    except Exception:
        args.input_output.unlink(missing_ok=True)
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
