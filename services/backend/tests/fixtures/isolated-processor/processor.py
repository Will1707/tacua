#!/usr/local/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic offline processor used only by the Docker isolation regression."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--sleep-seconds", type=int, default=0)
    args = parser.parse_args()

    document = json.loads(args.input.read_bytes())
    assert document["contract_version"] == "tacua.isolated-processing-input@1.0.0"
    assert args.model.read_bytes() == b"synthetic model fixture only\n"
    reference = document["source_input"]["capture"]["segments"][0]
    evidence = Path(reference["read_only_path"]).read_bytes()
    assert "sha256:" + hashlib.sha256(evidence).hexdigest() == reference["content_digest"]
    root_read_only = False
    payload_read_only = False
    try:
        Path("/tacua-root-write-probe").write_bytes(b"must fail")
    except OSError:
        root_read_only = True
    try:
        (args.model.parent / "write-probe").write_bytes(b"must fail")
    except OSError:
        payload_read_only = True
    assert root_read_only and payload_read_only
    if args.sleep_seconds:
        time.sleep(args.sleep_seconds)

    preview = b"isolated preview\n"
    result = {
        "contract_version": "tacua.local-processing-result@1.0.0",
        "disposition": "checkpoint",
        "fixture": "isolated-docker-passed",
        "payload_read_only": payload_read_only,
        "root_read_only": root_read_only,
        "uid": os.geteuid(),
        "result": {
            "candidates": [
                {
                    "previews": [
                        {
                            "body_file": "synthetic-preview.txt",
                            "content_digest": "sha256:" + hashlib.sha256(preview).hexdigest(),
                            "size_bytes": len(preview),
                        }
                    ]
                }
            ]
        },
    }
    result_bytes = json.dumps(
        result,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    envelope = {
        "contract_version": "tacua.isolated-processing-output@1.0.0",
        "previews": [
            {
                "content_base64": base64.b64encode(preview).decode("ascii"),
                "content_digest": "sha256:" + hashlib.sha256(preview).hexdigest(),
                "name": "synthetic-preview.txt",
                "size_bytes": len(preview),
            }
        ],
        "result": result,
        "result_digest": "sha256:" + hashlib.sha256(result_bytes).hexdigest(),
    }
    encoded = json.dumps(
        envelope,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
