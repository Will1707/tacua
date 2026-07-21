#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarize paired active-time markers in a Tacua JSONL timing log."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


class TimingError(ValueError):
    pass


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TimingError(f"line {line_number}: event must be an object")
            events.append(value)
    return events


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        raise TimingError("timing log is empty")
    sessions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    event_ids: set[str] = set()
    for event in events:
        if event.get("contract_version") != "tacua.timing-event@1.0.0":
            raise TimingError("unsupported timing contract")
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id or event_id in event_ids:
            raise TimingError(f"missing or duplicate event_id {event_id}")
        event_ids.add(event_id)
        session_id = event.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise TimingError(f"{event_id}: missing session_id")
        sessions[session_id].append(event)

    summaries: list[dict[str, Any]] = []
    for session_id in sorted(sessions):
        ordered = sorted(sessions[session_id], key=lambda event: event.get("offset_ms", -1))
        offsets = [event.get("offset_ms") for event in ordered]
        if any(not isinstance(offset, int) or offset < 0 for offset in offsets):
            raise TimingError(f"{session_id}: offsets must be non-negative integers")
        if len(offsets) != len(set(offsets)):
            raise TimingError(f"{session_id}: offsets must be unique")
        conditions = {event.get("condition") for event in ordered}
        if len(conditions) != 1 or next(iter(conditions)) not in {"A", "B", "C"}:
            raise TimingError(f"{session_id}: one valid condition is required")

        active_start: dict[str, Any] | None = None
        active_ms = 0
        by_activity: dict[str, int] = defaultdict(int)
        interactions = corrections = approvals = 0
        for event in ordered:
            event_type = event.get("event_type")
            if event_type == "active_start":
                if active_start is not None:
                    raise TimingError(f"{session_id}: overlapping active intervals")
                active_start = event
            elif event_type == "active_stop":
                if active_start is None:
                    raise TimingError(f"{session_id}: active_stop without active_start")
                duration = event["offset_ms"] - active_start["offset_ms"]
                if duration < 0:
                    raise TimingError(f"{session_id}: negative active interval")
                activity = active_start.get("activity_code")
                if activity != event.get("activity_code"):
                    raise TimingError(f"{session_id}: interval activity codes do not match")
                active_ms += duration
                by_activity[str(activity)] += duration
                active_start = None
            elif event_type == "interaction":
                required = ("interaction_kind", "evidence_gap", "prevented_error")
                if any(not event.get(field) for field in required):
                    raise TimingError(f"{session_id}: interaction is missing required context")
                interactions += 1
            elif event_type == "correction":
                corrections += 1
            elif event_type == "approval":
                approvals += 1
            elif event_type != "note":
                raise TimingError(f"{session_id}: invalid event_type {event_type}")
        if active_start is not None:
            raise TimingError(f"{session_id}: unclosed active interval")

        summaries.append(
            {
                "session_id": session_id,
                "condition": next(iter(conditions)),
                "active_ms": active_ms,
                "active_seconds": active_ms / 1000,
                "by_activity_ms": dict(sorted(by_activity.items())),
                "interactions": interactions,
                "corrections": corrections,
                "approvals": approvals,
            }
        )
    return {"contract_version": "tacua.timing-summary@1.0.0", "sessions": summaries}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(summarize(load_events(args.events)), indent=2, sort_keys=True))
        return 0
    except (OSError, json.JSONDecodeError, TimingError) as error:
        sys.stderr.write(f"timing summary failed: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
