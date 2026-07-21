# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from summarize_timing import TimingError, load_events, summarize  # noqa: E402


class TimingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.events = load_events(ROOT / "fixtures" / "timing" / "example-events.v1.0.0.jsonl")

    def test_active_time_excludes_waiting_gaps(self) -> None:
        result = summarize(self.events)["sessions"][0]
        self.assertEqual(result["active_ms"], 21000)
        self.assertEqual(result["interactions"], 1)
        self.assertEqual(result["approvals"], 1)
        self.assertEqual(
            result["by_activity_ms"],
            {"answer_clarification": 5000, "approve_ticket": 4000, "review_and_narrate": 12000},
        )

    def test_unclosed_interval_is_rejected(self) -> None:
        events = copy.deepcopy(self.events[:-1])
        with self.assertRaisesRegex(TimingError, "unclosed active interval"):
            summarize(events)

    def test_interaction_requires_gap_and_outcome(self) -> None:
        events = copy.deepcopy(self.events)
        interaction = next(item for item in events if item["event_type"] == "interaction")
        del interaction["evidence_gap"]
        with self.assertRaisesRegex(TimingError, "missing required context"):
            summarize(events)


if __name__ == "__main__":
    unittest.main()
