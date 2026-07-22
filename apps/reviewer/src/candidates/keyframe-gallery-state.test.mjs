// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  isKeyframeGalleryReady,
  keyframeCarouselPositionLabel,
  moveKeyframeCarouselIndex,
  normalizeKeyframeCarouselIndex,
  referencedAvailableKeyframes,
} from "./keyframe-gallery-state.ts";

function item(evidenceId, evidenceType = "media.keyframe", availability = "available") {
  return { evidence_id: evidenceId, evidence_type: evidenceType, availability };
}

test("selects every referenced available keyframe in content traversal order", () => {
  const evidence = {
    items: [
      item("ev_second"),
      item("ev_unavailable", "media.keyframe", "unavailable"),
      item("ev_event", "sdk.runtime_error"),
      item("ev_first"),
      item("ev_unreferenced"),
    ],
  };

  assert.deepEqual(
    referencedAvailableKeyframes(evidence, ["ev_first", "ev_event", "ev_unavailable", "ev_second"])
      .map((entry) => entry.evidence_id),
    ["ev_first", "ev_second"],
  );
});

test("requires at least one keyframe and every screenshot to have decoded after verification", () => {
  const first = item("ev_first");
  const second = item("ev_second");

  assert.equal(isKeyframeGalleryReady([], new Set()), false);
  assert.equal(isKeyframeGalleryReady([first], new Set()), false);
  assert.equal(isKeyframeGalleryReady([first, second], new Set(["ev_first"])), false);
  assert.equal(isKeyframeGalleryReady([first, second], new Set(["ev_first", "ev_second"])), true);
});

test("carousel movement is deterministic and bounded at both ends", () => {
  assert.equal(normalizeKeyframeCarouselIndex(-4, 3), 0);
  assert.equal(normalizeKeyframeCarouselIndex(12, 3), 2);
  assert.equal(normalizeKeyframeCarouselIndex(Number.NaN, 3), 0);
  assert.equal(normalizeKeyframeCarouselIndex(2, 0), 0);
  assert.equal(moveKeyframeCarouselIndex(0, 3, "previous"), 0);
  assert.equal(moveKeyframeCarouselIndex(0, 3, "next"), 1);
  assert.equal(moveKeyframeCarouselIndex(2, 3, "next"), 2);
  assert.equal(keyframeCarouselPositionLabel(7, 3), "Screenshot 3 of 3");
  assert.equal(keyframeCarouselPositionLabel(0, 0), "No screenshots");
});
