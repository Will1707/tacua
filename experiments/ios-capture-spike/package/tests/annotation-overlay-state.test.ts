// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  annotationOverlayReducer,
  initialAnnotationOverlayState,
  maximumAnnotationPoints,
  maximumAnnotationStrokes,
  maximumPointsPerStroke,
  normalizeAnnotationPoint,
  type AnnotationOverlayState,
} from "../src/annotation-overlay-state.ts";

function startStroke(
  state: AnnotationOverlayState,
  id: string,
  end = { x: 0.8, y: 0.7 },
): AnnotationOverlayState {
  let next = annotationOverlayReducer(state, {
    type: "begin_stroke",
    id,
    point: { x: 0.2, y: 0.3 },
  });
  next = annotationOverlayReducer(next, {
    type: "extend_stroke",
    point: end,
    minimumDistanceSquared: 0.0001,
  });
  return annotationOverlayReducer(next, { type: "finish_stroke" });
}

test("normalizes, clamps, and rejects unusable surface points", () => {
  assert.deepEqual(normalizeAnnotationPoint(50, 25, 100, 50), { x: 0.5, y: 0.5 });
  assert.deepEqual(normalizeAnnotationPoint(-20, 90, 100, 50), { x: 0, y: 1 });
  assert.equal(normalizeAnnotationPoint(1, 1, 0, 50), null);
  assert.equal(normalizeAnnotationPoint(Number.NaN, 1, 100, 50), null);

  const normalized = normalizeAnnotationPoint(75, 50, 100, 100);
  assert.deepEqual(normalized, { x: 0.75, y: 0.5 });
  assert.deepEqual(
    normalized && { x: normalized.x * 200, y: normalized.y * 300 },
    { x: 150, y: 150 },
    "normalized geometry should remain aligned after an orientation/size change",
  );
});

test("builds ordered pen and highlighter strokes and ignores tiny moves", () => {
  let state = initialAnnotationOverlayState();
  state = annotationOverlayReducer(state, { type: "toggle_menu" });
  assert.equal(state.menuOpen, true);
  state = annotationOverlayReducer(state, { type: "select_tool", tool: "pen" });
  assert.equal(state.menuOpen, false);

  state = annotationOverlayReducer(state, {
    type: "begin_stroke",
    id: "stroke_pen",
    point: { x: 0.1, y: 0.1 },
  });
  const unchanged = annotationOverlayReducer(state, {
    type: "extend_stroke",
    point: { x: 0.101, y: 0.101 },
    minimumDistanceSquared: 0.001,
  });
  assert.equal(unchanged, state);
  state = annotationOverlayReducer(state, {
    type: "extend_stroke",
    point: { x: 0.7, y: 0.8 },
    minimumDistanceSquared: 0.001,
  });
  state = annotationOverlayReducer(state, { type: "finish_stroke" });
  assert.deepEqual(state.strokes[0], {
    id: "stroke_pen",
    tool: "pen",
    points: [{ x: 0.1, y: 0.1 }, { x: 0.7, y: 0.8 }],
  });

  state = annotationOverlayReducer(state, { type: "select_tool", tool: "highlighter" });
  state = startStroke(state, "stroke_highlighter");
  assert.equal(state.strokes[1]?.tool, "highlighter");
});

test("undo, clear, cancellation, and save transitions preserve only intended state", () => {
  let state = annotationOverlayReducer(initialAnnotationOverlayState(), {
    type: "select_tool",
    tool: "pen",
  });
  state = startStroke(state, "stroke_one");
  state = startStroke(state, "stroke_two");
  state = annotationOverlayReducer(state, { type: "undo" });
  assert.deepEqual(state.strokes.map((stroke) => stroke.id), ["stroke_one"]);

  state = annotationOverlayReducer(state, {
    type: "begin_stroke",
    id: "unfinished",
    point: { x: 0.5, y: 0.5 },
  });
  state = annotationOverlayReducer(state, { type: "cancel_stroke" });
  assert.equal(state.currentStroke, null);
  assert.deepEqual(state.strokes.map((stroke) => stroke.id), ["stroke_one"]);

  state = annotationOverlayReducer(state, { type: "save_started" });
  assert.equal(state.saving, true);
  assert.equal(state.activeTool, "pen");
  state = annotationOverlayReducer(state, { type: "save_failed" });
  assert.equal(state.saving, false);
  assert.equal(state.strokes.length, 1, "a failed mark should preserve the drawing for retry");
  state = annotationOverlayReducer(state, { type: "save_started" });
  state = annotationOverlayReducer(state, { type: "save_succeeded" });
  assert.deepEqual(state, initialAnnotationOverlayState());

  state = annotationOverlayReducer(state, { type: "select_tool", tool: "pen" });
  state = startStroke(state, "stroke_three");
  state = annotationOverlayReducer(state, { type: "clear" });
  assert.equal(state.strokes.length, 0);
  state = annotationOverlayReducer(state, { type: "cancel" });
  assert.deepEqual(state, initialAnnotationOverlayState());
});

test("bounds completed stroke count without evicting visible annotations", () => {
  let state = annotationOverlayReducer(initialAnnotationOverlayState(), {
    type: "select_tool",
    tool: "pen",
  });
  for (let index = 0; index < maximumAnnotationStrokes; index += 1) {
    state = startStroke(state, `stroke_${index}`);
  }
  const full = state;
  state = annotationOverlayReducer(state, {
    type: "begin_stroke",
    id: "overflow",
    point: { x: 0.1, y: 0.1 },
  });
  assert.equal(state, full);
  assert.equal(state.strokes.length, maximumAnnotationStrokes);
});

test("bounds per-stroke and total point counts before rendering becomes excessive", () => {
  const point = { x: 0.5, y: 0.5 };
  const saturatedStroke = {
    id: "saturated",
    tool: "pen" as const,
    points: Array.from({ length: maximumPointsPerStroke }, () => point),
  };
  let state: AnnotationOverlayState = {
    ...initialAnnotationOverlayState(),
    activeTool: "pen",
    currentStroke: saturatedStroke,
  };
  assert.equal(
    annotationOverlayReducer(state, {
      type: "extend_stroke",
      point: { x: 0.8, y: 0.8 },
      minimumDistanceSquared: 0,
    }),
    state,
  );

  const almostFull = [
    saturatedStroke,
    {
      id: "almost_full_remainder",
      tool: "pen" as const,
      points: Array.from(
        { length: maximumAnnotationPoints - maximumPointsPerStroke - 1 },
        () => point,
      ),
    },
  ];
  state = {
    ...initialAnnotationOverlayState(),
    activeTool: "pen",
    strokes: almostFull,
  };
  assert.equal(
    annotationOverlayReducer(state, {
      type: "begin_stroke",
      id: "overflow",
      point,
    }),
    state,
  );
});
