// SPDX-License-Identifier: Apache-2.0

export type AnnotationTool = "pen" | "highlighter";

/** A point normalized to the current annotation surface (0...1 on each axis). */
export type AnnotationPoint = Readonly<{
  x: number;
  y: number;
}>;

export type AnnotationStroke = Readonly<{
  id: string;
  tool: AnnotationTool;
  points: readonly AnnotationPoint[];
}>;

export type AnnotationOverlayState = Readonly<{
  activeTool: AnnotationTool | null;
  currentStroke: AnnotationStroke | null;
  menuOpen: boolean;
  saving: boolean;
  strokes: readonly AnnotationStroke[];
}>;

export type AnnotationOverlayAction =
  | Readonly<{ type: "toggle_menu" }>
  | Readonly<{ type: "select_tool"; tool: AnnotationTool }>
  | Readonly<{ type: "begin_stroke"; id: string; point: AnnotationPoint }>
  | Readonly<{
      type: "extend_stroke";
      point: AnnotationPoint;
      minimumDistanceSquared: number;
    }>
  | Readonly<{ type: "finish_stroke" }>
  | Readonly<{ type: "cancel_stroke" }>
  | Readonly<{ type: "undo" }>
  | Readonly<{ type: "clear" }>
  | Readonly<{ type: "cancel" }>
  | Readonly<{ type: "save_started" }>
  | Readonly<{ type: "save_failed" }>
  | Readonly<{ type: "save_succeeded" }>
  | Readonly<{ type: "reset" }>;

export const maximumAnnotationStrokes = 16;
export const maximumAnnotationPoints = 512;
export const maximumPointsPerStroke = 384;

export function initialAnnotationOverlayState(): AnnotationOverlayState {
  return {
    activeTool: null,
    currentStroke: null,
    menuOpen: false,
    saving: false,
    strokes: [],
  };
}

export function normalizeAnnotationPoint(
  x: number,
  y: number,
  width: number,
  height: number,
): AnnotationPoint | null {
  if (
    !Number.isFinite(x)
    || !Number.isFinite(y)
    || !Number.isFinite(width)
    || !Number.isFinite(height)
    || width <= 0
    || height <= 0
  ) return null;
  return {
    x: Math.min(1, Math.max(0, x / width)),
    y: Math.min(1, Math.max(0, y / height)),
  };
}

function validPoint(point: AnnotationPoint): boolean {
  return Number.isFinite(point.x)
    && Number.isFinite(point.y)
    && point.x >= 0
    && point.x <= 1
    && point.y >= 0
    && point.y <= 1;
}

function squaredDistance(left: AnnotationPoint, right: AnnotationPoint): number {
  const x = right.x - left.x;
  const y = right.y - left.y;
  return x * x + y * y;
}

function completedPointCount(state: AnnotationOverlayState): number {
  return state.strokes.reduce((total, stroke) => total + stroke.points.length, 0);
}

export function annotationOverlayReducer(
  state: AnnotationOverlayState,
  action: AnnotationOverlayAction,
): AnnotationOverlayState {
  switch (action.type) {
    case "toggle_menu":
      if (state.saving || state.activeTool !== null) return state;
      return { ...state, menuOpen: !state.menuOpen };
    case "select_tool":
      if (state.saving) return state;
      return {
        ...state,
        activeTool: action.tool,
        currentStroke: null,
        menuOpen: false,
      };
    case "begin_stroke":
      if (
        state.saving
        || state.activeTool === null
        || state.currentStroke !== null
        || state.strokes.length >= maximumAnnotationStrokes
        || completedPointCount(state) + 2 > maximumAnnotationPoints
        || !validPoint(action.point)
      ) return state;
      return {
        ...state,
        currentStroke: {
          id: action.id,
          tool: state.activeTool,
          points: [action.point],
        },
      };
    case "extend_stroke": {
      const current = state.currentStroke;
      if (
        state.saving
        || current === null
        || current.points.length >= maximumPointsPerStroke
        || completedPointCount(state) + current.points.length >= maximumAnnotationPoints
        || !validPoint(action.point)
        || !Number.isFinite(action.minimumDistanceSquared)
        || action.minimumDistanceSquared < 0
      ) return state;
      const last = current.points[current.points.length - 1];
      if (!last || squaredDistance(last, action.point) < action.minimumDistanceSquared) {
        return state;
      }
      return {
        ...state,
        currentStroke: {
          ...current,
          points: [...current.points, action.point],
        },
      };
    }
    case "finish_stroke": {
      const current = state.currentStroke;
      if (current === null) return state;
      return {
        ...state,
        currentStroke: null,
        strokes: current.points.length >= 2
          ? [...state.strokes, current]
          : state.strokes,
      };
    }
    case "cancel_stroke":
      return state.currentStroke === null ? state : { ...state, currentStroke: null };
    case "undo":
      if (state.saving || state.currentStroke !== null || state.strokes.length === 0) {
        return state;
      }
      return { ...state, strokes: state.strokes.slice(0, -1) };
    case "clear":
      if (state.saving) return state;
      return { ...state, currentStroke: null, strokes: [] };
    case "cancel":
    case "save_succeeded":
    case "reset":
      return initialAnnotationOverlayState();
    case "save_started":
      if (state.saving || state.currentStroke !== null) return state;
      return { ...state, menuOpen: false, saving: true };
    case "save_failed":
      return state.saving ? { ...state, saving: false } : state;
  }
}
