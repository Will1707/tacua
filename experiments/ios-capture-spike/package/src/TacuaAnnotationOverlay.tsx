// SPDX-License-Identifier: Apache-2.0

import { memo, useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  ActivityIndicator,
  PanResponder,
  Pressable,
  StyleSheet,
  Text,
  View,
  type GestureResponderEvent,
  type LayoutChangeEvent,
} from "react-native";

import {
  annotationOverlayReducer,
  initialAnnotationOverlayState,
  maximumAnnotationPoints,
  maximumAnnotationStrokes,
  normalizeAnnotationPoint,
  type AnnotationPoint,
  type AnnotationStroke,
  type AnnotationTool,
} from "./annotation-overlay-state";
import {
  TacuaCaptureSpikeModule,
  type CaptureMarker,
  type CaptureStatus,
} from "./TacuaCaptureSpikeModule";

const defaultMaximumIssueMarks = 12;
const markerLabel = "screen_annotation";
const minimumPointDistance = 5;
const frameAdvanceTimeoutMilliseconds = 2_000;
const annotatedFrameHoldMilliseconds = 400;

type SurfaceSize = Readonly<{ width: number; height: number }>;

export type TacuaAnnotationOverlayProps = Readonly<{
  /** Raw ReplayKit state; markability additionally requires captureState === "recording". */
  recording: boolean;
  /** Native capture lifecycle state used to hide and cancel controls outside markable capture. */
  captureState: CaptureStatus["state"];
  /** Reset ephemeral marks whenever the SDK starts a different logical session. */
  sessionId: string | null;
  /** Current native marker count. The offline processor accepts at most twelve. */
  issueMarkCount: number;
  bottomOffset?: number;
  rightOffset?: number;
  onMarkerCreated?: (marker: CaptureMarker) => void;
  onError?: (error: unknown) => void;
}>;

class AnnotationFrameUnavailableError extends Error {
  readonly code = "ANNOTATION_FRAME_UNAVAILABLE";

  constructor() {
    super("Tacua could not verify a fresh video frame containing the annotation. Try marking it again.");
    this.name = "AnnotationFrameUnavailableError";
  }
}

class AnnotationMarkLimitError extends Error {
  readonly code = "ANNOTATION_MARK_LIMIT_REACHED";

  constructor(maximum: number) {
    super(`This recording already has the maximum of ${maximum} issue marks.`);
    this.name = "AnnotationMarkLimitError";
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function invokeHostCallback<T>(callback: ((value: T) => void) | undefined, value: T): void {
  try {
    callback?.(value);
  } catch {
    // A host callback cannot change whether the native evidence mark succeeded.
  }
}

function nextPaint(): Promise<void> {
  return new Promise((resolve) => {
    if (typeof requestAnimationFrame === "function") {
      requestAnimationFrame(() => resolve());
      return;
    }
    setTimeout(resolve, 16);
  });
}

async function waitForFreshVideoFrame(
  baseline: number,
  stillCurrent: () => boolean,
): Promise<void> {
  // The first paint applies the capture pulse; the second lets the chrome-free
  // annotation surface reach the native screen before ReplayKit samples it.
  await nextPaint();
  await nextPaint();
  const deadline = Date.now() + frameAdvanceTimeoutMilliseconds;
  while (stillCurrent() && Date.now() <= deadline) {
    const latest = TacuaCaptureSpikeModule.getStatus().appendedVideoFrameSequence;
    if (latest > baseline) return;
    await delay(32);
  }
  throw new AnnotationFrameUnavailableError();
}

function pointFromEvent(
  event: GestureResponderEvent,
  surface: SurfaceSize,
): AnnotationPoint | null {
  return normalizeAnnotationPoint(
    event.nativeEvent.locationX,
    event.nativeEvent.locationY,
    surface.width,
    surface.height,
  );
}

function strokeColor(tool: AnnotationTool): string {
  return tool === "pen" ? "#FF4F5E" : "#FFE45E";
}

function strokeWidth(tool: AnnotationTool): number {
  return tool === "pen" ? 5 : 20;
}

const StrokeLayer = memo(function StrokeLayer({
  capturePulse,
  stroke,
  surface,
}: Readonly<{
  capturePulse: boolean;
  stroke: AnnotationStroke;
  surface: SurfaceSize;
}>) {
  if (surface.width <= 0 || surface.height <= 0 || stroke.points.length < 2) return null;
  const thickness = strokeWidth(stroke.tool);
  return (
    <View
      pointerEvents="none"
      style={[
        styles.strokeLayer,
        {
          opacity: stroke.tool === "pen"
            ? capturePulse ? 1 : 0.96
            : capturePulse ? 0.48 : 0.42,
        },
      ]}
    >
      {stroke.points.slice(1).map((point, index) => {
        const previous = stroke.points[index];
        if (!previous) return null;
        const startX = previous.x * surface.width;
        const startY = previous.y * surface.height;
        const endX = point.x * surface.width;
        const endY = point.y * surface.height;
        const deltaX = endX - startX;
        const deltaY = endY - startY;
        const length = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
        if (length === 0) return null;
        return (
          <View
            key={`${stroke.id}:${index}`}
            pointerEvents="none"
            style={{
              position: "absolute",
              left: (startX + endX - length) / 2,
              top: (startY + endY - thickness) / 2,
              width: length,
              height: thickness,
              borderRadius: thickness / 2,
              backgroundColor: strokeColor(stroke.tool),
              transform: [{ rotate: `${Math.atan2(deltaY, deltaX)}rad` }],
            }}
          />
        );
      })}
    </View>
  );
});

function RoundControl({
  accessibilityLabel,
  disabled = false,
  label,
  onPress,
  selected = false,
}: Readonly<{
  accessibilityLabel: string;
  disabled?: boolean;
  label: string;
  onPress: () => void;
  selected?: boolean;
}>) {
  return (
    <Pressable
      accessibilityLabel={accessibilityLabel}
      accessibilityRole="button"
      accessibilityState={{ disabled, selected }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.roundControl,
        selected ? styles.roundControlSelected : null,
        disabled ? styles.disabled : pressed ? styles.pressed : null,
      ]}
    >
      <Text style={[styles.roundControlText, selected ? styles.roundControlTextSelected : null]}>
        {label}
      </Text>
    </Pressable>
  );
}

function MenuAction({
  disabled,
  label,
  onPress,
  symbol,
}: Readonly<{
  disabled: boolean;
  label: string;
  onPress: () => void;
  symbol: string;
}>) {
  return (
    <Pressable
      accessibilityLabel={label}
      accessibilityRole="button"
      accessibilityState={{ disabled }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.menuAction,
        disabled ? styles.disabled : pressed ? styles.pressed : null,
      ]}
    >
      <Text style={styles.menuActionLabel}>{label}</Text>
      <View style={styles.menuActionCircle}>
        <Text style={styles.menuActionSymbol}>{symbol}</Text>
      </View>
    </Pressable>
  );
}

export function TacuaAnnotationOverlay({
  recording,
  captureState,
  sessionId,
  issueMarkCount,
  bottomOffset = 24,
  rightOffset = 20,
  onMarkerCreated,
  onError,
}: TacuaAnnotationOverlayProps) {
  const markable = captureState === "recording" && recording;
  const [state, dispatch] = useReducer(
    annotationOverlayReducer,
    undefined,
    initialAnnotationOverlayState,
  );
  const [surface, setSurface] = useState<SurfaceSize>({ width: 0, height: 0 });
  const [feedback, setFeedback] = useState<string | null>(null);
  const [capturePulse, setCapturePulse] = useState(false);
  const strokeSequence = useRef(0);
  const operationGeneration = useRef(0);
  const surfaceRef = useRef(surface);
  const toolRef = useRef(state.activeTool);
  const savingRef = useRef(state.saving);
  surfaceRef.current = surface;
  toolRef.current = state.activeTool;
  savingRef.current = state.saving;

  useEffect(() => {
    operationGeneration.current += 1;
    dispatch({ type: "reset" });
    setFeedback(null);
    setCapturePulse(false);
  }, [markable, sessionId]);

  useEffect(() => () => {
    operationGeneration.current += 1;
  }, []);

  useEffect(() => {
    if (feedback === null) return;
    const timeout = setTimeout(() => setFeedback(null), 1_800);
    return () => clearTimeout(timeout);
  }, [feedback]);

  const updateSurface = useCallback((event: LayoutChangeEvent) => {
    const { width, height } = event.nativeEvent.layout;
    if (width > 0 && height > 0) setSurface({ width, height });
  }, []);

  const panResponder = useMemo(() => PanResponder.create({
    onStartShouldSetPanResponder: (event) => (
      toolRef.current !== null
      && !savingRef.current
      && event.nativeEvent.touches.length <= 1
    ),
    onMoveShouldSetPanResponder: (event) => (
      toolRef.current !== null
      && !savingRef.current
      && event.nativeEvent.touches.length <= 1
    ),
    onPanResponderGrant: (event) => {
      const point = pointFromEvent(event, surfaceRef.current);
      if (point === null) return;
      strokeSequence.current += 1;
      dispatch({
        type: "begin_stroke",
        id: `annotation_${strokeSequence.current}`,
        point,
      });
    },
    onPanResponderMove: (event) => {
      if (event.nativeEvent.touches.length > 1) {
        dispatch({ type: "cancel_stroke" });
        return;
      }
      const point = pointFromEvent(event, surfaceRef.current);
      if (point === null) return;
      const longestEdge = Math.max(surfaceRef.current.width, surfaceRef.current.height, 1);
      const normalizedDistance = minimumPointDistance / longestEdge;
      dispatch({
        type: "extend_stroke",
        point,
        minimumDistanceSquared: normalizedDistance * normalizedDistance,
      });
    },
    onPanResponderRelease: () => dispatch({ type: "finish_stroke" }),
    onPanResponderTerminate: () => dispatch({ type: "cancel_stroke" }),
    onPanResponderTerminationRequest: () => true,
    onShouldBlockNativeResponder: () => true,
  }), []);

  const createIssueMark = useCallback(async (allowEmpty: boolean) => {
    if (
      !markable
      || savingRef.current
      || state.currentStroke !== null
      || (!allowEmpty && state.strokes.length === 0)
    ) return;
    let nativeStatus: ReturnType<typeof TacuaCaptureSpikeModule.getStatus>;
    try {
      nativeStatus = TacuaCaptureSpikeModule.getStatus();
    } catch (error) {
      setFeedback(error instanceof Error ? error.message : "Tacua could not read capture status.");
      invokeHostCallback(onError, error);
      return;
    }
    if (nativeStatus.state !== "recording" || nativeStatus.recorderRecording !== true) {
      return;
    }
    const currentCount = Math.max(issueMarkCount, nativeStatus.markerCount);
    if (currentCount >= defaultMaximumIssueMarks) {
      const error = new AnnotationMarkLimitError(defaultMaximumIssueMarks);
      setFeedback(error.message);
      invokeHostCallback(onError, error);
      return;
    }
    const generation = operationGeneration.current + 1;
    operationGeneration.current = generation;
    const stillCurrent = () => (
      operationGeneration.current === generation
      && markable
    );
    savingRef.current = true;
    dispatch({ type: "save_started" });
    setFeedback(null);
    try {
      await nextPaint();
      await nextPaint();
      if (!stillCurrent()) return;
      const postHideBaseline = TacuaCaptureSpikeModule.getStatus().appendedVideoFrameSequence;
      // Pulse the chrome-free surface only after recording a post-hide baseline.
      // The native sequence advances only when that later ReplayKit callback is
      // successfully appended to the retained MOV, never for a dropped sample.
      setCapturePulse(true);
      await waitForFreshVideoFrame(postHideBaseline, stillCurrent);
      if (!stillCurrent()) return;
      const marker = await TacuaCaptureSpikeModule.mark(markerLabel);
      if (!stillCurrent()) return;
      // Leave the annotated pixels on screen briefly after the exact native mark.
      await delay(annotatedFrameHoldMilliseconds);
      if (!stillCurrent()) return;
      setCapturePulse(false);
      dispatch({ type: "save_succeeded" });
      setFeedback("Issue marked");
      invokeHostCallback(onMarkerCreated, marker);
    } catch (error) {
      if (!stillCurrent()) return;
      setCapturePulse(false);
      dispatch({ type: "save_failed" });
      setFeedback(error instanceof Error ? error.message : "Tacua could not mark this issue.");
      invokeHostCallback(onError, error);
    }
  }, [
    issueMarkCount,
    onError,
    onMarkerCreated,
    markable,
    state.currentStroke,
    state.strokes.length,
  ]);

  if (!markable) return null;

  const markLimitReached = issueMarkCount >= defaultMaximumIssueMarks;
  const drawingActive = state.activeTool !== null && !state.saving;
  const visibleStrokes = state.currentStroke
    ? [...state.strokes, state.currentStroke]
    : state.strokes;
  const annotationPointCount = state.strokes.reduce(
    (total, stroke) => total + stroke.points.length,
    0,
  );
  const drawingLimitReached = state.strokes.length >= maximumAnnotationStrokes
    || annotationPointCount + 2 > maximumAnnotationPoints;

  return (
    <View pointerEvents="box-none" style={styles.overlayRoot}>
      {(drawingActive || state.saving || visibleStrokes.length > 0) ? (
        <View
          accessibilityLabel={drawingActive ? "Screen annotation canvas" : undefined}
          onLayout={updateSurface}
          pointerEvents={drawingActive || state.saving ? "auto" : "none"}
          style={styles.canvas}
          {...(drawingActive ? panResponder.panHandlers : {})}
        >
          <View
            pointerEvents="none"
            style={[styles.framePulse, capturePulse ? styles.framePulseActive : null]}
          />
          {visibleStrokes.map((stroke) => (
            <StrokeLayer
              key={stroke.id}
              capturePulse={capturePulse}
              stroke={stroke}
              surface={surface}
            />
          ))}
        </View>
      ) : null}

      {state.saving ? (
        <View
          accessible
          accessibilityLabel="Saving annotated issue mark"
          accessibilityLiveRegion="polite"
          accessibilityRole="progressbar"
          pointerEvents="none"
          style={styles.hiddenProgress}
        >
          <ActivityIndicator />
        </View>
      ) : null}

      {!state.saving && state.activeTool !== null ? (
        <View
          pointerEvents="box-none"
          style={[styles.toolbarPosition, { bottom: bottomOffset, right: rightOffset }]}
        >
          <View style={styles.instructionPill}>
            <Text style={styles.instructionText}>Draw on the screen · app controls are paused</Text>
          </View>
          {feedback ? (
            <View accessibilityLiveRegion="assertive" accessibilityRole="alert" style={styles.feedbackPill}>
              <Text style={styles.feedbackText}>{feedback}</Text>
            </View>
          ) : null}
          <View style={styles.toolbar}>
            <RoundControl
              accessibilityLabel="Use pen"
              label="Pen"
              onPress={() => dispatch({ type: "select_tool", tool: "pen" })}
              selected={state.activeTool === "pen"}
            />
            <RoundControl
              accessibilityLabel="Use highlighter"
              label="Hi"
              onPress={() => dispatch({ type: "select_tool", tool: "highlighter" })}
              selected={state.activeTool === "highlighter"}
            />
            <RoundControl
              accessibilityLabel="Undo last stroke"
              disabled={state.strokes.length === 0}
              label="Undo"
              onPress={() => dispatch({ type: "undo" })}
            />
            <RoundControl
              accessibilityLabel="Clear drawing"
              disabled={state.strokes.length === 0}
              label="Clear"
              onPress={() => dispatch({ type: "clear" })}
            />
            <RoundControl
              accessibilityLabel="Cancel drawing"
              label="×"
              onPress={() => dispatch({ type: "cancel" })}
            />
            <RoundControl
              accessibilityLabel="Mark annotated issue"
              disabled={state.strokes.length === 0 || markLimitReached}
              label="Mark"
              onPress={() => { void createIssueMark(false); }}
            />
          </View>
          {drawingLimitReached ? (
            <Text accessibilityRole="alert" style={styles.limitText}>
              Drawing limit reached. Undo or clear a stroke before continuing.
            </Text>
          ) : null}
        </View>
      ) : null}

      {!state.saving && state.activeTool === null ? (
        <View
          pointerEvents="box-none"
          style={[styles.fabPosition, { bottom: bottomOffset, right: rightOffset }]}
        >
          {feedback ? (
            <View accessibilityLiveRegion="polite" style={styles.feedbackPill}>
              <Text style={styles.feedbackText}>{feedback}</Text>
            </View>
          ) : null}
          {state.menuOpen ? (
            <View pointerEvents="box-none" style={styles.menu}>
              <MenuAction
                disabled={markLimitReached}
                label="Draw"
                onPress={() => dispatch({ type: "select_tool", tool: "pen" })}
                symbol="✎"
              />
              <MenuAction
                disabled={markLimitReached}
                label="Highlight"
                onPress={() => dispatch({ type: "select_tool", tool: "highlighter" })}
                symbol="▰"
              />
              <MenuAction
                disabled={markLimitReached}
                label="Mark without drawing"
                onPress={() => { void createIssueMark(true); }}
                symbol="!"
              />
              <Text style={styles.markCountText}>
                {markLimitReached
                  ? `${defaultMaximumIssueMarks} issue mark limit reached`
                  : `${defaultMaximumIssueMarks - issueMarkCount} issue marks remaining`}
              </Text>
            </View>
          ) : null}
          <Pressable
            accessibilityLabel={state.menuOpen ? "Close Tacua issue tools" : "Open Tacua issue tools"}
            accessibilityRole="button"
            accessibilityState={{ expanded: state.menuOpen }}
            hitSlop={6}
            onPress={() => dispatch({ type: "toggle_menu" })}
            style={({ pressed }) => [styles.fab, pressed ? styles.pressed : null]}
          >
            <Text style={styles.fabSymbol}>{state.menuOpen ? "×" : "✎"}</Text>
          </Pressable>
        </View>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  overlayRoot: {
    position: "absolute",
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
    zIndex: 10_000,
  },
  canvas: {
    position: "absolute",
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
  },
  framePulse: {
    position: "absolute",
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
    backgroundColor: "transparent",
  },
  framePulseActive: {
    backgroundColor: "rgba(255,255,255,0.004)",
  },
  strokeLayer: {
    position: "absolute",
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
  },
  hiddenProgress: {
    position: "absolute",
    width: 1,
    height: 1,
    opacity: 0,
  },
  fabPosition: {
    position: "absolute",
    alignItems: "flex-end",
    gap: 10,
  },
  fab: {
    width: 58,
    height: 58,
    borderRadius: 29,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#006E67",
    borderColor: "rgba(255,255,255,0.82)",
    borderWidth: 2,
    shadowColor: "#000000",
    shadowOffset: { width: 0, height: 5 },
    shadowOpacity: 0.28,
    shadowRadius: 9,
    elevation: 12,
  },
  fabSymbol: {
    color: "#FFFFFF",
    fontSize: 27,
    lineHeight: 30,
    fontWeight: "800",
  },
  menu: {
    alignItems: "flex-end",
    gap: 9,
  },
  menuAction: {
    minHeight: 48,
    flexDirection: "row",
    alignItems: "center",
    gap: 9,
  },
  menuActionLabel: {
    overflow: "hidden",
    color: "#FFFFFF",
    backgroundColor: "rgba(5,8,6,0.92)",
    borderRadius: 16,
    paddingHorizontal: 12,
    paddingVertical: 8,
    fontSize: 14,
    fontWeight: "800",
  },
  menuActionCircle: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: "#121916",
    borderColor: "rgba(255,255,255,0.72)",
    borderWidth: 1,
    alignItems: "center",
    justifyContent: "center",
    shadowColor: "#000000",
    shadowOffset: { width: 0, height: 3 },
    shadowOpacity: 0.22,
    shadowRadius: 6,
    elevation: 8,
  },
  menuActionSymbol: {
    color: "#64DFD0",
    fontSize: 21,
    fontWeight: "900",
  },
  markCountText: {
    color: "#FFFFFF",
    backgroundColor: "rgba(5,8,6,0.88)",
    borderRadius: 12,
    paddingHorizontal: 10,
    paddingVertical: 6,
    fontSize: 12,
    fontWeight: "700",
  },
  feedbackPill: {
    maxWidth: 270,
    backgroundColor: "rgba(5,8,6,0.94)",
    borderColor: "rgba(100,223,208,0.7)",
    borderWidth: 1,
    borderRadius: 14,
    paddingHorizontal: 12,
    paddingVertical: 9,
  },
  feedbackText: {
    color: "#FFFFFF",
    fontSize: 13,
    lineHeight: 18,
    fontWeight: "700",
  },
  toolbarPosition: {
    position: "absolute",
    left: 16,
    alignItems: "flex-end",
    gap: 8,
  },
  instructionPill: {
    alignSelf: "center",
    backgroundColor: "rgba(5,8,6,0.92)",
    borderRadius: 14,
    paddingHorizontal: 12,
    paddingVertical: 7,
  },
  instructionText: {
    color: "#FFFFFF",
    fontSize: 12,
    lineHeight: 16,
    fontWeight: "700",
    textAlign: "center",
  },
  toolbar: {
    alignSelf: "stretch",
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "flex-end",
    gap: 8,
    backgroundColor: "rgba(5,8,6,0.92)",
    borderColor: "rgba(255,255,255,0.24)",
    borderWidth: 1,
    borderRadius: 24,
    padding: 8,
    shadowColor: "#000000",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.26,
    shadowRadius: 8,
    elevation: 10,
  },
  roundControl: {
    minWidth: 48,
    height: 48,
    paddingHorizontal: 9,
    borderRadius: 24,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#25302B",
    borderColor: "rgba(255,255,255,0.28)",
    borderWidth: 1,
  },
  roundControlSelected: {
    backgroundColor: "#64DFD0",
    borderColor: "#FFFFFF",
    borderWidth: 2,
  },
  roundControlText: {
    color: "#FFFFFF",
    fontSize: 11,
    fontWeight: "900",
  },
  roundControlTextSelected: {
    color: "#052B28",
  },
  limitText: {
    alignSelf: "center",
    color: "#FFFFFF",
    backgroundColor: "rgba(152,69,0,0.94)",
    borderRadius: 12,
    paddingHorizontal: 10,
    paddingVertical: 7,
    fontSize: 12,
    fontWeight: "800",
  },
  pressed: {
    opacity: 0.68,
    transform: [{ scale: 0.97 }],
  },
  disabled: {
    opacity: 0.42,
  },
});
