// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");

const packageRoot = path.resolve(__dirname, "..");
const harnessRoot = path.resolve(packageRoot, "../harness");
const fromHarness = (request) => require(require.resolve(request, { paths: [harnessRoot] }));
const babel = fromHarness("@babel/core");
const transformModulesCommonJS = fromHarness("@babel/plugin-transform-modules-commonjs");
const transformReactJSX = fromHarness("@babel/plugin-transform-react-jsx");
const transformTypeScript = fromHarness("@babel/plugin-transform-typescript");
const React = fromHarness("react");
const reactJSXRuntime = fromHarness("react/jsx-runtime");
const TestRenderer = fromHarness("react-test-renderer");

global.IS_REACT_ACT_ENVIRONMENT = true;

const nativeStatus = {
  state: "recording",
  recorderRecording: true,
  appendedVideoFrameSequence: 1,
  latestMediaPTSSeconds: 10,
  markerCount: 0,
};
let advanceOnStatusRead = null;
let nativeMarkCalls = 0;
let nativeStatusReads = 0;
const nativeModule = {
  getStatus: () => {
    nativeStatusReads += 1;
    if (nativeStatusReads === advanceOnStatusRead) {
      nativeStatus.appendedVideoFrameSequence += 1;
    }
    return nativeStatus;
  },
  mark: async () => {
    nativeMarkCalls += 1;
    return {
      id: "marker_render_test",
      label: "screen_annotation",
      hostUptimeSeconds: 10,
      latestMediaPTSSeconds: 10,
    };
  },
};
const reactNative = {
  ActivityIndicator: "ActivityIndicator",
  PanResponder: {
    create: (handlers) => ({
      panHandlers: {
        onStartShouldSetResponder: handlers.onStartShouldSetPanResponder,
        onMoveShouldSetResponder: handlers.onMoveShouldSetPanResponder,
        onResponderGrant: handlers.onPanResponderGrant,
        onResponderMove: handlers.onPanResponderMove,
        onResponderRelease: handlers.onPanResponderRelease,
        onResponderTerminate: handlers.onPanResponderTerminate,
        onResponderTerminationRequest: handlers.onPanResponderTerminationRequest,
      },
    }),
  },
  Pressable: "Pressable",
  StyleSheet: { create: (value) => value },
  Text: "Text",
  View: "View",
};

const originalLoad = Module._load;
const originalTypeScriptLoader = Module._extensions[".ts"];
const originalTSXLoader = Module._extensions[".tsx"];

function compileTypeScript(module, filename) {
  const result = babel.transformSync(fs.readFileSync(filename, "utf8"), {
    babelrc: false,
    configFile: false,
    filename,
    plugins: [
      [transformTypeScript, { isTSX: filename.endsWith(".tsx"), allExtensions: true }],
      [transformReactJSX, { runtime: "automatic" }],
      transformModulesCommonJS,
    ],
    sourceMaps: "inline",
  });
  module._compile(result.code, filename);
}

Module._extensions[".ts"] = compileTypeScript;
Module._extensions[".tsx"] = compileTypeScript;
Module._load = function load(request, parent, isMain) {
  if (request === "react") return React;
  if (request === "react/jsx-runtime") return reactJSXRuntime;
  if (request === "react-native") return reactNative;
  if (
    request === "./TacuaCaptureSpikeModule"
    && parent?.filename.endsWith("TacuaAnnotationOverlay.tsx")
  ) return { TacuaCaptureSpikeModule: nativeModule };
  return originalLoad.call(this, request, parent, isMain);
};

const { TacuaAnnotationOverlay } = require(path.join(
  packageRoot,
  "src/TacuaAnnotationOverlay.tsx",
));

function press(renderer, label) {
  return renderer.root.findAllByType("Pressable").find(
    (node) => node.props.accessibilityLabel === label,
  );
}

function responderEvent(x, y, touches = [{}]) {
  return { nativeEvent: { locationX: x, locationY: y, touches } };
}

function nearestViewAncestor(node) {
  let candidate = node.parent;
  while (candidate && candidate.type !== "View") candidate = candidate.parent;
  return candidate;
}

function overlayElement(properties = {}) {
  return React.createElement(TacuaAnnotationOverlay, {
    recording: true,
    captureState: "recording",
    sessionId: "qa_render_test",
    issueMarkCount: 0,
    ...properties,
  });
}

async function renderOverlay(properties = {}) {
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(overlayElement(properties));
  });
  return renderer;
}

test("idle bubble passes touches through and exposes bounded drawing choices", async () => {
  const renderer = await renderOverlay();
  try {
    const overlayRoot = renderer.root.findAllByType("View").find(
      (node) => node.props.pointerEvents === "box-none" && node.props.style?.zIndex === 10_000,
    );
    assert.ok(overlayRoot);
    assert.equal(
      renderer.root.findAllByType("View").some(
        (node) => node.props.accessibilityLabel === "Screen annotation canvas",
      ),
      false,
    );

    const open = press(renderer, "Open Tacua issue tools");
    assert.ok(open);
    assert.equal(nearestViewAncestor(open).props.pointerEvents, "box-none");
    const fabStyle = open.props.style({ pressed: false });
    assert.equal(fabStyle[0].width, 58);
    assert.equal(fabStyle[0].height, 58);
    await TestRenderer.act(async () => open.props.onPress());

    assert.ok(press(renderer, "Draw"));
    assert.ok(press(renderer, "Highlight"));
    assert.ok(press(renderer, "Mark without drawing"));
    assert.equal(press(renderer, "Draw").props.disabled, false);
    assert.equal(nearestViewAncestor(press(renderer, "Draw")).props.pointerEvents, "box-none");
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("draw and highlight capture the surface, render distinct strokes, and restore pass-through", async () => {
  const renderer = await renderOverlay();
  try {
    await TestRenderer.act(async () => press(renderer, "Open Tacua issue tools").props.onPress());
    await TestRenderer.act(async () => press(renderer, "Draw").props.onPress());
    let canvas = renderer.root.findAllByType("View").find(
      (node) => node.props.accessibilityLabel === "Screen annotation canvas",
    );
    assert.ok(canvas);
    assert.equal(canvas.props.pointerEvents, "auto");
    assert.equal(canvas.props.onStartShouldSetResponder(responderEvent(10, 20, [{}, {}])), false);
    assert.equal(canvas.props.onMoveShouldSetResponder(responderEvent(10, 20, [{}, {}])), false);
    await TestRenderer.act(async () => {
      canvas.props.onLayout({ nativeEvent: { layout: { width: 100, height: 200 } } });
    });
    canvas = renderer.root.findAllByType("View").find(
      (node) => node.props.accessibilityLabel === "Screen annotation canvas",
    );
    await TestRenderer.act(async () => {
      canvas.props.onResponderGrant(responderEvent(10, 20));
    });
    nativeStatusReads = 0;
    await TestRenderer.act(async () => {
      press(renderer, "Mark annotated issue").props.onPress();
    });
    assert.equal(nativeStatusReads, 0, "an in-progress gesture must not start evidence capture");
    await TestRenderer.act(async () => {
      canvas.props.onResponderMove(responderEvent(70, 100));
      canvas.props.onResponderRelease();
    });

    const penSegment = renderer.root.findAllByType("View").find(
      (node) => node.props.style?.backgroundColor === "#FF4F5E",
    );
    assert.ok(penSegment);
    assert.equal(penSegment.props.pointerEvents, "none");
    assert.equal(penSegment.props.style.height, 5);
    assert.equal(press(renderer, "Mark annotated issue").props.disabled, false);

    await TestRenderer.act(async () => press(renderer, "Use highlighter").props.onPress());
    canvas = renderer.root.findAllByType("View").find(
      (node) => node.props.accessibilityLabel === "Screen annotation canvas",
    );
    await TestRenderer.act(async () => {
      canvas.props.onResponderGrant(responderEvent(20, 40));
      canvas.props.onResponderMove(responderEvent(80, 140));
      canvas.props.onResponderRelease();
    });
    const highlightSegment = renderer.root.findAllByType("View").find(
      (node) => node.props.style?.backgroundColor === "#FFE45E",
    );
    assert.ok(highlightSegment);
    assert.equal(highlightSegment.props.style.height, 20);
    assert.equal(highlightSegment.parent.props.style[1].opacity, 0.42);

    await TestRenderer.act(async () => press(renderer, "Undo last stroke").props.onPress());
    assert.equal(
      renderer.root.findAllByType("View").some(
        (node) => node.props.style?.backgroundColor === "#FFE45E",
      ),
      false,
    );
    await TestRenderer.act(async () => press(renderer, "Clear drawing").props.onPress());
    assert.equal(press(renderer, "Mark annotated issue").props.disabled, true);
    await TestRenderer.act(async () => press(renderer, "Cancel drawing").props.onPress());
    assert.ok(press(renderer, "Open Tacua issue tools"));
    assert.equal(
      renderer.root.findAllByType("View").some(
        (node) => node.props.accessibilityLabel === "Screen annotation canvas",
      ),
      false,
    );
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("the processor mark limit disables every new issue action", async () => {
  const renderer = await renderOverlay({ issueMarkCount: 12 });
  try {
    await TestRenderer.act(async () => press(renderer, "Open Tacua issue tools").props.onPress());
    for (const label of ["Draw", "Highlight", "Mark without drawing"]) {
      assert.equal(press(renderer, label).props.disabled, true);
    }
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("mark waits for a successfully appended frame before committing native evidence", async () => {
  nativeMarkCalls = 0;
  nativeStatusReads = 0;
  nativeStatus.appendedVideoFrameSequence = 1;
  // Initial status, post-hide baseline, then the first retained-frame poll.
  advanceOnStatusRead = 3;
  const renderer = await renderOverlay({
    onMarkerCreated: () => {
      throw new Error("host callback failures must not roll back a native mark");
    },
  });
  try {
    await TestRenderer.act(async () => press(renderer, "Open Tacua issue tools").props.onPress());
    await TestRenderer.act(async () => press(renderer, "Draw").props.onPress());
    let canvas = renderer.root.findAllByType("View").find(
      (node) => node.props.accessibilityLabel === "Screen annotation canvas",
    );
    await TestRenderer.act(async () => {
      canvas.props.onLayout({ nativeEvent: { layout: { width: 100, height: 100 } } });
    });
    canvas = renderer.root.findAllByType("View").find(
      (node) => node.props.accessibilityLabel === "Screen annotation canvas",
    );
    await TestRenderer.act(async () => {
      canvas.props.onResponderGrant(responderEvent(10, 10));
      canvas.props.onResponderMove(responderEvent(80, 80));
      canvas.props.onResponderRelease();
    });

    await TestRenderer.act(async () => {
      press(renderer, "Mark annotated issue").props.onPress();
      await new Promise((resolve) => setTimeout(resolve, 550));
    });

    assert.ok(nativeStatusReads >= 3);
    assert.equal(nativeMarkCalls, 1);
    assert.ok(press(renderer, "Open Tacua issue tools"));
  } finally {
    advanceOnStatusRead = null;
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("leaving the native recording state cancels an in-flight annotation mark", async () => {
  nativeMarkCalls = 0;
  nativeStatusReads = 0;
  advanceOnStatusRead = null;
  const renderer = await renderOverlay();
  try {
    await TestRenderer.act(async () => press(renderer, "Open Tacua issue tools").props.onPress());
    await TestRenderer.act(async () => {
      press(renderer, "Mark without drawing").props.onPress();
      renderer.update(overlayElement({ captureState: "stopping" }));
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    assert.equal(renderer.toJSON(), null);
    assert.equal(nativeMarkCalls, 0);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("a stale host render cannot start work after native capture becomes unmarkable", async () => {
  nativeMarkCalls = 0;
  nativeStatusReads = 0;
  nativeStatus.state = "stop_failed_capture_active";
  const renderer = await renderOverlay();
  try {
    await TestRenderer.act(async () => press(renderer, "Open Tacua issue tools").props.onPress());
    await TestRenderer.act(async () => press(renderer, "Mark without drawing").props.onPress());
    assert.equal(nativeStatusReads, 1);
    assert.equal(nativeMarkCalls, 0);
  } finally {
    nativeStatus.state = "recording";
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("the QA control is absent whenever native capture cannot accept marks", async () => {
  for (const properties of [
    { recording: false, captureState: "idle", sessionId: null },
    { recording: true, captureState: "stopping" },
    { recording: true, captureState: "stop_failed_capture_active" },
  ]) {
    const renderer = await renderOverlay(properties);
    try {
      assert.equal(renderer.toJSON(), null);
    } finally {
      await TestRenderer.act(async () => renderer.unmount());
    }
  }
});

test.after(() => {
  Module._load = originalLoad;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
  if (originalTSXLoader) Module._extensions[".tsx"] = originalTSXLoader;
  else delete Module._extensions[".tsx"];
});
