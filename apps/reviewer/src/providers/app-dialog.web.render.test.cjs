// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");

const babel = require("@babel/core");
const transformModulesCommonJS = require("@babel/plugin-transform-modules-commonjs");
const transformReactJSX = require("@babel/plugin-transform-react-jsx");
const transformTypeScript = require("@babel/plugin-transform-typescript");
const React = require("react");
const TestRenderer = require("react-test-renderer");

global.IS_REACT_ACT_ENVIRONMENT = true;

const reviewerSourceRoot = path.resolve(__dirname, "..");
const reactNative = {
  DynamicColorIOS: ({ light }) => light,
  Modal: "Modal",
  Platform: { OS: "web" },
  Pressable: "Pressable",
  ScrollView: "ScrollView",
  Text: "Text",
  View: "View",
};
const originalLoad = Module._load;
const originalResolveFilename = Module._resolveFilename;
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
Module._resolveFilename = function resolveFilename(request, parent, isMain, options) {
  const resolvedRequest = request.startsWith("@/")
    ? path.join(reviewerSourceRoot, request.slice(2))
    : request;
  return originalResolveFilename.call(this, resolvedRequest, parent, isMain, options);
};
Module._load = function load(request, parent, isMain) {
  if (request === "react-native") return reactNative;
  if (request === "expo-router/react-navigation") {
    return { DarkTheme: { colors: {} }, DefaultTheme: { colors: {} } };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const {
  AppDialogProvider,
  useAppDialog,
} = require(path.join(reviewerSourceRoot, "providers/app-dialog.web.tsx"));

function Harness({ events }) {
  const showDialog = useAppDialog();
  return React.createElement(
    "Harness",
    null,
    React.createElement("Pressable", {
      accessibilityLabel: "Ask to delete",
      onPress: () => showDialog(
        "Delete exact item?",
        "This mutation needs a real browser confirmation.",
        [
          { text: "Cancel", style: "cancel", onPress: () => events.push("cancel") },
          { text: "Delete", style: "destructive", onPress: () => events.push("delete") },
        ],
      ),
    }),
    React.createElement("Pressable", {
      accessibilityLabel: "Show information",
      onPress: () => showDialog("Saved", "The exact item was saved."),
    }),
  );
}

function modal(renderer) {
  return renderer.root.findByType("Modal");
}

function press(renderer, label) {
  return renderer.root.findAllByType("Pressable").find(
    (node) => node.props.accessibilityLabel === label,
  );
}

test("web confirmation renders real cancel and destructive actions", async () => {
  const events = [];
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(
      React.createElement(
        AppDialogProvider,
        null,
        React.createElement(Harness, { events }),
      ),
    );
  });
  try {
    assert.equal(modal(renderer).props.visible, false);
    await TestRenderer.act(async () => press(renderer, "Ask to delete").props.onPress());
    assert.equal(modal(renderer).props.visible, true);
    assert.ok(press(renderer, "Cancel"));
    assert.ok(press(renderer, "Delete"));
    assert.equal(events.length, 0);

    await TestRenderer.act(async () => press(renderer, "Cancel").props.onPress());
    assert.deepEqual(events, ["cancel"]);
    assert.equal(modal(renderer).props.visible, false);

    await TestRenderer.act(async () => press(renderer, "Ask to delete").props.onPress());
    await TestRenderer.act(async () => press(renderer, "Delete").props.onPress());
    assert.deepEqual(events, ["cancel", "delete"]);
    assert.equal(modal(renderer).props.visible, false);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("escape follows the cancel action and information gets an OK action", async () => {
  const events = [];
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(
      React.createElement(
        AppDialogProvider,
        null,
        React.createElement(Harness, { events }),
      ),
    );
  });
  try {
    await TestRenderer.act(async () => press(renderer, "Ask to delete").props.onPress());
    await TestRenderer.act(async () => modal(renderer).props.onRequestClose());
    assert.deepEqual(events, ["cancel"]);
    assert.equal(modal(renderer).props.visible, false);

    await TestRenderer.act(async () => press(renderer, "Show information").props.onPress());
    assert.equal(modal(renderer).props.visible, true);
    assert.ok(press(renderer, "OK"));
    await TestRenderer.act(async () => press(renderer, "OK").props.onPress());
    assert.equal(modal(renderer).props.visible, false);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("unmounting a dialog owner removes its pending callback", async () => {
  const events = [];
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(
      React.createElement(
        AppDialogProvider,
        null,
        React.createElement(Harness, { events }),
      ),
    );
  });
  await TestRenderer.act(async () => press(renderer, "Ask to delete").props.onPress());
  assert.equal(modal(renderer).props.visible, true);
  await TestRenderer.act(async () => {
    renderer.update(React.createElement(AppDialogProvider));
  });
  assert.equal(modal(renderer).props.visible, false);
  assert.deepEqual(events, []);
  await TestRenderer.act(async () => renderer.unmount());
});

test.after(() => {
  Module._load = originalLoad;
  Module._resolveFilename = originalResolveFilename;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
  if (originalTSXLoader) Module._extensions[".tsx"] = originalTSXLoader;
  else delete Module._extensions[".tsx"];
});
