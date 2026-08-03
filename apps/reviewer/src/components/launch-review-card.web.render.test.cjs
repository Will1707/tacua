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
const build = {
  application_id: "app_kuzaba_ios",
  build_id: "build_kuzaba_ios_0_1_0_2_example",
  build_identity_digest: `sha256:${"a".repeat(64)}`,
  bundle_identifier: "com.kuzaba.app",
  distribution: "local",
  native_build: "2",
  native_version: "0.1.0",
};
const grant = {
  build_identity_digest: build.build_identity_digest,
  exchange_kind: "start_session",
  expires_at: "2099-08-03T21:08:00Z",
  launch_code: "Private_launch_code_1234567890ABCDEFGHijklmn",
  launch_id: "launch_example_001",
  scope_policy_digest: `sha256:${"b".repeat(64)}`,
  session_id: null,
};
const expectedLaunchUrl = `tacua-qa-app://tacua/start?launch_code=${grant.launch_code}`;
const openedUrls = [];
const encodedUrls = [];
let sameDeviceLaunch = false;
let createGrantCalls = 0;

const client = {
  async createLaunchGrant(buildId) {
    createGrantCalls += 1;
    assert.equal(buildId, build.build_id);
    return grant;
  },
  async listBuilds() { return [build]; },
};
const reactNative = {
  DynamicColorIOS: ({ light }) => light,
  Image: "Image",
  Linking: { openURL: async (url) => { openedUrls.push(url); } },
  Platform: { OS: "web" },
  Pressable: "Pressable",
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
  const resolvedRequest = request === "@/components/launch-qr-code"
    ? path.join(reviewerSourceRoot, "components/launch-qr-code.web.tsx")
    : request.startsWith("@/")
      ? path.join(reviewerSourceRoot, request.slice(2))
      : request;
  return originalResolveFilename.call(this, resolvedRequest, parent, isMain, options);
};
Module._load = function load(request, parent, isMain) {
  if (request === "react-native") return reactNative;
  if (request === "expo-router/react-navigation") {
    return { DarkTheme: { colors: {} }, DefaultTheme: { colors: {} } };
  }
  if (request === "@/utils/launch-qr-data-uri") {
    return {
      launchQRCodeDataUri(url) {
        encodedUrls.push(url);
        return "data:image/svg+xml;charset=utf-8,%3Csvg%2F%3E";
      },
    };
  }
  if (request === "@/api/client") {
    return { TacuaApiError: class TacuaApiError extends Error {} };
  }
  if (request === "@/utils/launch-device") {
    return { shouldAttemptSameDeviceLaunch: () => sameDeviceLaunch };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const { LaunchReviewCard } = require(path.join(
  reviewerSourceRoot,
  "components/launch-review-card.tsx",
));

function nodeText(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (!node) return "";
  if (Array.isArray(node)) return node.map(nodeText).join("");
  return nodeText(node.props?.children);
}

async function settle() {
  for (let index = 0; index < 4; index += 1) {
    await TestRenderer.act(async () => new Promise((resolve) => setImmediate(resolve)));
  }
}

function press(renderer, label) {
  return renderer.root.findAllByType("Pressable").find(
    (node) => node.props.accessibilityLabel === label || nodeText(node) === label,
  );
}

test("desktop creates a local private QR without navigating the computer", async () => {
  sameDeviceLaunch = false;
  createGrantCalls = 0;
  openedUrls.length = 0;
  encodedUrls.length = 0;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(LaunchReviewCard, {
      client,
      targetScheme: "tacua-qa-app",
    }));
  });
  try {
    await settle();
    let texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.match(texts, /reviewer is open on a computer/u);
    assert.match(texts, /Create QR/u);

    const create = press(renderer, "Create iPhone launch QR code for app_kuzaba_ios");
    assert.ok(create);
    await TestRenderer.act(async () => create.props.onPress());
    await settle();

    assert.deepEqual(openedUrls, []);
    assert.deepEqual(encodedUrls, [expectedLaunchUrl]);
    texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.match(texts, /Scan on the QA iPhone/u);
    assert.match(texts, /Custom URL schemes are not exclusive/u);
    assert.doesNotMatch(texts, /can launch only/u);
    assert.match(texts, /never sends it to a QR service/u);
    assert.doesNotMatch(texts, new RegExp(grant.launch_code, "u"));
    const image = renderer.root.findByType("Image");
    assert.match(image.props.accessibilityLabel, /One-time QR code/u);

    const fallback = press(renderer, "Open on this device instead");
    assert.ok(fallback);
    await TestRenderer.act(async () => fallback.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, [expectedLaunchUrl]);

    const createAnother = press(renderer, "Create iPhone launch QR code for app_kuzaba_ios");
    assert.ok(createAnother);
    assert.equal(createAnother.props.disabled, true);
    await TestRenderer.act(async () => createAnother.props.onPress());
    await settle();
    assert.equal(createGrantCalls, 1);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("iPhone browser requires a fresh user tap after the asynchronous grant", async () => {
  reactNative.Platform.OS = "web";
  sameDeviceLaunch = true;
  createGrantCalls = 0;
  openedUrls.length = 0;
  encodedUrls.length = 0;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(LaunchReviewCard, {
      client,
      targetScheme: "tacua-qa-app",
    }));
  });
  try {
    await settle();
    const prepare = press(renderer, "Prepare app_kuzaba_ios QA build launch on this device");
    assert.ok(prepare);
    await TestRenderer.act(async () => prepare.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, []);
    assert.deepEqual(encodedUrls, []);
    assert.equal(renderer.root.findAllByType("Image").length, 0);

    const explicitOpen = press(renderer, "Open the QA build");
    assert.ok(explicitOpen);
    await TestRenderer.act(async () => explicitOpen.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, [expectedLaunchUrl]);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("native reviewer opens the QA build immediately after grant creation", async () => {
  reactNative.Platform.OS = "ios";
  sameDeviceLaunch = true;
  createGrantCalls = 0;
  openedUrls.length = 0;
  encodedUrls.length = 0;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(LaunchReviewCard, {
      client,
      targetScheme: "tacua-qa-app",
    }));
  });
  try {
    await settle();
    const open = press(renderer, "Open app_kuzaba_ios QA build on this device");
    assert.ok(open);
    await TestRenderer.act(async () => open.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, [expectedLaunchUrl]);
    assert.deepEqual(encodedUrls, []);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
    reactNative.Platform.OS = "web";
  }
});

test.after(() => {
  Module._load = originalLoad;
  Module._resolveFilename = originalResolveFilename;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
  if (originalTSXLoader) Module._extensions[".tsx"] = originalTSXLoader;
  else delete Module._extensions[".tsx"];
});
