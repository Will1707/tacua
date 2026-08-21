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
  launch_scheme: "tacua-kuzaba-qa",
  native_build: "2",
  native_version: "0.1.0",
};
const bootstrap = {
  contract_version: "tacua.reviewer-bootstrap@1.0.0",
  reviewer_id: "reviewer_owner",
  builds: [build],
};
const session = {
  build_id: build.build_id,
  build_identity_digest: build.build_identity_digest,
  scope_digest: `sha256:${"b".repeat(64)}`,
  session_id: "session_kuzaba_001",
};
const grant = {
  build_identity_digest: session.build_identity_digest,
  exchange_kind: "resume_session",
  expires_at: "2099-08-03T21:08:00Z",
  launch_code: "Private_resume_code_1234567890ABCDEFGHijklmn",
  launch_id: "launch_resume_001",
  scope_digest: session.scope_digest,
  session_id: session.session_id,
};
const expectedLaunchUrl = `${build.launch_scheme}://tacua/start?launch_code=${grant.launch_code}&session_id=${session.session_id}`;
const link = {
  contract_version: "tacua.reviewer-launch-link@1.0.0",
  launch_url: expectedLaunchUrl,
  grant,
};
const openedUrls = [];
let createLinkCalls = 0;
let returnedLink = link;
let sameDeviceLaunch = true;

const client = {
  async createResumeLaunchLink(sessionId, expectedScheme, expectedBuildIdentityDigest) {
    createLinkCalls += 1;
    assert.equal(sessionId, session.session_id);
    assert.equal(expectedScheme, build.launch_scheme);
    assert.equal(expectedBuildIdentityDigest, session.build_identity_digest);
    return returnedLink;
  },
};
const reactNative = {
  ActivityIndicator: "ActivityIndicator",
  DynamicColorIOS: ({ light }) => light,
  Linking: { openURL: async (url) => { openedUrls.push(url); } },
  Platform: { OS: "ios" },
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
  if (request === "@/api/client") {
    return {
      TacuaApiError: class TacuaApiError extends Error {
        constructor(status, code, message) {
          super(message);
          this.status = status;
          this.code = code;
        }
      },
    };
  }
  if (request === "@/components/launch-qr-code") {
    return {
      LaunchQRCode: (props) => React.createElement("LaunchQRCodeMock", props),
    };
  }
  if (request === "@/utils/launch-device") {
    return { shouldAttemptSameDeviceLaunch: () => sameDeviceLaunch };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const { ResumeSessionCard } = require(path.join(
  reviewerSourceRoot,
  "components/resume-session-card.tsx",
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

test("native recovery opens the exact server-provided URL", async () => {
  reactNative.Platform.OS = "ios";
  createLinkCalls = 0;
  openedUrls.length = 0;
  returnedLink = link;
  sameDeviceLaunch = true;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(ResumeSessionCard, {
      bootstrap,
      client,
      session,
    }));
  });
  try {
    await settle();
    const open = press(renderer, "Open QA build recovery");
    assert.ok(open);
    await TestRenderer.act(async () => open.props.onPress());
    await settle();
    assert.equal(createLinkCalls, 1);
    assert.deepEqual(openedUrls, [expectedLaunchUrl]);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("web recovery requires a second tap and reuses the server URL verbatim", async () => {
  reactNative.Platform.OS = "web";
  createLinkCalls = 0;
  openedUrls.length = 0;
  returnedLink = link;
  sameDeviceLaunch = true;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(ResumeSessionCard, {
      bootstrap,
      client,
      session,
    }));
  });
  try {
    await settle();
    const prepare = press(renderer, "Prepare QA build recovery");
    assert.ok(prepare);
    await TestRenderer.act(async () => prepare.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, []);
    const explicitOpen = press(renderer, "Open prepared QA build recovery");
    assert.ok(explicitOpen);
    await TestRenderer.act(async () => explicitOpen.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, [expectedLaunchUrl]);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
    reactNative.Platform.OS = "ios";
  }
});

test("a recovery link with another scope fails closed", async () => {
  reactNative.Platform.OS = "ios";
  createLinkCalls = 0;
  openedUrls.length = 0;
  sameDeviceLaunch = true;
  returnedLink = {
    ...link,
    grant: { ...grant, scope_digest: `sha256:${"f".repeat(64)}` },
  };
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(ResumeSessionCard, {
      bootstrap,
      client,
      session,
    }));
  });
  try {
    await settle();
    const open = press(renderer, "Open QA build recovery");
    await TestRenderer.act(async () => open.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, []);
    const texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.match(texts, /another capture scope/u);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
    returnedLink = link;
  }
});

test("a legacy bootstrap disables recovery without minting a link", async () => {
  createLinkCalls = 0;
  openedUrls.length = 0;
  sameDeviceLaunch = true;
  const legacyBootstrap = {
    ...bootstrap,
    builds: [{ ...build, launch_scheme: null }],
  };
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(ResumeSessionCard, {
      bootstrap: legacyBootstrap,
      client,
      session,
    }));
  });
  try {
    await settle();
    const open = press(renderer, "Open QA build recovery");
    assert.ok(open);
    assert.equal(open.props.disabled, true);
    await TestRenderer.act(async () => open.props.onPress());
    await settle();
    assert.equal(createLinkCalls, 0);
    assert.deepEqual(openedUrls, []);
    const texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.match(texts, /SDK transport 1\.2/u);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("desktop recovery QR encodes the exact server-provided URL", async () => {
  reactNative.Platform.OS = "web";
  createLinkCalls = 0;
  openedUrls.length = 0;
  returnedLink = link;
  sameDeviceLaunch = false;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(ResumeSessionCard, {
      bootstrap,
      client,
      session,
    }));
  });
  try {
    await settle();
    const create = press(renderer, "Create recovery QR code");
    assert.ok(create);
    await TestRenderer.act(async () => create.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, []);
    const qr = renderer.root.findByType("LaunchQRCodeMock");
    assert.equal(qr.props.launchUrl, expectedLaunchUrl);
    const fallback = press(renderer, "Open QA build recovery on this device instead");
    assert.ok(fallback);
    await TestRenderer.act(async () => fallback.props.onPress());
    await settle();
    assert.deepEqual(openedUrls, [expectedLaunchUrl]);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
    reactNative.Platform.OS = "ios";
    sameDeviceLaunch = true;
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
