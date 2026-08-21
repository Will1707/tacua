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
const session = {
  application_id: "app_kuzaba_ios",
  build_id: "build_kuzaba_ios_0_1_0_2_example",
  build_identity_digest: `sha256:${"a".repeat(64)}`,
  created_at: "2026-08-21T10:00:00Z",
  diagnostics: [],
  jobs: [],
  retention: {
    raw_media_expires_at: "2026-08-28T10:00:00Z",
  },
  scope_digest: `sha256:${"b".repeat(64)}`,
  segments: [],
  session_id: "session_kuzaba_001",
  state: "receiving",
};
const bootstrap = {
  contract_version: "tacua.reviewer-bootstrap@1.0.0",
  reviewer_id: "reviewer_owner",
  builds: [{
    application_id: session.application_id,
    build_id: session.build_id,
    build_identity_digest: session.build_identity_digest,
    bundle_identifier: "com.kuzaba.app",
    distribution: "local",
    launch_scheme: "tacua-kuzaba-qa",
    native_build: "2",
    native_version: "0.1.0",
  }],
};
const client = {
  async getSession(sessionId) {
    assert.equal(sessionId, session.session_id);
    return session;
  },
  async listCandidates(sessionId) {
    assert.equal(sessionId, session.session_id);
    return { candidates: [], next_cursor: null };
  },
};
let backendContext = { bootstrap, client };

const reactNative = {
  ActivityIndicator: "ActivityIndicator",
  DynamicColorIOS: ({ light }) => light,
  Platform: { OS: "ios" },
  Pressable: "Pressable",
  RefreshControl: "RefreshControl",
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
  if (request === "expo-router") {
    const Link = ({ children }) => React.createElement(React.Fragment, null, children);
    Link.Trigger = ({ children }) => React.createElement(React.Fragment, null, children);
    Link.Preview = () => null;
    return { Link, useLocalSearchParams: () => ({ "session-id": session.session_id }) };
  }
  if (request === "@/components/candidate-merge-card") {
    return {
      CandidateMergeCard: (props) => React.createElement("CandidateMergeCardMock", props),
    };
  }
  if (request === "@/components/resume-session-card") {
    return {
      ResumeSessionCard: (props) => React.createElement("ResumeSessionCardMock", props),
    };
  }
  if (request === "@/hooks/use-backend") {
    return { useBackend: () => backendContext };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const SessionRoute = require(path.join(
  reviewerSourceRoot,
  "app/sessions/[session-id].tsx",
)).default;

async function settle() {
  for (let index = 0; index < 4; index += 1) {
    await TestRenderer.act(async () => new Promise((resolve) => setImmediate(resolve)));
  }
}

function nodeText(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (!node) return "";
  if (Array.isArray(node)) return node.map(nodeText).join("");
  return nodeText(node.props?.children ?? node.children);
}

test.beforeEach(() => {
  backendContext = { bootstrap, client };
});

test("session recovery and merge mutations use authoritative bootstrap bindings", async () => {
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(SessionRoute));
  });
  try {
    await settle();
    const recovery = renderer.root.findByType("ResumeSessionCardMock");
    assert.equal(recovery.props.bootstrap, bootstrap);
    assert.equal(recovery.props.client, client);
    assert.equal(recovery.props.session, session);

    const merge = renderer.root.findByType("CandidateMergeCardMock");
    assert.equal(merge.props.client, client);
    assert.equal(merge.props.reviewerId, bootstrap.reviewer_id);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("session details disappear when a replacement backend cannot verify them", async () => {
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(SessionRoute));
  });
  try {
    await settle();
    assert.match(nodeText(renderer.toJSON()), new RegExp(session.build_id, "u"));
    assert.equal(renderer.root.findAllByType("ResumeSessionCardMock").length, 1);

    let replacementLoads = 0;
    const replacementClient = {
      async getSession() {
        replacementLoads += 1;
        throw new Error("replacement backend did not verify this session");
      },
      async listCandidates() {
        throw new Error("candidate load must not run after a failed session load");
      },
    };
    backendContext = {
      bootstrap: { ...bootstrap, reviewer_id: "reviewer_replacement" },
      client: replacementClient,
    };
    await TestRenderer.act(async () => {
      renderer.update(React.createElement(SessionRoute));
    });
    await settle();

    assert.equal(replacementLoads, 1);
    const replacementText = nodeText(renderer.toJSON());
    assert.doesNotMatch(replacementText, new RegExp(session.build_id, "u"));
    assert.doesNotMatch(replacementText, new RegExp(session.application_id, "u"));
    assert.match(replacementText, /Session unavailable/u);
    assert.equal(renderer.root.findAllByType("ResumeSessionCardMock").length, 0);
    assert.equal(renderer.root.findAllByType("CandidateMergeCardMock").length, 0);

    backendContext = { bootstrap: null, client: null };
    await TestRenderer.act(async () => {
      renderer.update(React.createElement(SessionRoute));
    });
    assert.doesNotMatch(nodeText(renderer.toJSON()), new RegExp(session.build_id, "u"));
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
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
