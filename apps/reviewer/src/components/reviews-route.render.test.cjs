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
  application_id: "app_old_backend_ios",
  build_id: "build_old_backend_ios_1",
  created_at: "2026-08-21T10:00:00Z",
  session_id: "session_old_backend_001",
  state: "receiving",
};
const bootstrap = {
  contract_version: "tacua.reviewer-bootstrap@1.0.0",
  reviewer_id: "reviewer_owner",
  builds: [],
};
const client = {
  async listSessions(cursor) {
    assert.equal(cursor, undefined);
    return { sessions: [session], next_cursor: null };
  },
};
const connectedContext = {
  bootstrap,
  client,
  config: { baseUrl: "https://old-backend.example", sessionToken: null },
  session: {
    authKind: "web_session",
    expiresAt: "2026-08-22T10:00:00Z",
    reviewerId: bootstrap.reviewer_id,
  },
  status: "connected",
  pairing: null,
  error: null,
  migrationRequired: false,
  async reload() {},
  async beginPairing() {},
  cancelPairing() {},
};
let backendContext = connectedContext;

const reactNative = {
  ActivityIndicator: "ActivityIndicator",
  AppState: {
    currentState: "active",
    addEventListener: () => ({ remove() {} }),
  },
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
    return { Link };
  }
  if (request === "@/components/launch-review-card") {
    return {
      LaunchReviewCard: (props) => React.createElement("LaunchReviewCardMock", props),
    };
  }
  if (request === "@/hooks/use-backend") {
    return { useBackend: () => backendContext };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const ReviewsRoute = require(path.join(reviewerSourceRoot, "app/index.tsx")).default;

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
  backendContext = connectedContext;
});

test("review sessions disappear across backend replacement and auth loss", async () => {
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(ReviewsRoute));
  });
  try {
    await settle();
    assert.match(nodeText(renderer.toJSON()), new RegExp(session.build_id, "u"));
    assert.match(nodeText(renderer.toJSON()), new RegExp(session.application_id, "u"));

    let replacementLoads = 0;
    const replacementClient = {
      async listSessions() {
        replacementLoads += 1;
        throw new Error("replacement backend did not verify these sessions");
      },
    };
    backendContext = {
      ...connectedContext,
      bootstrap: { ...bootstrap, reviewer_id: "reviewer_replacement" },
      client: replacementClient,
      config: { baseUrl: "https://replacement-backend.example", sessionToken: null },
      session: {
        ...connectedContext.session,
        reviewerId: "reviewer_replacement",
      },
    };
    await TestRenderer.act(async () => {
      renderer.update(React.createElement(ReviewsRoute));
    });
    await settle();

    assert.equal(replacementLoads, 1);
    const replacementText = nodeText(renderer.toJSON());
    assert.doesNotMatch(replacementText, new RegExp(session.build_id, "u"));
    assert.doesNotMatch(replacementText, new RegExp(session.application_id, "u"));
    assert.match(replacementText, /Could not load sessions/u);

    backendContext = {
      ...connectedContext,
      bootstrap: null,
      client: null,
      config: null,
      session: null,
      status: "pairing_required",
    };
    await TestRenderer.act(async () => {
      renderer.update(React.createElement(ReviewsRoute));
    });
    const disconnectedText = nodeText(renderer.toJSON());
    assert.doesNotMatch(disconnectedText, new RegExp(session.build_id, "u"));
    assert.doesNotMatch(disconnectedText, new RegExp(session.application_id, "u"));
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
