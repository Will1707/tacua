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
const mockPlatform = { OS: "ios" };
const configureEndpointCalls = [];
const bootstrap = {
  contract_version: "tacua.reviewer-bootstrap@1.0.0",
  reviewer_id: "reviewer_owner",
  builds: [],
};

function session(authKind) {
  return {
    reviewer_id: bootstrap.reviewer_id,
    auth_kind: authKind,
    session_id: authKind === "session" ? "rsess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" : null,
    device_label: "Reviewer device",
    client_kind: mockPlatform.OS === "web" ? "web" : "native",
    scopes: ["reviewer.read", "reviewer.launch", "reviewer.write"],
    expires_at: null,
    csrf_token: authKind === "session" && mockPlatform.OS === "web" ? "csrf-token" : null,
  };
}

function connectedContext(authKind, sessionToken = null) {
  return {
    bootstrap,
    client: {},
    config: { baseUrl: "https://old-backend.example", sessionToken },
    session: session(authKind),
    status: "connected",
    loading: false,
    pairing: null,
    error: null,
    migrationRequired: false,
    async reload() {},
    async configureEndpoint(baseUrl) { configureEndpointCalls.push(baseUrl); },
    async beginPairing() {},
    async cancelPairing() {},
    async disconnect() {},
  };
}

let backendContext = connectedContext("tailscale_capability");

const reactNative = {
  DynamicColorIOS: ({ light }) => light,
  Platform: mockPlatform,
  ScrollView: "ScrollView",
  Text: "Text",
  TextInput: "TextInput",
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
  if (request === "@/components/action-button") {
    return {
      ActionButton: (props) => React.createElement("ActionButtonMock", props),
    };
  }
  if (request === "@/hooks/use-backend") {
    return { useBackend: () => backendContext };
  }
  if (request === "@/providers/app-dialog") {
    return { useAppDialog: () => () => {} };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const SettingsRoute = require(path.join(reviewerSourceRoot, "app/settings.tsx")).default;

function nodeText(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (!node) return "";
  if (Array.isArray(node)) return node.map(nodeText).join("");
  return nodeText(node.props?.children ?? node.children);
}

function action(renderer, label) {
  return renderer.root.findAllByType("ActionButtonMock").find((node) => node.props.label === label);
}

async function settle() {
  for (let index = 0; index < 4; index += 1) {
    await TestRenderer.act(async () => new Promise((resolve) => setImmediate(resolve)));
  }
}

async function renderSettings() {
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(SettingsRoute));
  });
  await settle();
  return renderer;
}

test.beforeEach(() => {
  mockPlatform.OS = "ios";
  configureEndpointCalls.length = 0;
  backendContext = connectedContext("tailscale_capability");
});

test("native capability access can replace the stored backend endpoint", async () => {
  const renderer = await renderSettings();
  try {
    const input = renderer.root.findByProps({ accessibilityLabel: "Backend URL" });
    assert.equal(input.props.editable, true);

    await TestRenderer.act(async () => {
      input.props.onChangeText("https://new-backend.example");
    });

    const update = action(renderer, "Update endpoint");
    assert.ok(update);
    assert.equal(update.props.disabled, false);
    await TestRenderer.act(async () => update.props.onPress());
    await settle();

    assert.deepEqual(configureEndpointCalls, ["https://new-backend.example"]);
    assert.match(nodeText(renderer.toJSON()), /To use another backend, update the endpoint above\./u);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("native paired sessions keep endpoint replacement locked behind revocation", async () => {
  const sessionToken = `rsess_${"a".repeat(32)}.${"B".repeat(43)}`;
  backendContext = connectedContext("session", sessionToken);
  const renderer = await renderSettings();
  try {
    const input = renderer.root.findByProps({ accessibilityLabel: "Backend URL" });
    assert.equal(input.props.editable, false);
    assert.equal(action(renderer, "Update endpoint"), undefined);
    assert.ok(action(renderer, "Disconnect paired reviewer"));
    assert.deepEqual(configureEndpointCalls, []);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("web capability access remains bound to the page exact origin", async () => {
  mockPlatform.OS = "web";
  backendContext = connectedContext("tailscale_capability");
  const renderer = await renderSettings();
  try {
    assert.equal(renderer.root.findAllByType("TextInput").length, 0);
    assert.equal(action(renderer, "Update endpoint"), undefined);
    assert.match(nodeText(renderer.toJSON()), /Backend originhttps:\/\/old-backend\.example/u);
    assert.match(nodeText(renderer.toJSON()), /page’s exact HTTPS origin/u);
    assert.deepEqual(configureEndpointCalls, []);
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
