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

const repositoryRoot = path.resolve(__dirname, "../../../..");
const reviewerSourceRoot = path.join(repositoryRoot, "apps/reviewer/src");
const candidate = JSON.parse(fs.readFileSync(
  path.join(repositoryRoot, "contracts/ticket-candidate/fixtures/positive/version-3-ready.json"),
  "utf8",
));
const screenshot = {
  evidence_id: "evidence_keyframe_001",
  evidence_type: "media.keyframe",
  availability: "available",
  description: "The enabled profile action reads Save draft.",
  time_range: { start_ms: 4_000, end_ms: 4_000, clock: "session_monotonic" },
  source: {
    component: "mobile_sdk",
    source_id: "segment_synthetic_001",
    snapshot_revision: "1",
    captured_at: "2026-07-21T10:00:04Z",
  },
  reference: {
    content_type: "image/png",
    size_bytes: 12_345,
    content_digest: `sha256:${"c".repeat(64)}`,
  },
  unavailable: null,
  preview: {
    status: "available",
    content_type: "image/png",
    size_bytes: 12_345,
    content_digest: `sha256:${"c".repeat(64)}`,
  },
};
const evidence = {
  contract_version: "tacua.candidate-evidence-view@1.0.0",
  candidate_id: candidate.candidate_id,
  candidate_version: candidate.candidate_version,
  candidate_digest: candidate.candidate_digest,
  evidence_manifest_digest: candidate.evidence_manifest.manifest_digest,
  items: [screenshot],
  diagnostic_events: [
    {
      event_id: "event_route_001",
      sequence: 1,
      elapsed_ms: 1_250,
      occurred_at: "2026-07-21T10:00:01Z",
      source: "mobile_sdk",
      evidence_refs: ["evidence_route_001"],
      event_type: "route_transition",
      data: { from_route: "Settings", to_route: "Edit profile", trigger: "user" },
    },
  ],
};

const preview = {
  uri: "blob:tacua-render-test",
  contentType: "image/png",
  sizeBytes: 12_345,
  contentDigest: screenshot.preview.content_digest,
  release() {},
};
let inspectionReady = false;
const client = {
  async getCandidate(candidateId) {
    assert.equal(candidateId, candidate.candidate_id);
    return candidate;
  },
  async getCandidateEvidence(requestedCandidate) {
    assert.equal(requestedCandidate.candidate_digest, candidate.candidate_digest);
    return evidence;
  },
};
const config = { reviewerId: "reviewer_owner" };
const alerts = [];

const reactNative = {
  ActivityIndicator: "ActivityIndicator",
  Alert: { alert: (...arguments_) => alerts.push(arguments_) },
  DynamicColorIOS: ({ light }) => light,
  Image: "Image",
  Platform: { OS: "ios" },
  Pressable: "Pressable",
  RefreshControl: "RefreshControl",
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
    return {
      DarkTheme: { colors: {} },
      DefaultTheme: { colors: {} },
    };
  }
  if (request === "expo-router") {
    return { useLocalSearchParams: () => ({ "candidate-id": candidate.candidate_id }) };
  }
  if (request === "expo-crypto") return { randomUUID: () => "00000000-0000-4000-8000-000000000000" };
  if (request === "expo-file-system") return {};
  if (request === "expo-sharing") {
    return { isAvailableAsync: async () => true, shareAsync: async () => undefined };
  }
  if (request === "@/api/client") {
    return { TacuaApiError: class TacuaApiError extends Error {} };
  }
  if (request === "@/approved-handoff/share-cache") {
    return {
      cleanupApprovedHandoffShareCache() {},
      createApprovedHandoffShareFile() { throw new Error("not exercised"); },
    };
  }
  if (request === "@/hooks/use-backend") {
    return { useBackend: () => ({ client, config }) };
  }
  if (request === "@/hooks/use-candidate-keyframe-previews") {
    return {
      useCandidateKeyframePreviews: () => ({
        activeIndex: 0,
        activePreviewState: { status: "ready", preview, decoded: true },
        inspectionReady,
        inspectedCount: inspectionReady ? 1 : 0,
        keyframes: [screenshot],
        moveNext() {},
        movePrevious() {},
        previewStates: {
          [screenshot.evidence_id]: { status: "ready", preview, decoded: true },
        },
        retryActivePreview() {},
        setKeyframeDecoded() {},
      }),
    };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const CandidateRoute = require(path.join(
  reviewerSourceRoot,
  "app/candidates/[candidate-id].tsx",
)).default;

function nodeText(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (!node) return "";
  if (Array.isArray(node)) return node.map(nodeText).join("");
  return nodeText(node.props?.children);
}

async function settle() {
  for (let index = 0; index < 4; index += 1) {
    await TestRenderer.act(async () => {
      await new Promise((resolve) => setImmediate(resolve));
    });
  }
}

test("renders ticket, verified screenshot, SDK timeline, and a fail-closed approval together", async () => {
  inspectionReady = false;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(CandidateRoute));
  });
  try {
    await settle();
    const texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.match(texts, /Profile action uses the wrong label/u);
    assert.match(texts, /Save draft instead of the approved Save profile copy/u);
    assert.match(texts, /Referenced screenshot gallery/u);
    assert.match(texts, /The enabled profile action reads Save draft/u);
    assert.match(texts, /digest verified/u);
    assert.match(texts, /SDK timeline/u);
    assert.match(texts, /Settings → Edit profile/u);
    assert.match(texts, /Observed/u);
    assert.match(texts, /Expected/u);
    assert.match(texts, /Exact version to approve/u);
    assert.match(texts, /Approval unlocks after every content-referenced available screenshot/u);

    const images = renderer.root.findAllByType("Image");
    assert.equal(images.length, 1);
    assert.equal(images[0].props.source.uri, preview.uri);
    assert.match(images[0].props.accessibilityLabel, /Screenshot 1 of 1/u);

    const approval = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Approve exact version",
    );
    assert.ok(approval);
    assert.equal(approval.props.disabled, true);
    assert.equal(alerts.length, 0);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("unlocks the exact-version action only after the screenshot inspection gate", async () => {
  inspectionReady = true;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(CandidateRoute));
  });
  try {
    await settle();
    const approval = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Approve exact version",
    );
    assert.ok(approval);
    assert.equal(approval.props.disabled, false);
    const texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.doesNotMatch(texts, /Approval unlocks after/u);
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
