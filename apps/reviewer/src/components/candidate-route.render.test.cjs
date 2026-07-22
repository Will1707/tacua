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
let supersession = null;
let replacementCalls = 0;
let evidenceFailure = false;
let evidenceCalls = 0;
const client = {
  async getCandidate(candidateId) {
    assert.equal(candidateId, candidate.candidate_id);
    return candidate;
  },
  async getCandidateEvidence(requestedCandidate) {
    assert.equal(requestedCandidate.candidate_digest, candidate.candidate_digest);
    evidenceCalls += 1;
    if (evidenceFailure) throw new Error("temporary historical evidence failure");
    return evidence;
  },
  async getCandidateSupersession(requestedCandidate) {
    assert.equal(requestedCandidate.candidate_digest, candidate.candidate_digest);
    return supersession;
  },
  async replaceCandidates() {
    replacementCalls += 1;
    throw new Error("not exercised past confirmation");
  },
};
const config = { reviewerId: "reviewer_owner" };
const alerts = [];
let randomSequence = 0;

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
    return { Link: "Link", useLocalSearchParams: () => ({ "candidate-id": candidate.candidate_id }) };
  }
  if (request === "expo-crypto") {
    return { randomUUID: () => `${String(++randomSequence).padStart(32, "0")}` };
  }
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
  supersession = null;
  replacementCalls = 0;
  evidenceFailure = false;
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
    assert.match(texts, /Split ticket/u);
    assert.match(texts, /Prepare split drafts/u);

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
  supersession = null;
  replacementCalls = 0;
  evidenceFailure = false;
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

test("split suggestions remain local until one explicit source-disposition confirmation", async () => {
  inspectionReady = true;
  supersession = null;
  replacementCalls = 0;
  evidenceFailure = false;
  alerts.length = 0;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(CandidateRoute));
  });
  try {
    await settle();
    const prepare = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Prepare split drafts",
    );
    assert.ok(prepare);
    await TestRenderer.act(async () => prepare.props.onPress());
    assert.equal(replacementCalls, 0);
    let texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.match(texts, /Result draft 1/u);
    assert.match(texts, /Result draft 2/u);
    assert.match(texts, /editable suggestions/u);
    assert.equal((texts.match(/Complete result content/gu) ?? []).length, 1);
    assert.match(texts, /1 of 2 complete results opened for review/u);
    assert.match(texts, /Claims and grounding/u);
    assert.match(texts, /The tested build renders Save draft on the profile action/u);
    assert.match(texts, /Reproduction details/u);
    assert.match(texts, /The enabled profile action reads Save profile in the tested locale/u);
    assert.match(texts, /Correct the profile action copy in the tested iOS build/u);
    assert.match(texts, /Copy for locales outside the tested English build was not inspected/u);
    assert.match(texts, /Which label should the enabled profile action use/u);

    let review = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Review and create 2 drafts",
    );
    assert.ok(review);
    assert.equal(review.props.disabled, true);
    const openSecond = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Open complete result draft 2",
    );
    assert.ok(openSecond);
    assert.equal(openSecond.props.accessibilityState.expanded, false);
    await TestRenderer.act(async () => openSecond.props.onPress());
    texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.equal((texts.match(/Complete result content/gu) ?? []).length, 1);
    assert.match(texts, /2 of 2 complete results opened for review/u);
    assert.match(texts, /Part 2/u);
    assert.equal(renderer.root.findAllByType("TextInput").filter(
      (node) => /^Result draft [12] title$/u.test(node.props.accessibilityLabel ?? ""),
    ).length, 1);
    review = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Review and create 2 drafts",
    );
    assert.equal(review.props.disabled, false);
    await TestRenderer.act(async () => review.props.onPress());
    assert.equal(replacementCalls, 0);
    assert.equal(alerts.length, 1);
    assert.match(alerts[0][0], /Replace 1 active ticket with 2 drafts/u);
    assert.match(alerts[0][1], /will leave the active queue/u);
    assert.equal(alerts[0][2][0].text, "Cancel");
    assert.equal(alerts[0][2][1].text, "Create 2 drafts");
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("renders exact ordered merge history and keeps superseded evidence retryable", async () => {
  inspectionReady = true;
  replacementCalls = 0;
  evidenceFailure = true;
  evidenceCalls = 0;
  const secondSourceDigest = `sha256:${"9".repeat(64)}`;
  supersession = {
    operation_id: "operation_merge_001",
    operation: "merge",
    actor_id: "reviewer_owner",
    occurred_at: "2026-07-21T10:08:00Z",
    sources: [
      {
        candidate_id: candidate.candidate_id,
        candidate_version: candidate.candidate_version,
        candidate_digest: candidate.candidate_digest,
        candidate_content_digest: candidate.candidate_content_digest,
        evidence_manifest_digest: candidate.evidence_manifest.manifest_digest,
      },
      {
        candidate_id: "candidate_other_source",
        candidate_version: 4,
        candidate_digest: secondSourceDigest,
        candidate_content_digest: `sha256:${"8".repeat(64)}`,
        evidence_manifest_digest: `sha256:${"7".repeat(64)}`,
      },
    ],
    results: [{
      candidate_id: "candidate_merged_result",
      candidate_version: 1,
      candidate_digest: `sha256:${"6".repeat(64)}`,
      candidate_content_digest: `sha256:${"5".repeat(64)}`,
      evidence_manifest_digest: `sha256:${"4".repeat(64)}`,
    }],
  };
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(CandidateRoute));
  });
  try {
    await settle();
    const texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.match(texts, /CANDIDATE_SUPERSEDED/u);
    assert.match(texts, /cannot be edited, approved, rejected, split, merged, or exported/u);
    assert.match(texts, /Exact source tickets/u);
    assert.match(texts, new RegExp(candidate.candidate_digest, "u"));
    assert.match(texts, /candidate_other_source · version 4/u);
    assert.match(texts, new RegExp(secondSourceDigest, "u"));
    assert.match(texts, /Open replacement 1/u);
    const sourceLinks = renderer.root.findAllByType("Pressable").filter(
      (node) => /^Open exact source/u.test(node.props.accessibilityLabel ?? ""),
    );
    assert.deepEqual(sourceLinks.map((node) => node.props.accessibilityLabel), [
      `Open exact source 1, ${candidate.candidate_id}, version ${candidate.candidate_version}`,
      "Open exact source 2, candidate_other_source, version 4",
    ]);
    const retryEvidence = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Retry evidence check",
    );
    assert.ok(retryEvidence);
    assert.equal(retryEvidence.props.disabled, false);
    assert.equal(evidenceCalls, 1);
    const approval = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Approve exact version",
    );
    const split = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Prepare split drafts",
    );
    assert.equal(approval, undefined);
    assert.equal(split, undefined);
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
    supersession = null;
    evidenceFailure = false;
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
