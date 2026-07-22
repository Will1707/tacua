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
const first = JSON.parse(fs.readFileSync(
  path.join(repositoryRoot, "contracts/ticket-candidate/fixtures/positive/version-1-draft.json"),
  "utf8",
));
const second = structuredClone(first);
second.candidate_id = "candidate_secondary_issue";
second.candidate_digest = `sha256:${"b".repeat(64)}`;
second.candidate_content_digest = `sha256:${"c".repeat(64)}`;
second.content.title = "Profile helper text uses stale copy";
second.content.summary.text = "The profile helper text does not match the approved wording.";
const sources = [first, second];
const summaries = sources.map((candidate) => ({
  candidate_id: candidate.candidate_id,
  candidate_version: candidate.candidate_version,
  candidate_digest: candidate.candidate_digest,
  state: candidate.state,
  priority: candidate.content.priority,
  title: candidate.content.title,
  summary: candidate.content.summary.text,
  version_created_at: candidate.version_created_at,
}));
const alerts = [];
let replacementCalls = 0;
const client = {
  async getCandidate(candidateId) {
    return sources.find((candidate) => candidate.candidate_id === candidateId);
  },
  async getCandidateSupersession() {
    return null;
  },
  async replaceCandidates() {
    replacementCalls += 1;
    throw new Error("not exercised past confirmation");
  },
};

const reactNative = {
  ActivityIndicator: "ActivityIndicator",
  Alert: { alert: (...arguments_) => alerts.push(arguments_) },
  DynamicColorIOS: ({ light }) => light,
  Platform: { OS: "ios" },
  Pressable: "Pressable",
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
  if (request === "expo-crypto") return { randomUUID: () => "00000000000000000000000000000001" };
  if (request === "@/api/client") {
    class TacuaApiError extends Error {}
    class CandidateSupersededApiError extends TacuaApiError {}
    return { CandidateSupersededApiError, TacuaApiError };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const CandidateMergeCard = require(path.join(
  reviewerSourceRoot,
  "components/candidate-merge-card.tsx",
)).CandidateMergeCard;

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

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function prepareAndSubmit(renderer) {
  for (const source of sources) {
    const selector = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === `Select ${source.content.title} for merge`,
    );
    await TestRenderer.act(async () => selector.props.onPress());
  }
  const prepare = renderer.root.findAllByType("Pressable").find(
    (node) => node.props.accessibilityLabel === "Prepare combined draft",
  );
  await TestRenderer.act(async () => prepare.props.onPress());
  await settle();
  const review = renderer.root.findAllByType("Pressable").find(
    (node) => node.props.accessibilityLabel === "Review and create combined draft",
  );
  await TestRenderer.act(async () => review.props.onPress());
  const confirmation = alerts.at(-1);
  await TestRenderer.act(async () => {
    confirmation[2][1].onPress();
    await new Promise((resolve) => setImmediate(resolve));
  });
}

test("merge selection produces an editable suggestion and never submits before source-disposition confirmation", async () => {
  alerts.length = 0;
  replacementCalls = 0;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(CandidateMergeCard, {
      candidates: summaries,
      client,
      disabled: false,
      reviewerId: "reviewer_owner",
      onCompleted: async () => undefined,
    }));
  });
  try {
    await settle();
    for (const source of sources) {
      const selector = renderer.root.findAllByType("Pressable").find(
        (node) => node.props.accessibilityLabel === `Select ${source.content.title} for merge`,
      );
      assert.ok(selector);
      await TestRenderer.act(async () => selector.props.onPress());
    }
    const prepare = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Prepare combined draft",
    );
    assert.ok(prepare);
    assert.equal(prepare.props.disabled, false);
    await TestRenderer.act(async () => prepare.props.onPress());
    await settle();
    assert.equal(replacementCalls, 0);
    const texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.match(texts, /editable suggestion combines 2 exact source tickets/u);
    assert.match(texts, /Result draft 1/u);
    assert.equal((texts.match(/Complete result content/gu) ?? []).length, 1);
    assert.match(texts, /Claims and grounding/u);
    assert.match(texts, /The tested build renders Save draft on the profile action/u);
    assert.match(texts, /Reproduction details/u);
    assert.match(texts, /The enabled profile action reads Save profile in the tested locale/u);
    assert.match(texts, /Correct the profile action copy in the tested iOS build/u);
    assert.match(texts, /Copy for locales outside the tested English build was not inspected/u);
    assert.match(texts, /Which label should the enabled profile action use/u);
    const summary = renderer.root.findAllByType("TextInput").find(
      (node) => node.props.accessibilityLabel === "Result draft 1 summary",
    );
    assert.match(summary.props.value, /\[Ticket 1\]/u);
    assert.match(summary.props.value, /\[Ticket 2\]/u);

    const review = renderer.root.findAllByType("Pressable").find(
      (node) => node.props.accessibilityLabel === "Review and create combined draft",
    );
    assert.ok(review);
    await TestRenderer.act(async () => review.props.onPress());
    assert.equal(replacementCalls, 0);
    assert.equal(alerts.length, 1);
    assert.match(alerts[0][0], /Replace 2 active tickets with 1 draft/u);
    assert.match(alerts[0][1], /These sources will leave the active queue/u);
    assert.match(alerts[0][1], /Profile action uses the wrong label/u);
    assert.match(alerts[0][1], /Profile helper text uses stale copy/u);
    assert.equal(alerts[0][2][0].text, "Cancel");
    assert.equal(alerts[0][2][1].text, "Create combined draft");
  } finally {
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("merge completion never updates or refreshes a changed context", async () => {
  for (const outcome of ["success", "error"]) {
    alerts.length = 0;
    const pending = deferred();
    let oldCompletions = 0;
    let newCompletions = 0;
    const oldClient = {
      ...client,
      replaceCandidates: () => pending.promise,
    };
    const newClient = {
      ...client,
      async replaceCandidates() { throw new Error("new client must not submit"); },
    };
    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(React.createElement(CandidateMergeCard, {
        candidates: summaries,
        client: oldClient,
        disabled: false,
        reviewerId: "reviewer_owner",
        onCompleted: async () => { oldCompletions += 1; },
      }));
    });
    await prepareAndSubmit(renderer);
    assert.equal(alerts.length, 1);

    await TestRenderer.act(async () => {
      renderer.update(React.createElement(CandidateMergeCard, {
        candidates: summaries,
        client: newClient,
        disabled: false,
        reviewerId: "reviewer_owner",
        onCompleted: async () => { newCompletions += 1; },
      }));
    });
    if (outcome === "success") {
      pending.resolve({ operation: { sources: [{}, {}] } });
    } else {
      pending.reject(new Error("old context failed"));
    }
    await settle();
    const texts = renderer.root.findAllByType("Text").map(nodeText).join("\n");
    assert.equal(alerts.length, 1);
    assert.equal(oldCompletions, 0);
    assert.equal(newCompletions, 0);
    assert.doesNotMatch(texts, /old context failed/u);
    await TestRenderer.act(async () => renderer.unmount());
  }
});

test("merge completion is inert after unmount", async () => {
  alerts.length = 0;
  const pending = deferred();
  let completions = 0;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(React.createElement(CandidateMergeCard, {
      candidates: summaries,
      client: { ...client, replaceCandidates: () => pending.promise },
      disabled: false,
      reviewerId: "reviewer_owner",
      onCompleted: async () => { completions += 1; },
    }));
  });
  await prepareAndSubmit(renderer);
  assert.equal(alerts.length, 1);
  await TestRenderer.act(async () => renderer.unmount());
  pending.resolve({ operation: { sources: [{}, {}] } });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(alerts.length, 1);
  assert.equal(completions, 0);
});

test.after(() => {
  Module._load = originalLoad;
  Module._resolveFilename = originalResolveFilename;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
  if (originalTSXLoader) Module._extensions[".tsx"] = originalTSXLoader;
  else delete Module._extensions[".tsx"];
});
