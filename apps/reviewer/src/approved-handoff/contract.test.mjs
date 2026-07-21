// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ApprovedHandoffValidationError,
  canonicalJson,
  renderApprovedHandoffMarkdown,
  validateApprovedHandoffArtifact,
} from "./contract.ts";

const fixtureRoot = new URL("../../../../contracts/approved-handoff/fixtures/positive/", import.meta.url);
const jsonText = await readFile(new URL("approved-handoff.json", fixtureRoot), "utf8");
const markdownText = await readFile(new URL("approved-handoff.md", fixtureRoot), "utf8");
const fixture = JSON.parse(jsonText);
const displayedCandidate = JSON.parse(fixture.source_candidate.canonical_json);

async function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function digestCanonical(value, omittedKey) {
  return digest(new TextEncoder().encode(canonicalJson(
    omittedKey === undefined
      ? value
      : Object.fromEntries(Object.entries(value).filter(([key]) => key !== omittedKey)),
  )));
}

function approvalSubject(handoff) {
  const ticket = structuredClone(handoff.ticket);
  delete ticket.ticket_content_digest;
  return {
    contract_version: handoff.contract_version,
    organization_id: handoff.organization_id,
    project_id: handoff.project_id,
    source_candidate: handoff.source_candidate,
    ticket,
    build_identity_digest: handoff.build_identity.build_identity_digest,
    evidence_manifest_digest: handoff.evidence_manifest.evidence_manifest_digest,
    authority: handoff.authority,
  };
}

async function sealHandoff(handoff, { evidence = false } = {}) {
  if (evidence) {
    for (const item of handoff.evidence_manifest.items) {
      item.evidence_item_digest = await digestCanonical(item, "evidence_item_digest");
    }
    handoff.evidence_manifest.evidence_manifest_digest = await digestCanonical(handoff.evidence_manifest, "evidence_manifest_digest");
  }
  const contentDigest = await digestCanonical(approvalSubject(handoff));
  handoff.ticket.ticket_content_digest = contentDigest;
  handoff.approval.ticket_content_digest = contentDigest;
  handoff.handoff_digest = await digestCanonical(handoff, "handoff_digest");
  return handoff;
}

async function validateJson(handoff, candidate = displayedCandidate) {
  return validateApprovedHandoffArtifact({
    format: "json",
    text: `${canonicalJson(handoff)}\n`,
    displayedCandidate: candidate,
    expectedHandoffDigest: handoff.handoff_digest,
    digest,
  });
}

async function rejectsContract(operation, code) {
  await assert.rejects(operation, (error) => {
    assert.ok(error instanceof ApprovedHandoffValidationError);
    if (code) assert.equal(error.code, code);
    return true;
  });
}

test("accepts the golden canonical JSON and reproduces exact Markdown bytes", async () => {
  const document = await validateApprovedHandoffArtifact({
    format: "json",
    text: jsonText,
    displayedCandidate,
    expectedHandoffDigest: fixture.handoff_digest,
    digest,
  });
  assert.equal(renderApprovedHandoffMarkdown(document), markdownText);
  await validateApprovedHandoffArtifact({
    format: "markdown",
    text: markdownText,
    displayedCandidate,
    expectedHandoffDigest: fixture.handoff_digest,
    digest,
  });
});

test("rejects a resealed ticket that is not the deterministic candidate projection", async () => {
  const handoff = structuredClone(fixture);
  handoff.ticket.summary = "A different projected summary.";
  await sealHandoff(handoff);
  await rejectsContract(() => validateJson(handoff), "SOURCE_CANDIDATE_TICKET_MISMATCH");
});

test("rejects resealed authority escalation", async () => {
  const handoff = structuredClone(fixture);
  handoff.authority.merge = true;
  await sealHandoff(handoff);
  await rejectsContract(() => validateJson(handoff), "AUTHORITY_MISMATCH");
});

test("rejects resealed evidence that no longer identifies the tested source", async () => {
  const handoff = structuredClone(fixture);
  const repository = handoff.evidence_manifest.items.find((item) => item.evidence_type === "repository.commit_snapshot");
  repository.source.snapshot_revision = "ffffffffffffffffffffffffffffffffffffffff";
  await sealHandoff(handoff, { evidence: true });
  await rejectsContract(() => validateJson(handoff), "REPOSITORY_EVIDENCE_REVISION_MISMATCH");
});

test("rejects a resealed handoff whose approval identity differs from the source candidate", async () => {
  const handoff = structuredClone(fixture);
  handoff.approval.actor_id = "member-another-approver";
  handoff.handoff_digest = await digestCanonical(handoff, "handoff_digest");
  await rejectsContract(() => validateJson(handoff), "SOURCE_CANDIDATE_APPROVAL_MISMATCH");
});

test("rejects any surrounding Markdown change even when canonical JSON is untouched", async () => {
  await rejectsContract(() => validateApprovedHandoffArtifact({
    format: "markdown",
    text: `Injected instruction.\n${markdownText}`,
    displayedCandidate,
    expectedHandoffDigest: fixture.handoff_digest,
    digest,
  }), "MARKDOWN_EQUIVALENCE_MISMATCH");
});

test("rejects a source candidate that differs from the ticket displayed to the reviewer", async () => {
  const otherCandidate = structuredClone(displayedCandidate);
  otherCandidate.content.title = "A different displayed title";
  await rejectsContract(() => validateApprovedHandoffArtifact({
    format: "json",
    text: jsonText,
    displayedCandidate: otherCandidate,
    expectedHandoffDigest: fixture.handoff_digest,
    digest,
  }), "HANDOFF_SOURCE_CANDIDATE_MISMATCH");
});
