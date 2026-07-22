// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { collectContentEvidenceRefs } from "./content-evidence-refs.ts";

test("recursively collects every content citation and presentation reference", () => {
  const content = {
    summary: { evidence_refs: ["ev_summary", "ev_shared"] },
    actual_behavior: { evidence_refs: ["ev_actual"] },
    expected_behavior: { evidence_refs: ["ev_expected"] },
    claims: [{ evidence_refs: ["ev_claim"] }],
    reproduction: {
      preconditions: [{ evidence_refs: ["ev_precondition"] }],
      steps: [{ evidence_refs: ["ev_step"] }],
    },
    acceptance_criteria: [{ evidence_refs: ["ev_acceptance"] }],
    uncertainty: { items: [{ evidence_refs: ["ev_uncertainty"] }] },
    clarifications: [{
      choices: [{
        evidence_refs: ["ev_choice", "ev_shared"],
        presentation: { evidence_ref: "ev_thumbnail" },
      }],
    }],
  };

  assert.deepEqual(collectContentEvidenceRefs(content), [
    "ev_summary",
    "ev_shared",
    "ev_actual",
    "ev_expected",
    "ev_claim",
    "ev_precondition",
    "ev_step",
    "ev_acceptance",
    "ev_uncertainty",
    "ev_choice",
    "ev_thumbnail",
  ]);
});

test("ignores lookalike scalar fields and terminates safely for repeated objects", () => {
  const repeated = { evidence_refs: ["ev_once"] };
  const content = {
    evidence_refs: ["ev_root", 42, null],
    first: repeated,
    second: repeated,
    presentation: { evidence_ref: null },
    unrelated: { evidence_ref: "ev_not_a_presentation" },
  };

  assert.deepEqual(collectContentEvidenceRefs(content), ["ev_root", "ev_once"]);
});
