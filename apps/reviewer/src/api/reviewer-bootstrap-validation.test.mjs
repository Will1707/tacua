// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  maximumReviewerBootstrapResponseBytes,
  ReviewerBootstrapValidationError,
  validateReviewerBootstrap,
} from "./reviewer-bootstrap-validation.ts";

function registeredBuild(overrides = {}) {
  return {
    build_id: "build_kuzaba_qa",
    application_id: "application_kuzaba_qa",
    bundle_identifier: "com.kuzaba.app",
    native_version: "0.1.0",
    native_build: "4",
    distribution: "internal",
    build_identity_digest: `sha256:${"a".repeat(64)}`,
    launch_scheme: "tacua-kuzaba-qa",
    ...overrides,
  };
}

function bootstrap(overrides = {}) {
  return {
    contract_version: "tacua.reviewer-bootstrap@1.0.0",
    reviewer_id: "reviewer_owner_qa",
    builds: [registeredBuild()],
    ...overrides,
  };
}

function rejects(value) {
  assert.throws(
    () => validateReviewerBootstrap(value),
    (error) => error instanceof ReviewerBootstrapValidationError
      && error.code === "INVALID_REVIEWER_BOOTSTRAP",
  );
}

test("accepts exact current and transport 1.1 build projections", () => {
  assert.deepEqual(validateReviewerBootstrap(bootstrap()), bootstrap());
  const legacyTransport = bootstrap({ builds: [registeredBuild({ launch_scheme: null })] });
  assert.deepEqual(validateReviewerBootstrap(legacyTransport), legacyTransport);
  assert.ok(maximumReviewerBootstrapResponseBytes <= 128 * 1_024);
});

test("rejects contract drift and non-exact envelope or build shapes", () => {
  rejects(bootstrap({ contract_version: "tacua.reviewer-bootstrap@2.0.0" }));
  rejects({ ...bootstrap(), debug: true });
  const { reviewer_id: _reviewerId, ...missingReviewer } = bootstrap();
  rejects(missingReviewer);
  rejects(bootstrap({ builds: [{ ...registeredBuild(), debug: true }] }));
  const { launch_scheme: _launchScheme, ...missingScheme } = registeredBuild();
  rejects(bootstrap({ builds: [missingScheme] }));
});

test("rejects invalid legacy identities and unsafe launch schemes", () => {
  for (const reviewer_id of ["Reviewer_owner", "ab", "reviewer.owner", "reviewer_e\u0301"]) {
    rejects(bootstrap({ reviewer_id }));
  }
  for (const launch_scheme of ["https", "tacua", "TACUA-KUZABA-QA", "x", `${"x".repeat(65)}`]) {
    rejects(bootstrap({ builds: [registeredBuild({ launch_scheme })] }));
  }
});

test("enforces build field grammars, the registry bound, and unique bindings", () => {
  for (const invalid of [
    { build_id: "Build_kuzaba_qa" },
    { application_id: "application.kuzaba.qa" },
    { bundle_identifier: "kuzaba" },
    { native_version: "" },
    { native_build: "4 beta" },
    { distribution: "appstore" },
    { build_identity_digest: `sha256:${"A".repeat(64)}` },
  ]) {
    rejects(bootstrap({ builds: [registeredBuild(invalid)] }));
  }

  const builds = Array.from({ length: 101 }, (_, index) => registeredBuild({
    build_id: `build_${index}`,
    build_identity_digest: `sha256:${index.toString(16).padStart(64, "0")}`,
  }));
  rejects(bootstrap({ builds }));
  rejects(bootstrap({ builds: [registeredBuild(), registeredBuild()] }));
  rejects(bootstrap({ builds: [
    registeredBuild(),
    registeredBuild({ build_id: "build_other" }),
  ] }));
});
