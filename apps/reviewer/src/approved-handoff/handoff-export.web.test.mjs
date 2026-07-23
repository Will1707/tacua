// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { createApprovedHandoffDownload } from "./handoff-export.web.ts";

test("web handoff download copies bounded bytes and sanitizes its filename", async () => {
  const source = new Uint8Array([1, 2, 3, 4]);
  const download = createApprovedHandoffDownload({
    title: "Ignored for the filename",
    candidateId: "../candidate unsafe",
    candidateVersion: 7,
    extension: "json",
    bytes: source,
    mimeType: "application/json",
    uti: "public.json",
  });
  source[0] = 9;

  assert.equal(download.filename, "tacua-handoff-___candidate_unsafe-v7.json");
  assert.equal(download.blob.type, "application/json");
  assert.deepEqual(new Uint8Array(await download.blob.arrayBuffer()), new Uint8Array([1, 2, 3, 4]));
});

test("web handoff download rejects empty and invalid-version exports", () => {
  const valid = {
    title: "Ticket",
    candidateId: "candidate_one",
    candidateVersion: 1,
    extension: "md",
    bytes: new Uint8Array([1]),
    mimeType: "text/markdown",
    uti: "net.daringfireball.markdown",
  };
  assert.throws(
    () => createApprovedHandoffDownload({ ...valid, bytes: new Uint8Array() }),
    /outside the safe download size/u,
  );
  assert.throws(
    () => createApprovedHandoffDownload({ ...valid, candidateVersion: 0 }),
    /version is invalid/u,
  );
});
