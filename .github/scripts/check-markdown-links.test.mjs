// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  checkMarkdownFile,
  extractMarkdownDestinations,
} from "./check-markdown-links.mjs";

test("extracts inline, image, and reference destinations but ignores code", () => {
  const markdown = [
    "[guide](docs/guide.md)",
    "![image](<assets/image one.png>)",
    "[reference]: docs/reference.md",
    "`[not a link](missing.md)`",
    "```md",
    "[also not a link](missing.md)",
    "```",
  ].join("\n");
  assert.deepEqual(extractMarkdownDestinations(markdown), [
    "docs/guide.md",
    "assets/image one.png",
    "docs/reference.md",
  ]);
});

test("checks files, directories, encoded paths, root paths, and fragments", () => {
  const root = mkdtempSync(path.join(tmpdir(), "tacua-markdown-links-"));
  try {
    mkdirSync(path.join(root, "docs"));
    mkdirSync(path.join(root, "assets"));
    writeFileSync(path.join(root, "README.md"), [
      "[guide](docs/guide.md#repeated-heading-1)",
      "[asset](assets/image%20one.png)",
      "[directory](docs)",
      "[root](/docs/guide.md#explicit)",
      "[external](https://example.test/missing)",
    ].join("\n"));
    writeFileSync(path.join(root, "docs/guide.md"), [
      "# Repeated heading",
      "## Repeated heading",
      '<a id="explicit"></a>',
    ].join("\n"));
    writeFileSync(path.join(root, "assets/image one.png"), "synthetic");
    assert.deepEqual(checkMarkdownFile(root, "README.md"), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reports missing, escaping, external-symlink, malformed, and fragment links", () => {
  const root = mkdtempSync(path.join(tmpdir(), "tacua-markdown-links-"));
  const outside = mkdtempSync(path.join(tmpdir(), "tacua-markdown-outside-"));
  try {
    writeFileSync(path.join(outside, "outside.md"), "# Outside\n");
    symlinkSync(path.join(outside, "outside.md"), path.join(root, "outside.md"));
    writeFileSync(path.join(root, "README.md"), [
      "[missing](missing.md)",
      "[escape](../outside.md)",
      "[symlink](outside.md)",
      "[malformed](bad%ZZ.md)",
      "[fragment](README.md#missing-heading)",
    ].join("\n"));
    const failures = checkMarkdownFile(root, "README.md");
    assert.equal(failures.length, 5);
    assert.match(failures.join("\n"), /missing local link target/u);
    assert.match(failures.join("\n"), /escapes repository/u);
    assert.match(failures.join("\n"), /resolves outside repository/u);
    assert.match(failures.join("\n"), /malformed percent-encoding/u);
    assert.match(failures.join("\n"), /missing local heading fragment/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
