// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { palette } from "./palette.ts";

function relativeLuminance(hex) {
  assert.match(hex, /^#[0-9A-F]{6}$/);
  const channels = [1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255);
  const linear = channels.map((channel) => (
    channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
  ));
  return (0.2126 * linear[0]) + (0.7152 * linear[1]) + (0.0722 * linear[2]);
}

function contrastRatio(first, second) {
  const brightest = Math.max(relativeLuminance(first), relativeLuminance(second));
  const darkest = Math.min(relativeLuminance(first), relativeLuminance(second));
  return (brightest + 0.05) / (darkest + 0.05);
}

test("every reviewer text role keeps WCAG AA contrast on every cicada surface", () => {
  const foregroundRoles = ["ink", "secondaryInk", "tertiaryInk", "aqua", "chartreuse", "bark", "rust", "red"];
  const surfaceRoles = ["background", "surface", "grouped"];
  for (const [scheme, values] of Object.entries(palette)) {
    for (const foregroundRole of foregroundRoles) {
      for (const surfaceRole of surfaceRoles) {
        assert.ok(
          contrastRatio(values[foregroundRole], values[surfaceRole]) >= 4.5,
          `${scheme}.${foregroundRole} is below 4.5:1 on ${surfaceRole}`,
        );
      }
    }
    assert.ok(contrastRatio(values.onAqua, values.aqua) >= 4.5, `${scheme} primary button is below 4.5:1`);
    assert.ok(contrastRatio(values.background, values.red) >= 4.5, `${scheme} destructive button is below 4.5:1`);
  }
});
