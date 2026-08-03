// SPDX-License-Identifier: Apache-2.0

import { encode } from "uqr";

import { palette } from "../theme/palette.ts";

const maximumModulesPerSide = 177 + 8;

/**
 * Build a self-contained QR image without retaining the bearer as SVG text.
 * The dependency supplies only the boolean module matrix; Tacua owns the
 * bounded SVG serialization below.
 */
export function launchQRCodeDataUri(launchUrl: string): string | null {
  try {
    const matrix = encode(launchUrl, {
      boostEcc: true,
      border: 4,
      ecc: "Q",
    });
    if (
      matrix.size < 21 + 8
      || matrix.size > maximumModulesPerSide
      || matrix.data.length !== matrix.size
      || matrix.data.some((row) => row.length !== matrix.size)
    ) return null;

    const commands: string[] = [];
    for (let y = 0; y < matrix.size; y += 1) {
      const row = matrix.data[y];
      if (!row) return null;
      let runStart = -1;
      for (let x = 0; x <= matrix.size; x += 1) {
        if (x < matrix.size && row[x] === true) {
          if (runStart < 0) runStart = x;
        } else if (runStart >= 0) {
          const runLength = x - runStart;
          commands.push(`M${runStart},${y}h${runLength}v1h-${runLength}z`);
          runStart = -1;
        }
      }
    }
    if (!commands.length) return null;
    const svg = [
      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${matrix.size} ${matrix.size}" shape-rendering="crispEdges">`,
      `<rect fill="#FFFFFF" width="${matrix.size}" height="${matrix.size}"/>`,
      `<path fill="${palette.light.ink}" d="${commands.join("")}"/>`,
      "</svg>",
    ].join("");
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  } catch {
    return null;
  }
}
