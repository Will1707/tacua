// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import jsQR from "jsqr";

import { launchQRCodeDataUri } from "../utils/launch-qr-data-uri.ts";

function rasterizeSerializedModules(svg, scale = 6) {
  const viewBox = svg.match(/viewBox="0 0 ([0-9]+) ([0-9]+)"/u);
  assert.ok(viewBox);
  assert.equal(viewBox[1], viewBox[2]);
  const modules = Number(viewBox[1]);
  const path = svg.match(/<path fill="#[A-Fa-f0-9]{6}" d="([^"]+)"\/>/u);
  assert.ok(path);
  const size = modules * scale;
  const pixels = new Uint8ClampedArray(size * size * 4);
  pixels.fill(255);
  const command = /M([0-9]+),([0-9]+)h([0-9]+)v1h-([0-9]+)z/gu;
  let match;
  let consumed = "";
  while ((match = command.exec(path[1])) !== null) {
    consumed += match[0];
    const startX = Number(match[1]);
    const y = Number(match[2]);
    const run = Number(match[3]);
    assert.equal(run, Number(match[4]));
    for (let moduleX = startX; moduleX < startX + run; moduleX += 1) {
      for (let pixelY = y * scale; pixelY < (y + 1) * scale; pixelY += 1) {
        for (let pixelX = moduleX * scale; pixelX < (moduleX + 1) * scale; pixelX += 1) {
          const offset = (pixelY * size + pixelX) * 4;
          pixels[offset] = 17;
          pixels[offset + 1] = 23;
          pixels[offset + 2] = 19;
        }
      }
    }
  }
  assert.equal(consumed, path[1]);
  return { pixels, size };
}

test("serializes only QR pixels and never plaintext launch authority", () => {
  const launchCode = "Private_launch_code_1234567890ABCDEFGHijklmn";
  const launchUrl = `tacua-qa-app://tacua/start?launch_code=${launchCode}`;
  const dataUri = launchQRCodeDataUri(launchUrl);
  assert.ok(dataUri?.startsWith("data:image/svg+xml;charset=utf-8,"));
  assert.equal(dataUri.includes(launchCode), false);
  assert.equal(dataUri.includes(encodeURIComponent(launchCode)), false);

  const svg = decodeURIComponent(dataUri.slice(dataUri.indexOf(",") + 1));
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 [0-9]+ [0-9]+" shape-rendering="crispEdges">/u);
  assert.match(svg, /<rect fill="#FFFFFF" width="[0-9]+" height="[0-9]+"\/>/u);
  assert.match(svg, /<path fill="#111713" d="(?:M[0-9]+,[0-9]+h[0-9]+v1h-[0-9]+z)+"\/><\/svg>$/u);
  assert.equal(svg.includes(launchUrl), false);
  assert.equal(svg.includes("<script"), false);

  const { pixels, size } = rasterizeSerializedModules(svg);
  const decoded = jsQR(pixels, size, size, { inversionAttempts: "dontInvert" });
  assert.equal(decoded?.data, launchUrl);
});

test("fails closed when the launch payload cannot fit one QR code", () => {
  assert.equal(launchQRCodeDataUri("x".repeat(10_000)), null);
});
