// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { launchQRCodeDataUri } from "../utils/launch-qr-data-uri.ts";

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
});

test("fails closed when the launch payload cannot fit one QR code", () => {
  assert.equal(launchQRCodeDataUri("x".repeat(10_000)), null);
});
