// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  checkReviewerThirdPartyNotices,
} from "./generate-reviewer-third-party-notices.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");

export const maximumReviewerFiles = 1_024;
export const maximumReviewerFileBytes = 16_777_216;
export const maximumReviewerBytes = 67_108_864;

const expectedBase =
  "python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91";
const expectedInstructions = [
  ["FROM", expectedBase],
  [
    "LABEL",
    'org.opencontainers.image.title="Tacua reviewer web" org.opencontainers.image.description="Authority-free static reviewer for a self-hosted Tacua deployment" org.opencontainers.image.licenses="Apache-2.0"',
  ],
  ["ENV", "PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1"],
  [
    "RUN",
    "groupadd --gid 10002 tacua-reviewer && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tacua-reviewer && install -d -o root -g root -m 0555 /srv/tacua-reviewer /licenses /licenses/tacua /licenses/reviewer",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0555 services/reviewer-web/server.py /usr/local/bin/tacua-reviewer-web",
  ],
  [
    "COPY",
    "--chown=root:root apps/reviewer/dist/ /srv/tacua-reviewer/",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0444 LICENSE NOTICE /licenses/tacua/",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0444 apps/reviewer/NOTICE /licenses/reviewer/NOTICE",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0444 apps/reviewer/generated/THIRD_PARTY_NOTICES.txt /licenses/reviewer/THIRD_PARTY_NOTICES.txt",
  ],
  ["USER", "10002:10002"],
  ["EXPOSE", "8081"],
  [
    "HEALTHCHECK",
    "--interval=30s --timeout=3s --start-period=5s --retries=3 CMD [\"python\", \"-c\", \"import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8081/', timeout=2); assert r.status==200 and r.headers['Cache-Control']=='no-store' and r.headers['X-Content-Type-Options']=='nosniff'\"]",
  ],
  ["ENTRYPOINT", '["python", "-B", "/usr/local/bin/tacua-reviewer-web"]'],
];
const expectedIgnoreRules = new Set([
  "**",
  "!apps/",
  "!apps/reviewer/",
  "!apps/reviewer/dist/",
  "!apps/reviewer/dist/**",
  "!apps/reviewer/NOTICE",
  "!apps/reviewer/generated/",
  "!apps/reviewer/generated/THIRD_PARTY_NOTICES.txt",
  "!LICENSE",
  "!NOTICE",
  "!services/",
  "!services/reviewer-web/",
  "!services/reviewer-web/server.py",
]);
const safePart = /^[A-Za-z0-9@._-]{1,255}$/u;
const entryBundle = /^_expo\/static\/js\/web\/entry-([a-f0-9]{32})\.js$/u;
const allowedAssetExtension = new Set([
  ".css",
  ".jpeg",
  ".jpg",
  ".png",
  ".svg",
  ".ttf",
  ".webp",
  ".woff2",
]);
const forbiddenBundleText = [
  "localStorage",
  "expo-file-system",
  "expo-secure-store",
  "expo-sharing",
  "sourceMappingURL",
];

function fail(message) {
  throw new Error(message);
}

function parseDockerInstructions(dockerfile) {
  if (/^\s*#\s*(?:check|escape|syntax)\s*=/imu.test(dockerfile)) {
    fail("reviewer Dockerfile must not select parser or frontend directives");
  }
  const instructions = [];
  let parts = [];
  for (const original of dockerfile.split(/\r?\n/u)) {
    const line = original.trim();
    if (!parts.length && (!line || line.startsWith("#"))) continue;
    if (parts.length && line.startsWith("#")) continue;
    if (!line) fail("reviewer Dockerfile contains an invalid continuation");
    const continued = line.endsWith("\\");
    parts.push(continued ? line.slice(0, -1).trimEnd() : line);
    if (continued) continue;
    const logical = parts.join(" ").trim();
    parts = [];
    const match = /^([A-Za-z]+)\s+([\s\S]+)$/u.exec(logical);
    if (!match) fail("reviewer Dockerfile contains an invalid instruction");
    instructions.push([match[1].toUpperCase(), match[2]]);
  }
  if (parts.length) fail("reviewer Dockerfile ends in an incomplete instruction");
  return instructions;
}

export function validateDockerDefinition(dockerfile, dockerignore) {
  const instructions = parseDockerInstructions(dockerfile);
  if (
    instructions.length !== expectedInstructions.length
    || instructions.some(
      ([name, body], index) =>
        name !== expectedInstructions[index][0]
        || body !== expectedInstructions[index][1],
    )
    || instructions.some(([name]) => name === "ADD")
  ) {
    fail("reviewer Dockerfile differs from the closed instruction policy");
  }
  const ignoreLines = dockerignore
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  if (
    ignoreLines.length !== expectedIgnoreRules.size
    || new Set(ignoreLines).size !== expectedIgnoreRules.size
    || ignoreLines.some((line) => !expectedIgnoreRules.has(line))
  ) {
    fail("reviewer Docker ignore boundary differs from the closed policy");
  }
}

function safeFile(relative, absolute) {
  const metadata = lstatSync(absolute);
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1
    || (metadata.mode & 0o022) !== 0
    || metadata.size < 1
    || metadata.size > maximumReviewerFileBytes
  ) {
    fail(`reviewer export contains an unsafe file: ${relative}`);
  }
  return metadata.size;
}

function collectFiles(root) {
  const rootMetadata = lstatSync(root);
  if (
    !rootMetadata.isDirectory()
    || rootMetadata.isSymbolicLink()
    || (rootMetadata.mode & 0o022) !== 0
  ) {
    fail("reviewer export root must be one real directory");
  }
  const resolvedRoot = realpathSync(root);
  const pending = [root];
  const files = new Map();
  let total = 0;
  while (pending.length) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      if (
        relative.startsWith("../")
        || relative.split("/").some((part) => !safePart.test(part))
        || realpathSync(absolute) !== path.resolve(resolvedRoot, relative)
      ) {
        fail("reviewer export path is unsafe");
      }
      if (entry.isSymbolicLink()) fail("reviewer export must not contain links");
      if (entry.isDirectory()) {
        if ((lstatSync(absolute).mode & 0o022) !== 0) {
          fail("reviewer export contains a writable directory");
        }
        pending.push(absolute);
      } else if (entry.isFile()) {
        total += safeFile(relative, absolute);
        files.set(relative, absolute);
      } else {
        fail("reviewer export contains a non-file entry");
      }
      if (files.size > maximumReviewerFiles || total > maximumReviewerBytes) {
        fail("reviewer export exceeds its closed size or file-count bound");
      }
    }
  }
  return files;
}

function validateIndex(indexBytes, bundleName) {
  const index = indexBytes.toString("utf8");
  if (
    Buffer.from(index, "utf8").compare(indexBytes) !== 0
    || !index.startsWith("<!DOCTYPE html>")
    || !index.includes('<div id="root"></div>')
    || [...index.matchAll(/<script\b[^>]*>/giu)].length !== 1
    || !index.includes(`<script src="/${bundleName}" defer></script>`)
    || /<script\b(?![^>]*\bsrc=)[^>]*>/iu.test(index)
    || /<(?:script|link|img)\b[^>]*(?:src|href)=["'](?:https?:)?\/\//iu.test(index)
  ) {
    fail("reviewer SPA shell differs from the closed script/origin policy");
  }
}

export function validateReviewerExport(root) {
  const files = collectFiles(root);
  const names = [...files.keys()].sort();
  const bundles = names.filter((name) => entryBundle.test(name));
  if (
    bundles.length !== 1
    || !files.has("index.html")
    || !files.has("metadata.json")
  ) {
    fail("reviewer export must contain one SPA shell, metadata file, and entry bundle");
  }
  for (const name of names) {
    const permitted = name === "index.html"
      || name === "metadata.json"
      || entryBundle.test(name)
      || (
        name.startsWith("assets/")
        && allowedAssetExtension.has(path.posix.extname(name).toLowerCase())
      );
    if (!permitted || name.endsWith(".map")) {
      fail(`reviewer export contains an unexpected artifact: ${name}`);
    }
  }
  const metadata = readFileSync(files.get("metadata.json"));
  if (
    metadata.toString("utf8")
      !== '{"version":0,"bundler":"metro","fileMetadata":{}}'
  ) {
    fail("reviewer export metadata differs from the closed static form");
  }
  validateIndex(readFileSync(files.get("index.html")), bundles[0]);
  const bundleBytes = readFileSync(files.get(bundles[0]));
  const expectedBundleDigest = entryBundle.exec(bundles[0])?.[1];
  const actualBundleDigest = createHash("md5")
    .update(bundleBytes)
    .digest("hex");
  if (actualBundleDigest !== expectedBundleDigest) {
    fail("reviewer entry bundle content does not match its immutable filename");
  }
  const bundle = bundleBytes.toString("utf8");
  if (
    !bundle.includes("sessionStorage")
    || forbiddenBundleText.some((value) => bundle.includes(value))
  ) {
    fail("reviewer bundle contains a forbidden storage, native, or source-map path");
  }
  return {
    bundle: bundles[0],
    files: files.size,
    status: "ok",
  };
}

export function validateRepository(root = repositoryRoot) {
  checkReviewerThirdPartyNotices(root);
  validateDockerDefinition(
    readFileSync(path.join(root, "services/reviewer-web/Dockerfile"), "utf8"),
    readFileSync(
      path.join(root, "services/reviewer-web/Dockerfile.dockerignore"),
      "utf8",
    ),
  );
  return validateReviewerExport(path.join(root, "apps/reviewer/dist"));
}

if (
  process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  process.stdout.write(`${JSON.stringify(validateRepository())}\n`);
}
