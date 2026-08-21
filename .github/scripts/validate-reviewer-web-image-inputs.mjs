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
    "groupadd --gid 10002 tacua-reviewer && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tacua-reviewer && install -d -o root -g root -m 0555 /srv/tacua-reviewer /srv/tacua-reviewer/_expo /srv/tacua-reviewer/_expo/static /srv/tacua-reviewer/_expo/static/js /srv/tacua-reviewer/_expo/static/js/web /srv/tacua-reviewer/assets /srv/tacua-reviewer/assets/node_modules /srv/tacua-reviewer/assets/node_modules/expo-router /srv/tacua-reviewer/assets/node_modules/expo-router/assets /srv/tacua-reviewer/assets/node_modules/expo-router/assets/react-navigation /srv/tacua-reviewer/assets/node_modules/expo-router/assets/react-navigation/elements /licenses /licenses/tacua /licenses/reviewer",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0555 services/reviewer-web/server.py /usr/local/bin/tacua-reviewer-web",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0444 apps/reviewer/dist/index.html apps/reviewer/dist/metadata.json /srv/tacua-reviewer/",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0444 apps/reviewer/dist/_expo/static/js/web/*.js /srv/tacua-reviewer/_expo/static/js/web/",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0444 apps/reviewer/dist/assets/node_modules/expo-router/assets/*.png /srv/tacua-reviewer/assets/node_modules/expo-router/assets/",
  ],
  [
    "COPY",
    "--chown=root:root --chmod=0444 apps/reviewer/dist/assets/node_modules/expo-router/assets/react-navigation/elements/*.png /srv/tacua-reviewer/assets/node_modules/expo-router/assets/react-navigation/elements/",
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
export const reviewerImageInputPaths = Object.freeze([
  "LICENSE",
  "NOTICE",
  "apps/reviewer/NOTICE",
  "apps/reviewer/generated/THIRD_PARTY_NOTICES.txt",
  "services/reviewer-web/server.py",
]);
const reviewerImageInputDirectories = new Set([""]);
for (const inputPath of reviewerImageInputPaths) {
  let directory = path.posix.dirname(inputPath);
  while (directory !== ".") {
    reviewerImageInputDirectories.add(directory);
    directory = path.posix.dirname(directory);
  }
}
const safePart = /^[A-Za-z0-9@._-]{1,255}$/u;
const allowedDirectories = new Set([
  "_expo",
  "_expo/static",
  "_expo/static/js",
  "_expo/static/js/web",
  "assets",
  "assets/node_modules",
  "assets/node_modules/expo-router",
  "assets/node_modules/expo-router/assets",
  "assets/node_modules/expo-router/assets/react-navigation",
  "assets/node_modules/expo-router/assets/react-navigation/elements",
]);
const entryBundle = /^_expo\/static\/js\/web\/entry-([a-f0-9]{32})\.js$/u;
const allowedAsset = /^(?:assets\/node_modules\/expo-router\/assets\/(?:[^/]+\.png|react-navigation\/elements\/[^/]+\.png))$/u;
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

function metadataIdentity(metadata) {
  return [
    metadata.dev,
    metadata.ino,
    metadata.mode,
    metadata.nlink,
    metadata.size,
    metadata.mtimeMs,
    metadata.ctimeMs,
  ];
}

function sameMetadata(left, right) {
  const before = metadataIdentity(left);
  const after = metadataIdentity(right);
  return before.every((value, index) => value === after[index]);
}

function snapshotReviewerImageInputs(root) {
  const absoluteRoot = path.resolve(root);
  const rootMetadata = lstatSync(absoluteRoot);
  if (
    !rootMetadata.isDirectory()
    || rootMetadata.isSymbolicLink()
    || ![0o555, 0o700, 0o755].includes(rootMetadata.mode & 0o7777)
  ) {
    fail("reviewer image input root is not a safe real directory");
  }
  const resolvedRoot = realpathSync(absoluteRoot);
  const directorySnapshots = new Map();
  for (const relativePath of [...reviewerImageInputDirectories].sort()) {
    const absolutePath = relativePath
      ? path.join(absoluteRoot, relativePath)
      : absoluteRoot;
    const metadata = lstatSync(absolutePath);
    const expectedResolved = relativePath
      ? path.join(resolvedRoot, ...relativePath.split("/"))
      : resolvedRoot;
    if (
      !metadata.isDirectory()
      || metadata.isSymbolicLink()
      || ![0o555, 0o700, 0o755].includes(metadata.mode & 0o7777)
      || realpathSync(absolutePath) !== expectedResolved
    ) {
      fail(`reviewer image input directory is unsafe: ${relativePath || "."}`);
    }
    directorySnapshots.set(absolutePath, { expectedResolved, metadata });
  }

  let totalBytes = 0;
  const fileSnapshots = new Map();
  for (const relativePath of reviewerImageInputPaths) {
    const absolutePath = path.join(absoluteRoot, relativePath);
    const metadata = lstatSync(absolutePath);
    const resolved = realpathSync(absolutePath);
    const after = lstatSync(absolutePath);
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.nlink !== 1
      || ![0o444, 0o600, 0o644].includes(metadata.mode & 0o7777)
      || metadata.size < 1
      || metadata.size > maximumReviewerFileBytes
      || resolved !== path.join(resolvedRoot, ...relativePath.split("/"))
      || !sameMetadata(metadata, after)
    ) {
      fail(`reviewer image contains an unsafe copied input: ${relativePath}`);
    }
    fileSnapshots.set(absolutePath, {
      expectedResolved: resolved,
      metadata,
      relativePath,
    });
    totalBytes += metadata.size;
  }
  if (totalBytes > maximumReviewerBytes) {
    fail("reviewer non-export image inputs exceed their aggregate bound");
  }
  return {
    result: { files: reviewerImageInputPaths.length, totalBytes },
    revalidate() {
      for (const [absolutePath, before] of fileSnapshots) {
        const after = lstatSync(absolutePath);
        if (
          !after.isFile()
          || after.isSymbolicLink()
          || !sameMetadata(before.metadata, after)
          || realpathSync(absolutePath) !== before.expectedResolved
        ) {
          fail(`reviewer image input changed during validation: ${before.relativePath}`);
        }
      }
      for (const [absolutePath, before] of directorySnapshots) {
        const after = lstatSync(absolutePath);
        if (
          !after.isDirectory()
          || after.isSymbolicLink()
          || !sameMetadata(before.metadata, after)
          || realpathSync(absolutePath) !== before.expectedResolved
        ) {
          fail("reviewer image input directory changed during validation");
        }
      }
    },
  };
}

export function validateReviewerImageInputs(root = repositoryRoot, hooks = {}) {
  const validation = snapshotReviewerImageInputs(root);
  hooks.beforeFinalRevalidation?.();
  validation.revalidate();
  return validation.result;
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

function safeFile(relative, metadata) {
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1
    || ![0o600, 0o644].includes(metadata.mode & 0o7777)
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
    || ![0o700, 0o755].includes(rootMetadata.mode & 0o7777)
  ) {
    fail("reviewer export root must be one real directory");
  }
  const resolvedRoot = realpathSync(root);
  const rootAfter = lstatSync(root);
  if (!sameMetadata(rootMetadata, rootAfter)) {
    fail("reviewer export root changed during inspection");
  }
  const pending = [root];
  const directories = new Set();
  const files = new Map();
  const snapshots = new Map([
    [root, {
      expectedResolved: resolvedRoot,
      kind: "directory",
      metadata: rootMetadata,
      relativePath: ".",
    }],
  ]);
  let total = 0;
  while (pending.length) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      const metadata = lstatSync(absolute);
      const resolved = realpathSync(absolute);
      const after = lstatSync(absolute);
      if (
        relative.startsWith("../")
        || relative.split("/").some((part) => !safePart.test(part))
        || resolved !== path.resolve(resolvedRoot, relative)
        || !sameMetadata(metadata, after)
      ) {
        fail("reviewer export path is unsafe");
      }
      if (metadata.isSymbolicLink() || entry.isSymbolicLink()) {
        fail("reviewer export must not contain links");
      }
      if (metadata.isDirectory()) {
        if (
          !allowedDirectories.has(relative)
          || ![0o700, 0o755].includes(metadata.mode & 0o7777)
        ) {
          fail("reviewer export contains a non-container-readable directory");
        }
        directories.add(relative);
        pending.push(absolute);
        snapshots.set(absolute, {
          expectedResolved: resolved,
          kind: "directory",
          metadata,
          relativePath: relative,
        });
      } else if (metadata.isFile()) {
        total += safeFile(relative, metadata);
        files.set(relative, absolute);
        snapshots.set(absolute, {
          expectedResolved: resolved,
          kind: "file",
          metadata,
          relativePath: relative,
        });
      } else {
        fail("reviewer export contains a non-file entry");
      }
      if (files.size > maximumReviewerFiles || total > maximumReviewerBytes) {
        fail("reviewer export exceeds its closed size or file-count bound");
      }
    }
  }
  if (
    directories.size !== allowedDirectories.size
    || [...allowedDirectories].some((directory) => !directories.has(directory))
  ) {
    fail("reviewer export directory shape differs from the closed policy");
  }
  return { files, snapshots };
}

function revalidateExportSnapshots(snapshots) {
  for (const [absolutePath, before] of snapshots) {
    const after = lstatSync(absolutePath);
    const expectedKind = before.kind === "file"
      ? after.isFile()
      : after.isDirectory();
    if (
      !expectedKind
      || after.isSymbolicLink()
      || !sameMetadata(before.metadata, after)
      || realpathSync(absolutePath) !== before.expectedResolved
    ) {
      fail(`reviewer export changed during validation: ${before.relativePath}`);
    }
  }
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

function snapshotReviewerExport(root) {
  const { files, snapshots } = collectFiles(root);
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
      || allowedAsset.test(name);
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
    result: {
      bundle: bundles[0],
      files: files.size,
      status: "ok",
    },
    revalidate() {
      revalidateExportSnapshots(snapshots);
    },
  };
}

export function validateReviewerExport(root, hooks = {}) {
  const validation = snapshotReviewerExport(root);
  hooks.beforeFinalRevalidation?.();
  validation.revalidate();
  return validation.result;
}

export function validateRepository(root = repositoryRoot, hooks = {}) {
  const inputValidation = snapshotReviewerImageInputs(root);
  checkReviewerThirdPartyNotices(root);
  validateDockerDefinition(
    readFileSync(path.join(root, "services/reviewer-web/Dockerfile"), "utf8"),
    readFileSync(
      path.join(root, "services/reviewer-web/Dockerfile.dockerignore"),
      "utf8",
    ),
  );
  const exportValidation = snapshotReviewerExport(
    path.join(root, "apps/reviewer/dist"),
  );
  hooks.beforeFinalRevalidation?.();
  exportValidation.revalidate();
  inputValidation.revalidate();
  return exportValidation.result;
}

if (
  process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  process.stdout.write(`${JSON.stringify(validateRepository())}\n`);
}
