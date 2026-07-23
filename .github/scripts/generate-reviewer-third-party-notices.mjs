// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultRepositoryRoot = path.resolve(scriptDirectory, "../..");
const maximumPackages = 1_024;
const maximumSourceBytes = 1_048_576;
const maximumNoticeBytes = 4_194_304;
const auditedFallbackSetDigest =
  "sha256:5ce9a9b8b7c40ddf36ec3f4f771be0aff7b19d36d4981594ede0b2743e11a912";
const noticeName =
  /^(?:unlicense|licen[cs]e|copying|notice)(?:$|[._-])/iu;
const metadataFallbackPackages = new Set([
  "@expo/sdk-runtime-versions",
  "@expo/ws-tunnel",
  "@expo/xcpretty",
  "@react-native/debugger-frontend",
  "client-only",
  "jimp-compact",
  "server-only",
  "standard-navigation",
  "structured-headers",
  "tr46",
]);
const licenseTermSources = {
  "Apache-2.0": ["../../LICENSE"],
  "BSD-3-Clause": ["node_modules/hyphenate-style-name/LICENSE"],
  MIT: ["node_modules/expo/LICENSE"],
  "MIT OR Apache-2.0": [
    "node_modules/expo/LICENSE",
    "../../LICENSE",
  ],
  "(MIT OR Apache-2.0)": [
    "node_modules/expo/LICENSE",
    "../../LICENSE",
  ],
  Unlicense: ["node_modules/big-integer/LICENSE"],
};

function fail(message) {
  throw new Error(message);
}

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function safeText(bytes, label) {
  if (bytes.length < 1 || bytes.length > maximumSourceBytes) {
    fail(`${label} is empty or oversized`);
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not UTF-8`);
  }
  if (text.includes("\0")) fail(`${label} contains a NUL`);
  return text.replaceAll("\r\n", "\n").replaceAll("\r", "\n").trimEnd();
}

function safeRegularFile(filename, label) {
  const metadata = lstatSync(filename);
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || (metadata.mode & 0o022) !== 0
    || metadata.size < 1
    || metadata.size > maximumSourceBytes
  ) {
    fail(`${label} is not a bounded read-only regular file`);
  }
  return readFileSync(filename);
}

function safeDirectory(directory, label) {
  const metadata = lstatSync(directory);
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || (metadata.mode & 0o022) !== 0
  ) {
    fail(`${label} is not a read-only real directory`);
  }
}

function repositoryValue(value) {
  const candidate = typeof value === "string" ? value : value?.url;
  if (typeof candidate !== "string" || !candidate.trim()) return "not declared";
  const normalized = candidate.trim();
  if (
    normalized.length > 512
    || /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    fail("dependency repository metadata is invalid");
  }
  return normalized;
}

function packageNameFromInstallKey(installKey) {
  const tail = installKey
    .slice("node_modules/".length)
    .split("/node_modules/")
    .at(-1);
  if (!tail) fail("package-lock install key is invalid");
  const parts = tail.split("/");
  const name = parts[0]?.startsWith("@")
    ? `${parts[0]}/${parts[1] ?? ""}`
    : parts[0];
  if (
    !name
    || name.length > 214
    || !/^(@[a-z0-9._-]+\/)?[a-z0-9._-]+$/iu.test(name)
  ) {
    fail("package-lock package name is invalid");
  }
  return name;
}

function licenseFiles(packageDirectory) {
  const pending = [{ absolute: packageDirectory, depth: 0, relative: "" }];
  const files = [];
  let directories = 0;
  while (pending.length) {
    const current = pending.pop();
    directories += 1;
    if (directories > 2_048 || current.depth > 16) {
      fail("dependency notice scan exceeds its closed directory bound");
    }
    for (const entry of readdirSync(current.absolute, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const relative = current.relative
        ? `${current.relative}/${entry.name}`
        : entry.name;
      const absolute = path.join(current.absolute, entry.name);
      if (entry.isDirectory()) {
        // Nested dependencies are represented by their own package-lock entry.
        if (entry.name !== "node_modules") {
          pending.push({
            absolute,
            depth: current.depth + 1,
            relative,
          });
        }
      } else if (entry.isFile() && noticeName.test(entry.name)) {
        files.push(relative);
        if (files.length > 128) {
          fail("dependency notice scan exceeds its closed file bound");
        }
      }
    }
  }
  return files.sort((first, second) => first.localeCompare(second, "en"));
}

function hasPackageLicense(metadata, files) {
  return (
    files.some((filename) => !filename.includes("/"))
    || (
      metadata.name === "@react-native/debugger-frontend"
      && files.includes("dist/third-party/LICENSE")
    )
  );
}

function embeddedPackageNotices(packageDirectory, metadata) {
  if (metadata.name === "bser" && metadata.version === "2.1.1") {
    const expectedHeader = [
      "/* Copyright 2015-present Facebook, Inc.",
      " * Licensed under the Apache License, Version 2.0 */",
    ].join("\n");
    const source = safeText(
      safeRegularFile(
        path.join(packageDirectory, "index.js"),
        "bser embedded attribution",
      ),
      "bser embedded attribution",
    );
    if (!source.startsWith(`${expectedHeader}\n\n`)) {
      fail("bser embedded attribution differs from its audited form");
    }
    const apache = safeText(
      safeRegularFile(
        path.join(packageDirectory, "../../../../LICENSE"),
        "audited Apache-2.0 terms",
      ),
      "audited Apache-2.0 terms",
    );
    return [
      { label: "index.js#license-header", text: expectedHeader },
      { label: "declared-Apache-2.0-terms", text: apache },
    ];
  }
  if (metadata.name === "fb-watchman" && metadata.version === "2.0.2") {
    const expectedHeader = [
      "/**",
      " * Copyright (c) Meta Platforms, Inc. and affiliates.",
      " *",
      " * This source code is licensed under the MIT license found in the",
      " * LICENSE file in the root directory of this source tree.",
      " */",
    ].join("\n");
    const source = safeText(
      safeRegularFile(
        path.join(packageDirectory, "index.js"),
        "fb-watchman embedded attribution",
      ),
      "fb-watchman embedded attribution",
    );
    if (!source.startsWith(`${expectedHeader}\n\n`)) {
      fail("fb-watchman embedded attribution differs from its audited form");
    }
    const mit = safeText(
      safeRegularFile(
        path.join(packageDirectory, "../react-native/LICENSE"),
        "audited Meta MIT terms",
      ),
      "audited Meta MIT terms",
    );
    const apache = safeText(
      safeRegularFile(
        path.join(packageDirectory, "../../../../LICENSE"),
        "audited Apache-2.0 terms",
      ),
      "audited Apache-2.0 terms",
    );
    return [
      { label: "index.js#license-header", text: expectedHeader },
      {
        label: "upstream-license-metadata-note",
        text: [
          "This exact package declares Apache-2.0 in its package metadata,",
          "while index.js carries the retained Meta MIT license header.",
          "Tacua conservatively includes both license texts.",
        ].join("\n"),
      },
      { label: "source-header-Meta-MIT-license", text: mit },
      { label: "declared-Apache-2.0-terms", text: apache },
    ];
  }
  if (metadata.name === "@expo/devcert" && metadata.version === "1.2.1") {
    const readme = safeText(
      safeRegularFile(
        path.join(packageDirectory, "README.md"),
        "@expo/devcert embedded attribution",
      ),
      "@expo/devcert embedded attribution",
    );
    const marker = "## License\n\n";
    const offset = readme.indexOf(marker);
    const section = offset < 0 ? "" : readme.slice(offset);
    if (!section.includes("MIT © [Dave Wasmer](http://davewasmer.com)")) {
      fail("@expo/devcert embedded attribution differs from its audited form");
    }
    const mit = safeText(
      safeRegularFile(
        path.join(packageDirectory, "../../expo/LICENSE"),
        "audited MIT permission terms",
      ),
      "audited MIT permission terms",
    );
    return [
      { label: "README.md#License", text: section },
      {
        label: "declared-MIT-permission-terms",
        text: permissionTerms(mit, "MIT", "node_modules/expo/LICENSE"),
      },
    ];
  }
  if (metadata.name !== "bplist-parser" || metadata.version !== "0.3.1") {
    return [];
  }
  const relative = "README.md";
  const readme = safeText(
    safeRegularFile(
      path.join(packageDirectory, relative),
      "bplist-parser embedded license",
    ),
    "bplist-parser embedded license",
  );
  const marker = "## License\n\n";
  const offset = readme.indexOf(marker);
  if (
    offset < 0
    || !readme.slice(offset).includes(
      "Copyright (c) 2012 Near Infinity Corporation",
    )
    || !readme.slice(offset).includes("Permission is hereby granted")
  ) {
    fail("bplist-parser embedded license differs from its audited form");
  }
  return [{
    label: "README.md#License",
    text: readme.slice(offset),
  }];
}

function normalizedRepository(metadata) {
  return repositoryValue(metadata.repository)
    .replace(/^git\+ssh:\/\/git@github\.com\//u, "https://github.com/")
    .replace(/^git\+https:/u, "https:")
    .replace(/^git@github\.com:/u, "https://github.com/")
    .replace(/^git\+/u, "");
}

function exactProjectFallback(metadata, license) {
  const repository = normalizedRepository(metadata);
  if (
    license === "MIT"
    && (
      repository === "https://github.com/expo/expo.git"
      || metadata.name === "@expo/sdk-runtime-versions"
      || metadata.name === "@expo/ws-tunnel"
    )
  ) {
    return [{
      label: "audited-expo-license",
      relative: "node_modules/expo/LICENSE",
    }];
  }
  if (
    license === "(MIT OR Apache-2.0)"
    && repository === "https://github.com/facebook/dotslash.git"
  ) {
    return [
      {
        label: "audited-dotslash-meta-mit-byte-equivalent",
        relative: "node_modules/react-native/LICENSE",
      },
      {
        label: "audited-apache-2.0-terms",
        relative: "../../LICENSE",
      },
    ];
  }
  if (
    license === "MIT"
    && repository === "https://github.com/facebook/react-native.git"
  ) {
    return [{
      label: "audited-react-native-license",
      relative: "node_modules/react-native/LICENSE",
    }];
  }
  if (
    license === "MIT"
    && (
      repository === "https://github.com/facebook/react.git"
      || metadata.name === "client-only"
      || metadata.name === "server-only"
    )
  ) {
    return [{
      label: "audited-react-license",
      relative: "node_modules/react/LICENSE",
    }];
  }
  if (
    license === "MIT"
    && repository === "https://github.com/facebook/hermes.git"
  ) {
    return [{
      label: "audited-hermes-license",
      relative: "node_modules/hermes-parser/LICENSE",
    }];
  }
  if (
    license === "MIT"
    && repository === "https://github.com/facebook/metro.git"
  ) {
    return [{
      label: "audited-metro-license-byte-equivalent",
      relative: "node_modules/react-native/LICENSE",
    }];
  }
  return null;
}

function permissionTerms(text, license, label) {
  let marker;
  if (license === "MIT") marker = "Permission is hereby granted";
  if (license === "BSD-3-Clause") marker = "Redistribution and use";
  if (!marker) return text;
  const offset = text.indexOf(marker);
  if (offset < 0) fail(`${label} does not contain the expected ${license} terms`);
  return text.slice(offset);
}

function safePublishedMetadata(metadata) {
  const attribution = JSON.stringify({
    author: metadata.author ?? null,
    contributors: metadata.contributors ?? null,
    repository: metadata.repository ?? null,
  });
  if (
    attribution.length > 8_192
    || /[\u0000-\u001f\u007f]/u.test(attribution)
  ) {
    fail(`published attribution metadata is invalid for ${metadata.name}`);
  }
  return [
    "The publisher omitted a license/notice file from this exact package.",
    "Tacua therefore retains the package's published attribution metadata",
    "and the unmodified permission terms for its declared SPDX license.",
    "",
    attribution,
  ].join("\n");
}

function fallbackLicenseBytes(repositoryRoot, reviewerRoot, metadata, license) {
  const exactSources = exactProjectFallback(metadata, license);
  if (exactSources) {
    return exactSources.map(({ label, relative }) => {
      const absolute = path.join(reviewerRoot, relative);
      return {
        label: `${label}:${relative}`,
        text: safeText(
          safeRegularFile(absolute, `same-project license ${relative}`),
          `same-project license ${relative}`,
        ),
      };
    });
  }
  const metadataFallbackAllowed = (
    metadataFallbackPackages.has(metadata.name)
    || metadata.name === "react-remove-scroll-bar"
  );
  const sources = licenseTermSources[license];
  if (!metadataFallbackAllowed || !sources) {
    fail(
      `package ${metadata.name} omitted its ${license} license text `
      + "and has no audited package fallback",
    );
  }
  const included = [{
    label: "published-package-attribution",
    text: safePublishedMetadata(metadata),
  }];
  for (const relative of sources) {
    const absolute = path.resolve(reviewerRoot, relative);
    if (
      absolute !== path.join(repositoryRoot, "LICENSE")
      && !absolute.startsWith(`${reviewerRoot}${path.sep}`)
    ) {
      fail("audited license-term source escaped its closed roots");
    }
    const sourceLicense = relative === "../../LICENSE"
      ? "Apache-2.0"
      : license === "BSD-3-Clause"
        ? "BSD-3-Clause"
        : license === "Unlicense"
          ? "Unlicense"
          : "MIT";
    const sourceText = safeText(
      safeRegularFile(absolute, `license terms ${relative}`),
      `license terms ${relative}`,
    );
    included.push({
      label: `declared-${sourceLicense}-permission-terms`,
      text: permissionTerms(sourceText, sourceLicense, relative),
    });
  }
  return included;
}

export function validateFallbackAuditRows(rows) {
  const bytes = Buffer.from(JSON.stringify(rows), "utf8");
  const actualDigest = digest(bytes);
  if (actualDigest !== auditedFallbackSetDigest) {
    fail(
      "reviewer package fallback inventory differs from the audited set "
      + `(received ${actualDigest})`,
    );
  }
}

export function buildReviewerThirdPartyNotices(
  repositoryRoot = defaultRepositoryRoot,
) {
  const reviewerRoot = path.join(repositoryRoot, "apps/reviewer");
  const lockPath = path.join(reviewerRoot, "package-lock.json");
  const packagePath = path.join(reviewerRoot, "package.json");
  const nodeModules = path.join(reviewerRoot, "node_modules");
  safeDirectory(reviewerRoot, "reviewer root");
  safeDirectory(nodeModules, "reviewer node_modules");
  const lockBytes = safeRegularFile(lockPath, "reviewer package lock");
  const packageBytes = safeRegularFile(packagePath, "reviewer package manifest");
  const lock = JSON.parse(safeText(lockBytes, "reviewer package lock"));
  const manifest = JSON.parse(safeText(packageBytes, "reviewer package manifest"));
  if (
    lock.lockfileVersion !== 3
    || !lock.packages
    || typeof lock.packages !== "object"
    || Array.isArray(lock.packages)
    || lock.packages[""]?.name !== manifest.name
    || lock.packages[""]?.version !== manifest.version
  ) {
    fail("reviewer package lock does not bind the package manifest");
  }

  const packages = Object.entries(lock.packages)
    .filter(([installKey, record]) => (
      installKey.startsWith("node_modules/")
      && record
      && typeof record === "object"
      && record.dev !== true
      && record.link !== true
      // Optional platform/tooling packages are not shipped in the static
      // reviewer image. Their presence in node_modules varies by build host,
      // so including them would also make the generated notice non-reproducible.
      && record.optional !== true
    ))
    .sort(([first], [second]) => first.localeCompare(second, "en"));
  if (!packages.length || packages.length > maximumPackages) {
    fail("reviewer production dependency count is outside the closed bound");
  }

  const sections = [];
  const fallbackAuditRows = [];
  for (const [installKey, record] of packages) {
    const packageDirectory = path.join(reviewerRoot, installKey);
    safeDirectory(packageDirectory, `dependency ${installKey}`);
    const metadataPath = path.join(packageDirectory, "package.json");
    const metadata = JSON.parse(safeText(
      safeRegularFile(metadataPath, `dependency metadata ${installKey}`),
      `dependency metadata ${installKey}`,
    ));
    const expectedName = packageNameFromInstallKey(installKey);
    if (
      metadata.name !== expectedName
      || metadata.version !== record.version
      || typeof record.license !== "string"
      || !record.license
      || record.license.length > 128
      || /[\u0000-\u001f\u007f]/u.test(record.license)
    ) {
      fail(`dependency metadata does not match package-lock: ${installKey}`);
    }
    const files = licenseFiles(packageDirectory);
    const embedded = embeddedPackageNotices(packageDirectory, metadata);
    const needsPackageFallback = (
      !hasPackageLicense(metadata, files)
      && !embedded.length
    );
    if (needsPackageFallback) {
      fallbackAuditRows.push({
        install_key: installKey,
        integrity: record.integrity ?? null,
        license: record.license,
        name: metadata.name,
        repository: normalizedRepository(metadata),
        version: metadata.version,
      });
    }
    const included = [
      ...files.map((filename) => ({
        label: filename,
        text: safeText(
          safeRegularFile(
            path.join(packageDirectory, filename),
            `dependency notice ${installKey}/${filename}`,
          ),
          `dependency notice ${installKey}/${filename}`,
        ),
      })),
      ...embedded,
      ...(
        needsPackageFallback
          ? fallbackLicenseBytes(
            repositoryRoot,
            reviewerRoot,
            metadata,
            record.license,
          )
          : []
      ),
    ];
    const body = included.map(({ label, text }) => (
      `Included notice: ${label}\n\n${text}`
    )).join("\n\n");
    sections.push(
      [
        "=".repeat(80),
        `Package: ${metadata.name}`,
        `Version: ${metadata.version}`,
        `Install key: ${installKey}`,
        `Declared license: ${record.license}`,
        `Repository: ${repositoryValue(metadata.repository)}`,
        "",
        body,
      ].join("\n"),
    );
  }
  validateFallbackAuditRows(fallbackAuditRows);

  const output = [
    "Tacua reviewer web — third-party notices",
    "",
    "This conservative inventory covers every non-development, non-optional",
    "package entry from the exact reviewer package lock. It can over-include",
    "build-time packages that are not present in the static JavaScript output.",
    "Each section retains the package's own license and notice files. When a",
    "publisher omitted them, an explicit audited fallback retains either the",
    "same project's license or the exact published package attribution plus",
    "the permission terms for the declared SPDX license.",
    "",
    `Reviewer package: ${manifest.name}@${manifest.version}`,
    `Package-lock digest: ${digest(lockBytes)}`,
    `Dependency entries: ${packages.length}`,
    "",
    ...sections,
    "",
  ].join("\n");
  const bytes = Buffer.from(output, "utf8");
  if (bytes.length > maximumNoticeBytes) {
    fail("generated reviewer third-party notices exceed the closed byte bound");
  }
  return bytes;
}

function outputPath(repositoryRoot) {
  return path.join(
    repositoryRoot,
    "apps/reviewer/generated/THIRD_PARTY_NOTICES.txt",
  );
}

function validateGeneratedDirectory(directory) {
  if (!existsSync(directory)) {
    mkdirSync(directory, { mode: 0o755 });
  }
  safeDirectory(directory, "reviewer generated directory");
}

export function writeReviewerThirdPartyNotices(
  repositoryRoot = defaultRepositoryRoot,
) {
  const bytes = buildReviewerThirdPartyNotices(repositoryRoot);
  const destination = outputPath(repositoryRoot);
  const directory = path.dirname(destination);
  validateGeneratedDirectory(directory);
  if (existsSync(destination) && lstatSync(destination).isSymbolicLink()) {
    fail("reviewer third-party notices destination must not be a link");
  }
  const temporary = `${destination}.${process.pid}.tmp`;
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, destination);
    chmodSync(destination, 0o444);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(temporary)) unlinkSync(temporary);
    throw error;
  }
  return { bytes: bytes.length, digest: digest(bytes) };
}

export function checkReviewerThirdPartyNotices(
  repositoryRoot = defaultRepositoryRoot,
) {
  const expected = buildReviewerThirdPartyNotices(repositoryRoot);
  const destination = outputPath(repositoryRoot);
  const actual = safeRegularFile(destination, "generated reviewer notices");
  if (
    (lstatSync(destination).mode & 0o777) !== 0o444
    || !actual.equals(expected)
  ) {
    fail("generated reviewer third-party notices are stale or unsafe");
  }
  return { bytes: actual.length, digest: digest(actual) };
}

if (
  process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  const command = process.argv[2];
  if (process.argv.length > (command === "--check" ? 3 : 2)) {
    fail("usage: generate-reviewer-third-party-notices.mjs [--check]");
  }
  const result = command === "--check"
    ? checkReviewerThirdPartyNotices()
    : writeReviewerThirdPartyNotices();
  process.stdout.write(`${JSON.stringify({ ...result, status: "ok" })}\n`);
}
