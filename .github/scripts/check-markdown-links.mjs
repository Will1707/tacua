// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultRepositoryRoot = path.resolve(scriptDirectory, "../..");

function withoutCode(markdown) {
  return markdown
    .replace(/^ {0,3}(`{3,}|~{3,})[^\n]*\n[\s\S]*?^ {0,3}\1\s*$/gmu, "")
    .replace(/`+[^`\n]*`+/gu, "");
}

export function extractMarkdownDestinations(markdown) {
  const source = withoutCode(markdown);
  const destinations = [];
  const inline = /!?\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^\s)]+))/gu;
  const reference = /^ {0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|([^\s]+))/gmu;
  for (const pattern of [inline, reference]) {
    for (const match of source.matchAll(pattern)) {
      destinations.push(match[1] ?? match[2]);
    }
  }
  return destinations;
}

function githubHeadingAnchors(markdown) {
  const anchors = new Set();
  const duplicateCounts = new Map();
  for (const line of withoutCode(markdown).split(/\r?\n/u)) {
    const heading = /^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$/u.exec(line)?.[1];
    if (!heading) continue;
    const base = heading
      .replace(/<[^>]*>/gu, "")
      .replace(/[\p{P}\p{S}]/gu, (character) => (character === "-" || character === "_" ? character : ""))
      .trim()
      .toLocaleLowerCase("en-US")
      .replace(/\s+/gu, "-");
    if (!base) continue;
    const count = duplicateCounts.get(base) ?? 0;
    duplicateCounts.set(base, count + 1);
    anchors.add(count === 0 ? base : `${base}-${count}`);
  }
  for (const match of markdown.matchAll(/<(?:a|[A-Za-z][A-Za-z0-9-]*)\s+(?:[^>]*?\s)?(?:id|name)=["']([^"']+)["'][^>]*>/gu)) {
    anchors.add(match[1]);
  }
  return anchors;
}

function localDestination(destination) {
  if (
    destination.startsWith("//") ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(destination)
  ) {
    return null;
  }
  const hashIndex = destination.indexOf("#");
  const queryIndex = destination.indexOf("?");
  const pathEnd = [hashIndex, queryIndex]
    .filter((index) => index >= 0)
    .reduce((minimum, index) => Math.min(minimum, index), destination.length);
  const encodedPath = destination.slice(0, pathEnd);
  const encodedFragment = hashIndex >= 0
    ? destination.slice(hashIndex + 1, queryIndex > hashIndex ? queryIndex : undefined)
    : "";
  try {
    return {
      fragment: decodeURIComponent(encodedFragment),
      targetPath: decodeURIComponent(encodedPath),
    };
  } catch {
    throw new Error(`malformed percent-encoding in Markdown destination: ${destination}`);
  }
}

export function checkMarkdownFile(repositoryRoot, relativeSourcePath) {
  const root = realpathSync(repositoryRoot);
  const sourcePath = path.resolve(root, relativeSourcePath);
  const source = readFileSync(sourcePath, "utf8");
  const failures = [];
  for (const destination of extractMarkdownDestinations(source)) {
    let local;
    try {
      local = localDestination(destination);
    } catch (error) {
      failures.push(`${relativeSourcePath}: ${error.message}`);
      continue;
    }
    if (!local) continue;
    const unresolved = local.targetPath
      ? local.targetPath.startsWith("/")
        ? path.resolve(root, `.${local.targetPath}`)
        : path.resolve(path.dirname(sourcePath), local.targetPath)
      : sourcePath;
    const relativeTarget = path.relative(root, unresolved);
    if (relativeTarget === ".." || relativeTarget.startsWith(`..${path.sep}`)) {
      failures.push(`${relativeSourcePath}: local link escapes repository: ${destination}`);
      continue;
    }
    if (!existsSync(unresolved)) {
      failures.push(`${relativeSourcePath}: missing local link target: ${destination}`);
      continue;
    }
    let resolved;
    try {
      resolved = realpathSync(unresolved);
    } catch {
      failures.push(`${relativeSourcePath}: unreadable local link target: ${destination}`);
      continue;
    }
    const realRelative = path.relative(root, resolved);
    if (realRelative === ".." || realRelative.startsWith(`..${path.sep}`)) {
      failures.push(`${relativeSourcePath}: local link resolves outside repository: ${destination}`);
      continue;
    }
    if (local.fragment && statSync(resolved).isFile()) {
      const anchors = githubHeadingAnchors(readFileSync(resolved, "utf8"));
      if (!anchors.has(local.fragment)) {
        failures.push(`${relativeSourcePath}: missing local heading fragment: ${destination}`);
      }
    }
  }
  return failures;
}

export function checkRepositoryMarkdownLinks(repositoryRoot = defaultRepositoryRoot) {
  const paths = execFileSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "--", "*.md"],
    { cwd: repositoryRoot, encoding: "utf8", maxBuffer: 4 * 1_024 * 1_024 },
  )
    .split(/\r?\n/u)
    .filter(Boolean)
    .sort();
  return paths.flatMap((sourcePath) => checkMarkdownFile(repositoryRoot, sourcePath));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const failures = checkRepositoryMarkdownLinks();
  if (failures.length) {
    process.stderr.write(`${failures.join("\n")}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write("All repository-local Markdown links resolve.\n");
  }
}
