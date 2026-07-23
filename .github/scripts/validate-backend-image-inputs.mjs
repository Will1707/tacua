// SPDX-License-Identifier: Apache-2.0

import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");

export const MAX_BACKEND_IMAGE_INPUT_FILES = 256;
export const MAX_BACKEND_IMAGE_INPUT_FILE_BYTES = 2_097_152;
export const MAX_BACKEND_IMAGE_INPUT_BYTES = 16_777_216;

const expectedBase =
  "python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91";

const exactPaths = [
  "LICENSE",
  "NOTICE",
  "services/backend/config.example.json",
  "services/backend/config.template.example.json",
  "services/backend/scripts/run_compose_isolated_processing.py",
  "services/backend/scripts/run_isolated_processor.py",
];
const sourceFamilies = [
  {
    directory: "services/backend/src/tacua_backend",
    pattern: /^[A-Za-z0-9_]+\.py$/u,
  },
  ...[
    "approved-handoff",
    "runtime",
    "sdk-backend-protocol",
    "ticket-candidate",
  ].flatMap((contract) => [
    {
      directory: `contracts/${contract}/src`,
      pattern: /^[A-Za-z0-9_]+\.py$/u,
    },
    {
      directory: `contracts/${contract}/schemas`,
      pattern: /^[a-z0-9][a-z0-9-]*\.schema\.json$/u,
    },
  ]),
];
const expectedInputPaths = new Set([
  ...exactPaths,
  "contracts/approved-handoff/schemas/agent-trial.schema.json",
  "contracts/approved-handoff/schemas/approved-handoff.schema.json",
  "contracts/approved-handoff/schemas/build-identity.schema.json",
  "contracts/approved-handoff/schemas/evidence-item.schema.json",
  "contracts/approved-handoff/schemas/evidence-manifest.schema.json",
  "contracts/approved-handoff/schemas/execution-assertion.schema.json",
  "contracts/approved-handoff/schemas/execution-revocations.schema.json",
  "contracts/approved-handoff/schemas/registry-assertion.schema.json",
  "contracts/approved-handoff/src/handoff_contract.py",
  "contracts/runtime/schemas/capture-upload-manifest.schema.json",
  "contracts/runtime/schemas/common.schema.json",
  "contracts/runtime/schemas/diagnostic-envelope.schema.json",
  "contracts/runtime/schemas/processing-job.schema.json",
  "contracts/runtime/schemas/ticket-candidate.schema.json",
  "contracts/runtime/src/runtime_contract.py",
  "contracts/sdk-backend-protocol/schemas/build-identity.schema.json",
  "contracts/sdk-backend-protocol/schemas/capture-scope.schema.json",
  "contracts/sdk-backend-protocol/schemas/common.schema.json",
  "contracts/sdk-backend-protocol/schemas/completion-receipt.schema.json",
  "contracts/sdk-backend-protocol/schemas/completion-request.schema.json",
  "contracts/sdk-backend-protocol/schemas/deletion-request.schema.json",
  "contracts/sdk-backend-protocol/schemas/deletion-tombstone.schema.json",
  "contracts/sdk-backend-protocol/schemas/diagnostic-upload-receipt.schema.json",
  "contracts/sdk-backend-protocol/schemas/diagnostic-upload-request.schema.json",
  "contracts/sdk-backend-protocol/schemas/launch-exchange-receipt.schema.json",
  "contracts/sdk-backend-protocol/schemas/launch-exchange-request.schema.json",
  "contracts/sdk-backend-protocol/schemas/segment-upload-intent.schema.json",
  "contracts/sdk-backend-protocol/schemas/segment-upload-receipt.schema.json",
  "contracts/sdk-backend-protocol/src/protocol_contract.py",
  "contracts/ticket-candidate/schemas/common.schema.json",
  "contracts/ticket-candidate/schemas/candidate-replacement-request.schema.json",
  "contracts/ticket-candidate/schemas/candidate-replacement-response.schema.json",
  "contracts/ticket-candidate/schemas/ticket-candidate.schema.json",
  "contracts/ticket-candidate/src/candidate_replacement_contract.py",
  "contracts/ticket-candidate/src/ticket_candidate_contract.py",
  "services/backend/src/tacua_backend/__init__.py",
  "services/backend/src/tacua_backend/__main__.py",
  "services/backend/src/tacua_backend/candidate_domain.py",
  "services/backend/src/tacua_backend/candidate_store.py",
  "services/backend/src/tacua_backend/config.py",
  "services/backend/src/tacua_backend/config_tool.py",
  "services/backend/src/tacua_backend/contracts.py",
  "services/backend/src/tacua_backend/evidence_domain.py",
  "services/backend/src/tacua_backend/handoff_export.py",
  "services/backend/src/tacua_backend/handoff_store.py",
  "services/backend/src/tacua_backend/http_api.py",
  "services/backend/src/tacua_backend/instance_lock.py",
  "services/backend/src/tacua_backend/operator_tool.py",
  "services/backend/src/tacua_backend/processing_adapter.py",
  "services/backend/src/tacua_backend/processing_bridge.py",
  "services/backend/src/tacua_backend/processing_jobs.py",
  "services/backend/src/tacua_backend/processing_worker.py",
  "services/backend/src/tacua_backend/service.py",
]);
const expectedCopyBodies = [
  "--chown=root:root LICENSE NOTICE /app/",
  "--chown=root:root services/backend/src/tacua_backend/*.py /app/services/backend/src/tacua_backend/",
  "--chown=root:root --chmod=0555 services/backend/scripts/run_compose_isolated_processing.py services/backend/scripts/run_isolated_processor.py /app/services/backend/scripts/",
  "--chown=root:root services/backend/config.example.json services/backend/config.template.example.json /app/services/backend/",
  "--chown=root:root contracts/sdk-backend-protocol/src/*.py /app/contracts/sdk-backend-protocol/src/",
  "--chown=root:root contracts/sdk-backend-protocol/schemas/*.schema.json /app/contracts/sdk-backend-protocol/schemas/",
  "--chown=root:root contracts/runtime/src/*.py /app/contracts/runtime/src/",
  "--chown=root:root contracts/runtime/schemas/*.schema.json /app/contracts/runtime/schemas/",
  "--chown=root:root contracts/ticket-candidate/src/*.py /app/contracts/ticket-candidate/src/",
  "--chown=root:root contracts/ticket-candidate/schemas/*.schema.json /app/contracts/ticket-candidate/schemas/",
  "--chown=root:root contracts/approved-handoff/src/*.py /app/contracts/approved-handoff/src/",
  "--chown=root:root contracts/approved-handoff/schemas/*.schema.json /app/contracts/approved-handoff/schemas/",
];
const expectedInstructions = [
  ["FROM", expectedBase],
  [
    "LABEL",
    'org.opencontainers.image.title="Tacua backend" org.opencontainers.image.description="Self-hosted SDK capture transport and processing queue" org.opencontainers.image.licenses="Apache-2.0"',
  ],
  [
    "ENV",
    "PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app/services/backend/src TMPDIR=/var/lib/tacua/tmp",
  ],
  [
    "RUN",
    "groupadd --gid 10001 tacua && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tacua && install -d -o tacua -g tacua -m 0700 /var/lib/tacua /var/lib/tacua/tmp",
  ],
  ["WORKDIR", "/app"],
  ...expectedCopyBodies.map((body) => ["COPY", body]),
  ["USER", "10001:10001"],
  ["VOLUME", '["/var/lib/tacua"]'],
  ["EXPOSE", "8080"],
  [
    "HEALTHCHECK",
    '--interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["python", "-c", "import json,urllib.request; d=json.load(urllib.request.urlopen(\'http://127.0.0.1:8080/healthz\', timeout=2)); assert d[\'status\']==\'ok\' and d[\'retention_worker_running\'] and d[\'pending_deletions\']==0 and d[\'retention_last_failed_sessions\']==0"]',
  ],
  ["ENTRYPOINT", '["python", "-m", "tacua_backend"]'],
  [
    "CMD",
    '["--config-file", "/run/tacua/config.json", "--admin-secret-file", "/run/secrets/tacua_admin"]',
  ],
];
const expectedIgnoreRules = new Set([
  "**",
  "!LICENSE",
  "!NOTICE",
  "!services/",
  "!services/backend/",
  "!services/backend/src/",
  "!services/backend/src/tacua_backend/",
  "!services/backend/src/tacua_backend/*.py",
  "!services/backend/scripts/",
  "!services/backend/scripts/run_compose_isolated_processing.py",
  "!services/backend/scripts/run_isolated_processor.py",
  "!services/backend/config.example.json",
  "!services/backend/config.template.example.json",
  "!contracts/",
  "!contracts/runtime/",
  "!contracts/runtime/src/",
  "!contracts/runtime/src/*.py",
  "!contracts/runtime/schemas/",
  "!contracts/runtime/schemas/*.schema.json",
  "!contracts/sdk-backend-protocol/",
  "!contracts/sdk-backend-protocol/src/",
  "!contracts/sdk-backend-protocol/src/*.py",
  "!contracts/sdk-backend-protocol/schemas/",
  "!contracts/sdk-backend-protocol/schemas/*.schema.json",
  "!contracts/ticket-candidate/",
  "!contracts/ticket-candidate/src/",
  "!contracts/ticket-candidate/src/*.py",
  "!contracts/ticket-candidate/schemas/",
  "!contracts/ticket-candidate/schemas/*.schema.json",
  "!contracts/approved-handoff/",
  "!contracts/approved-handoff/src/",
  "!contracts/approved-handoff/src/*.py",
  "!contracts/approved-handoff/schemas/",
  "!contracts/approved-handoff/schemas/*.schema.json",
]);

function fail(message) {
  throw new Error(message);
}

function parseDockerInstructions(dockerfile) {
  if (/^\s*#\s*(?:check|escape|syntax)\s*=/imu.test(dockerfile)) {
    fail("backend Dockerfile must not select parser or frontend directives");
  }
  const instructions = [];
  let parts = [];
  for (const original of dockerfile.split(/\r?\n/u)) {
    const line = original.trim();
    if (!parts.length && (!line || line.startsWith("#"))) {
      continue;
    }
    if (parts.length && line.startsWith("#")) {
      continue;
    }
    if (!line) {
      fail("backend Dockerfile contains an invalid continued instruction");
    }
    const continued = line.endsWith("\\");
    parts.push(continued ? line.slice(0, -1).trimEnd() : line);
    if (continued) {
      continue;
    }
    const logical = parts.join(" ").trim();
    parts = [];
    const match = /^([A-Za-z]+)\s+([\s\S]+)$/u.exec(logical);
    if (!match) {
      fail("backend Dockerfile contains an invalid instruction");
    }
    instructions.push([match[1].toUpperCase(), match[2]]);
  }
  if (parts.length) {
    fail("backend Dockerfile ends in an incomplete instruction");
  }
  return instructions;
}

export function validateDockerDefinition(dockerfile, dockerignore) {
  const instructions = parseDockerInstructions(dockerfile);
  const fromBodies = instructions
    .filter(([name]) => name === "FROM")
    .map(([_name, body]) => body);
  if (fromBodies.length !== 1 || fromBodies[0] !== expectedBase) {
    fail("backend base image must use one exact Python patch and OCI digest");
  }
  const copyBodies = instructions
    .filter(([name]) => name === "COPY")
    .map(([_name, body]) => body);
  const expectedCopySet = new Set(expectedCopyBodies);
  if (
    copyBodies.length !== expectedCopyBodies.length ||
    new Set(copyBodies).size !== expectedCopyBodies.length ||
    copyBodies.some((body) => !expectedCopySet.has(body)) ||
    instructions.some(([name]) => name === "ADD")
  ) {
    fail("backend Dockerfile COPY boundary differs from the closed source policy");
  }
  if (
    instructions.length !== expectedInstructions.length ||
    instructions.some(
      ([name, body], index) =>
        name !== expectedInstructions[index][0] ||
        body !== expectedInstructions[index][1],
    )
  ) {
    fail("backend Dockerfile differs from the closed instruction policy");
  }

  const ignoreLines = dockerignore
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  const ignoreRules = new Set(ignoreLines);
  if (
    ignoreLines.length !== expectedIgnoreRules.size ||
    ignoreRules.size !== expectedIgnoreRules.size ||
    [...ignoreRules].some((line) => !expectedIgnoreRules.has(line))
  ) {
    fail("backend Docker build context is not restricted to source file types");
  }
}

export function validateInputRecords(records) {
  if (
    !Array.isArray(records) ||
    records.length < 1 ||
    records.length > MAX_BACKEND_IMAGE_INPUT_FILES
  ) {
    fail("backend image input file count is outside the release bound");
  }
  const names = new Set();
  let totalBytes = 0;
  for (const record of records) {
    if (
      !record ||
      typeof record.path !== "string" ||
      names.has(record.path) ||
      !expectedInputPaths.has(record.path) ||
      record.regular !== true ||
      record.symbolicLink !== false ||
      record.links !== 1 ||
      !Number.isSafeInteger(record.size) ||
      record.size < 1 ||
      record.size > MAX_BACKEND_IMAGE_INPUT_FILE_BYTES
    ) {
      fail("backend image contains an unsafe or oversized input file");
    }
    names.add(record.path);
    totalBytes += record.size;
  }
  if (
    totalBytes > MAX_BACKEND_IMAGE_INPUT_BYTES ||
    names.size !== expectedInputPaths.size ||
    [...expectedInputPaths].some((name) => !names.has(name))
  ) {
    fail("backend image input set is incomplete or exceeds its aggregate bound");
  }
  return totalBytes;
}

function record(relativePath) {
  const absolutePath = path.join(repositoryRoot, relativePath);
  const metadata = lstatSync(absolutePath);
  const resolvedRoot = `${realpathSync(repositoryRoot)}${path.sep}`;
  const resolved = realpathSync(absolutePath);
  if (!resolved.startsWith(resolvedRoot)) {
    fail(`backend image input escaped the repository: ${relativePath}`);
  }
  return {
    links: metadata.nlink,
    path: relativePath,
    regular: metadata.isFile(),
    size: metadata.size,
    symbolicLink: metadata.isSymbolicLink(),
  };
}

function collectRecords() {
  const records = exactPaths.map(record);
  for (const family of sourceFamilies) {
    for (const entry of readdirSync(path.join(repositoryRoot, family.directory), {
      withFileTypes: true,
    })) {
      if (family.pattern.test(entry.name)) {
        records.push(record(`${family.directory}/${entry.name}`));
      }
    }
  }
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

function main() {
  validateDockerDefinition(
    readFileSync(path.join(repositoryRoot, "services/backend/Dockerfile"), "utf8"),
    readFileSync(
      path.join(repositoryRoot, "services/backend/Dockerfile.dockerignore"),
      "utf8",
    ),
  );
  const records = collectRecords();
  const totalBytes = validateInputRecords(records);
  process.stdout.write(
    `${JSON.stringify({ files: records.length, status: "ok", totalBytes })}\n`,
  );
}

if (
  process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`backend image input validation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
