// SPDX-License-Identifier: Apache-2.0

import {
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");

const baseImage =
  "docker.io/library/debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd";
const whisperRevision = "f24588a272ae8e23280d9c220536437164e6ed28";
const expectedInstructions = [
  ["ARG", `DEBIAN_IMAGE=${baseImage}`],
  ["FROM", "${DEBIAN_IMAGE} AS whisper-build"],
  ["ARG", `WHISPER_CPP_REV=${whisperRevision}`],
  [
    "RUN",
    "apt-get update && apt-get install -y --no-install-recommends ca-certificates cmake g++ git make && rm -rf /var/lib/apt/lists/*",
  ],
  [
    "RUN",
    "git init /src/whisper.cpp && git -C /src/whisper.cpp remote add origin https://github.com/ggml-org/whisper.cpp.git && git -C /src/whisper.cpp fetch --depth 1 origin \"${WHISPER_CPP_REV}\" && test \"$(git -C /src/whisper.cpp rev-parse FETCH_HEAD)\" = \"${WHISPER_CPP_REV}\" && git -C /src/whisper.cpp checkout --detach FETCH_HEAD",
  ],
  [
    "RUN",
    "cmake -S /src/whisper.cpp -B /src/whisper.cpp/build -DCMAKE_BUILD_TYPE=Release -DWHISPER_BUILD_TESTS=OFF -DWHISPER_BUILD_SERVER=OFF -DWHISPER_CURL=OFF -DBUILD_SHARED_LIBS=OFF -DGGML_NATIVE=OFF -DGGML_OPENMP=OFF && cmake --build /src/whisper.cpp/build --config Release --target whisper-cli -j2",
  ],
  ["FROM", "${DEBIAN_IMAGE} AS runtime"],
  [
    "RUN",
    "apt-get update && apt-get install -y --no-install-recommends ffmpeg python3 && rm -rf /var/lib/apt/lists/*",
  ],
  [
    "COPY",
    "--from=whisper-build /src/whisper.cpp/build/bin/whisper-cli /usr/local/bin/whisper-cli",
  ],
  [
    "COPY",
    "--from=whisper-build /src/whisper.cpp/LICENSE /usr/share/doc/whisper.cpp/LICENSE",
  ],
  ["RUN", "install -d -m 0555 /usr/share/doc/tacua"],
  ["COPY", "--chmod=0444 LICENSE /usr/share/doc/tacua/LICENSE"],
  ["COPY", "--chmod=0444 NOTICE /usr/share/doc/tacua/NOTICE"],
  [
    "COPY",
    "--chmod=0444 services/processor/THIRD_PARTY_NOTICES.md /usr/share/doc/tacua/THIRD_PARTY_NOTICES.md",
  ],
  [
    "COPY",
    "--chmod=0555 services/processor/processor.py /usr/local/bin/tacua-offline-processor",
  ],
  ["FROM", "scratch"],
  ["COPY", "--from=runtime / /"],
  ["ENV", "LANG=C.UTF-8"],
  ["ENV", "LC_ALL=C.UTF-8"],
  [
    "ENV",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  ],
];
const expectedIgnoreRules = new Set([
  "*",
  "!LICENSE",
  "!NOTICE",
  "!services/processor/processor.py",
  "!services/processor/THIRD_PARTY_NOTICES.md",
]);
const expectedInputs = [
  ["LICENSE", 1_048_576],
  ["NOTICE", 65_536],
  ["services/processor/processor.py", 262_144],
  ["services/processor/THIRD_PARTY_NOTICES.md", 65_536],
];

function fail(message) {
  throw new Error(message);
}

function parseDockerInstructions(dockerfile) {
  if (/^\s*#\s*(?:check|escape|syntax)\s*=/imu.test(dockerfile)) {
    fail("processor Dockerfile must not select parser or frontend directives");
  }
  const instructions = [];
  let parts = [];
  for (const original of dockerfile.split(/\r?\n/u)) {
    const line = original.trim();
    if (!parts.length && (!line || line.startsWith("#"))) continue;
    if (parts.length && line.startsWith("#")) continue;
    if (!line) fail("processor Dockerfile contains an invalid continuation");
    const continued = line.endsWith("\\");
    parts.push(continued ? line.slice(0, -1).trimEnd() : line);
    if (continued) continue;
    const logical = parts.join(" ").trim();
    parts = [];
    const match = /^([A-Za-z]+)\s+([\s\S]+)$/u.exec(logical);
    if (!match) fail("processor Dockerfile contains an invalid instruction");
    instructions.push([match[1].toUpperCase(), match[2]]);
  }
  if (parts.length) fail("processor Dockerfile ends in an incomplete instruction");
  return instructions;
}

export function validateProcessorDockerDefinition(dockerfile, dockerignore) {
  const instructions = parseDockerInstructions(dockerfile);
  if (
    instructions.length !== expectedInstructions.length
    || instructions.some(
      ([name, body], index) => (
        name !== expectedInstructions[index][0]
        || body !== expectedInstructions[index][1]
      ),
    )
    || instructions.some(([name]) => ["ADD", "CMD", "ENTRYPOINT"].includes(name))
  ) {
    fail("processor Dockerfile differs from the closed instruction policy");
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
    fail("processor Docker ignore boundary differs from the closed policy");
  }
}

function validateInput(root, relative, maximumBytes) {
  const absolute = path.join(root, relative);
  const metadata = lstatSync(absolute);
  if (
    realpathSync(absolute) !== absolute
    || !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1
    || (metadata.mode & 0o022) !== 0
    || metadata.size < 1
    || metadata.size > maximumBytes
  ) {
    fail(`processor image input is unsafe: ${relative}`);
  }
  const bytes = readFileSync(absolute);
  if (bytes.includes(0)) fail(`processor image input contains a NUL: ${relative}`);
  return bytes;
}

export function validateProcessorRepository(root = repositoryRoot) {
  validateProcessorDockerDefinition(
    readFileSync(path.join(root, "services/processor/Dockerfile"), "utf8"),
    readFileSync(
      path.join(root, "services/processor/Dockerfile.dockerignore"),
      "utf8",
    ),
  );
  const inputs = new Map(
    expectedInputs.map(([relative, maximumBytes]) => [
      relative,
      validateInput(root, relative, maximumBytes),
    ]),
  );
  const notices = inputs.get("services/processor/THIRD_PARTY_NOTICES.md")
    .toString("utf8");
  if (
    !notices.includes(whisperRevision)
    || !notices.includes("FFmpeg")
    || !notices.includes("Model weights are not redistributed")
  ) {
    fail("processor third-party notices do not bind the selected dependencies");
  }
  return {
    files: inputs.size,
    status: "ok",
    whisper_revision: whisperRevision,
  };
}

if (
  process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  process.stdout.write(`${JSON.stringify(validateProcessorRepository())}\n`);
}
