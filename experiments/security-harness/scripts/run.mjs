#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateResults } from '../src/harness.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const harnessRoot = resolve(scriptDir, '..');
const outputRoot = resolve(process.argv[2] ?? `${harnessRoot}/../../artifacts/security-harness/EXP-004`);

const { results } = await generateResults({ harnessRoot, outputRoot });
process.stdout.write(
  `${JSON.stringify({
    experimentId: results.experimentId,
    phase: results.phase,
    status: results.status,
    exp004Complete: results.exp004Complete,
    summary: results.summary,
    outputRoot,
  })}\n`,
);

if (results.status !== 'local_contract_simulations_passed') process.exitCode = 1;
