#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { loadJson, scanForCanaries, scanPathsForProhibitedCanaries, stableStringify } from '../src/harness.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const harnessRoot = resolve(scriptDir, '..');
const outputRoot = resolve(process.argv[2] ?? `${harnessRoot}/../../artifacts/security-harness/EXP-004`);
const catalogue = await loadJson(resolve(harnessRoot, 'fixtures/canaries.json'));
const results = await loadJson(resolve(outputRoot, 'run-results.json'));
const matrix = await loadJson(resolve(outputRoot, 'egress-matrix.json'));
const coverage = await loadJson(resolve(outputRoot, 'coverage.json'));
const findings = await scanPathsForProhibitedCanaries([outputRoot], catalogue);
const fixtureRoot = resolve(harnessRoot, 'fixtures');
const fixtureFiles = (await readdir(fixtureRoot)).filter((name) => name.endsWith('.json')).sort();
const fixtureFindings = [];
for (const name of fixtureFiles) {
  const content = await readFile(join(fixtureRoot, name), 'utf8');
  for (const finding of scanForCanaries(content, catalogue)) fixtureFindings.push({ name, ...finding });
}
const unexpectedFixtureFindings = fixtureFindings.filter(({ name }) => name !== 'canaries.json');

const checks = {
  localRunPassed: results.status === 'local_contract_simulations_passed',
  exp004NotMisrepresentedComplete: results.exp004Complete === false,
  allDataClassesPresent: new Set(matrix.rows.map(({ dataClass }) => dataClass)).size === 12,
  allDestinationsPresent: new Set(matrix.rows.map(({ destination }) => destination)).size === 11,
  matrixCellCountMatches: matrix.cellCount === coverage.summary.matrixCellCount,
  everyMatrixCellReported: coverage.matrixCells.length === matrix.cellCount,
  noProhibitedCanaryInGeneratedArtifacts: findings.length === 0,
  prohibitedFixtureValuesConfinedToCatalogue: unexpectedFixtureFindings.length === 0,
};

process.stdout.write(
  `${stableStringify(
    {
      checks,
      generatedArtifactFindingIds: findings.map(({ id }) => id),
      fixtureCatalogueFindingCount: fixtureFindings.filter(({ name }) => name === 'canaries.json').length,
      unexpectedFixtureFindingIds: unexpectedFixtureFindings.map(({ id }) => id),
    },
    2,
  )}\n`,
);
if (Object.values(checks).some((value) => value !== true)) process.exitCode = 1;
