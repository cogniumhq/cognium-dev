/**
 * Tests for the version bump in release.sh.
 *
 * Run with `npm run test:scripts`. Inside a workspace, `npm version` also
 * reifies the tree. Between the lib bump and the CLI pin update, circle-ir is
 * X+1 while packages/cli still pins circle-ir exactly to X, so npm installs
 * circle-ir@X from the registry into packages/cli/node_modules/circle-ir and
 * the CLI build guard (cognium-dev#383) refuses the release. Every
 * `npm version` call must skip that reify with --workspaces-update=false.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = dirname(dirname(fileURLToPath(import.meta.url)));
const RELEASE = join(REPO, 'release.sh');

function npmVersionCalls() {
  return readFileSync(RELEASE, 'utf8')
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .filter((line) => /\bnpm\s+version\b/.test(line));
}

test('release.sh bumps both the lib and the CLI with npm version', () => {
  const calls = npmVersionCalls();
  assert.equal(calls.length, 2, `expected 2 npm version calls, found:\n${calls.join('\n')}`);
  assert.ok(calls.some((line) => line.includes('"$LIB_DIR"')), 'lib bump missing');
  assert.ok(calls.some((line) => line.includes('"$CLI_DIR"')), 'CLI bump missing');
});

test('every npm version call in release.sh skips the workspace reify', () => {
  for (const line of npmVersionCalls()) {
    assert.match(line, /--workspaces-update=false\b/, `missing --workspaces-update=false:\n${line.trim()}`);
  }
});
