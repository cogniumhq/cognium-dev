/**
 * Tests for release reporting to Cursor Rollouts.
 *
 * Run with `npm run test:scripts`. The reporter is a subprocess: the contract
 * is the exit code release.sh sees, and which service id it would record.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(HERE);
const SCRIPT = join(HERE, 'report-rollouts.sh');
const RELEASE = join(REPO, 'release.sh');
const BASH = '/bin/bash';

const cleanup = [];
test.after(() => { for (const d of cleanup) rmSync(d, { recursive: true, force: true }); });

function toolDir({ curl = false, jq = false, releaseTools = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'rollouts-path-'));
  cleanup.push(dir);
  const stub = '#!/bin/sh\nexit 0\n';
  writeFileSync(join(dir, 'bash'), '#!/bin/sh\nexec /bin/bash "$@"\n', { mode: 0o755 });
  if (curl) writeFileSync(join(dir, 'curl'), stub, { mode: 0o755 });
  if (jq) writeFileSync(join(dir, 'jq'), stub, { mode: 0o755 });
  if (releaseTools) {
    for (const name of ['bun', 'node', 'npm', 'gh']) {
      writeFileSync(join(dir, name), stub, { mode: 0o755 });
    }
  }
  return dir;
}

function reporterFixture(exitCode = 0) {
  const root = mkdtempSync(join(tmpdir(), 'rollouts-repo-'));
  cleanup.push(root);
  const calls = join(root, 'calls');
  mkdirSync(join(root, 'scripts'));
  writeFileSync(join(root, 'scripts/report-rollouts-deployment.sh'), `#!/bin/sh
printf '%s %s\\n' "$CHANGE_MONITOR_SERVICE" "$1" >> ${JSON.stringify(calls)}
exit ${exitCode}
`, { mode: 0o755 });
  return { root, calls };
}

function readCalls(calls) {
  try {
    return readFileSync(calls, 'utf8').split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

function runReport(service, action, { curl = true, jq = true, key = 'test-key', stubExit = 0 } = {}) {
  const { root, calls } = reporterFixture(stubExit);
  const env = {
    PATH: toolDir({ curl, jq }),
    REPO_ROOT: root,
    HOME: process.env.HOME,
  };
  if (key != null) env.CURSOR_API_KEY = key;
  let code = 0;
  let stdout = '';
  let stderr = '';
  try {
    stdout = execFileSync(BASH, [SCRIPT, service, action], {
      encoding: 'utf8',
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    code = error.status ?? 1;
    stdout = error.stdout?.toString() ?? '';
    stderr = error.stderr?.toString() ?? '';
  }
  return { code, stdout, stderr, output: `${stdout}\n${stderr}`, calls: readCalls(calls) };
}

test('a directory service id is skipped and nothing is recorded', () => {
  const result = runReport('packages/circle-ir', 'bootstrap');
  assert.equal(result.code, 0);
  assert.match(result.output, /single slug/);
  assert.deepEqual(result.calls, []);
});

test('package names from this repo are single slugs that get recorded', () => {
  const circleIr = execFileSync('node', ['-p', "require('./packages/circle-ir/package.json').name"], {
    cwd: REPO,
    encoding: 'utf8',
  }).trim();
  const cli = execFileSync('node', ['-p', "require('./packages/cli/package.json').name"], {
    cwd: REPO,
    encoding: 'utf8',
  }).trim();
  assert.equal(circleIr, 'circle-ir');
  assert.equal(cli, 'cognium-dev');
  assert.equal(circleIr.includes('/'), false);
  assert.equal(cli.includes('/'), false);

  const lib = runReport(circleIr, 'bootstrap');
  const app = runReport(cli, 'start');
  assert.equal(lib.code, 0);
  assert.equal(app.code, 0);
  assert.deepEqual(lib.calls, ['circle-ir bootstrap']);
  assert.deepEqual(app.calls, ['cognium-dev start']);
});

test('release.sh reports package names, not package directories', () => {
  const release = readFileSync(RELEASE, 'utf8');
  assert.match(release, /LIB_SERVICE="\$\(node -p "require\('\.\/\$LIB_DIR\/package\.json'\)\.name"\)"/);
  assert.match(release, /CLI_SERVICE="\$\(node -p "require\('\.\/\$CLI_DIR\/package\.json'\)\.name"\)"/);
  assert.match(release, /report_rollouts "\$LIB_SERVICE"/);
  assert.match(release, /report_rollouts "\$CLI_SERVICE"/);
  assert.doesNotMatch(release, /report_rollouts "\$LIB_DIR"/);
  assert.doesNotMatch(release, /report_rollouts "\$CLI_DIR"/);
});

test('missing curl does not fail the report', () => {
  const result = runReport('circle-ir', 'bootstrap', { curl: false, jq: true });
  assert.equal(result.code, 0);
  assert.match(result.output, /curl and jq are required/);
  assert.deepEqual(result.calls, []);
});

test('missing jq does not fail the report', () => {
  const result = runReport('cognium-dev', 'finish', { curl: true, jq: false });
  assert.equal(result.code, 0);
  assert.match(result.output, /curl and jq are required/);
  assert.deepEqual(result.calls, []);
});

test('missing curl and jq do not abort release.sh', () => {
  const release = readFileSync(RELEASE, 'utf8');
  const hook = release.indexOf('RELEASE_STOP_AFTER_PREREQ');
  assert.ok(hook > 0, 'release.sh must stop after prerequisites when RELEASE_STOP_AFTER_PREREQ is set');
  const beforeHook = release.slice(0, hook);
  assert.doesNotMatch(beforeHook, /command -v curl/);
  assert.doesNotMatch(beforeHook, /command -v jq/);
  assert.match(release, /RELEASE_STOP_AFTER_PREREQ:-[\s\S]*exit 0/);

  let code = 0;
  let stdout = '';
  let stderr = '';
  try {
    stdout = execFileSync(BASH, [RELEASE, 'patch'], {
      encoding: 'utf8',
      cwd: REPO,
      timeout: 5000,
      env: {
        PATH: toolDir({ releaseTools: true }),
        HOME: process.env.HOME,
        RELEASE_STOP_AFTER_PREREQ: '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    code = error.status ?? 1;
    stdout = error.stdout?.toString() ?? '';
    stderr = error.stderr?.toString() ?? '';
  }
  assert.equal(code, 0, `${stdout}\n${stderr}`);
  assert.match(stdout, /Prerequisites OK/);
});

test('a reporter failure does not fail the caller', () => {
  const result = runReport('circle-ir', 'bootstrap', { stubExit: 1 });
  assert.equal(result.code, 0);
  assert.match(result.output, /returned 1/);
  assert.deepEqual(result.calls, ['circle-ir bootstrap']);
});
