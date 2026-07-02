import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #223 — aisec safe-mirror regressions REG-144-17..20.
 *
 * REG-144-17/18/19: JS/TS false-positive command_injection on
 *   safely bounded `child_process.execFile('tool', args)` where the
 *   `tool` slot is guarded by an allowlist (`ALLOWED.includes(v)` /
 *   `SET.has(v)` / `arr.indexOf(v) < 0`) with an early throw/return.
 *
 * REG-144-20: JS/TS false-positive path_traversal on
 *   `path.resolve(root, name)` (or `path.join`) followed by
 *   `!full.startsWith(root)` guard with early throw/return before
 *   `fs.readFile(full)` (or similar).
 *
 * Both regressions surfaced against the aisec safe-mirror corpus at
 * v3.144.0 where the harness reports concrete finding IDs. These
 * tests lock the "no flow" property against synthetic fixtures
 * carrying the reported shapes, plus recall guards to ensure the
 * unguarded variants still fire.
 */
describe('cognium-dev #223 — aisec safe mirrors', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // -------------------------------------------------------------------
  // REG-144-20 — path.resolve + startsWith path-traversal escape
  // -------------------------------------------------------------------

  it('REG-144-20: path.resolve + startsWith guard suppresses path_traversal', async () => {
    const code = `
const path = require('path');
const fs = require('fs');
const ROOT = '/var/data';

module.exports.read = function (req, res) {
  const name = req.query.name;
  const full = path.resolve(ROOT, name);
  if (!full.startsWith(ROOT)) {
    throw new Error('escape');
  }
  return fs.readFileSync(full);
};
`;
    const ir = await analyze(code, 'safe-read.js', 'javascript');
    const flows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'path_traversal',
    );
    expect(flows.length).toBe(0);
  });

  it('REG-144-20: recall guard — no startsWith guard, sink is still detected', async () => {
    // Baseline: without the guard the sanitizer must NOT be emitted so
    // that a downstream propagation improvement can still fire. We
    // assert at the sink level (guaranteed to be present) — a full
    // taint flow through `path.resolve` is a separate engine concern
    // tracked outside this ticket.
    const code = `
const path = require('path');
const fs = require('fs');
const ROOT = '/var/data';

module.exports.read = function (req, res) {
  const name = req.query.name;
  const full = path.resolve(ROOT, name);
  return fs.readFileSync(full);
};
`;
    const ir = await analyze(code, 'unsafe-read.js', 'javascript');
    const sinks = (ir.taint.sinks ?? []).filter(
      s => s.type === 'path_traversal',
    );
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('REG-144-20: path.join + startsWith guard also suppresses path_traversal', async () => {
    const code = `
const path = require('path');
const fs = require('fs');
const ROOT = '/var/data';

module.exports.read = function (req) {
  const name = req.query.name;
  const full = path.join(ROOT, name);
  if (!full.startsWith(ROOT)) throw new Error('escape');
  return fs.readFileSync(full);
};
`;
    const ir = await analyze(code, 'safe-join.js', 'javascript');
    const flows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'path_traversal',
    );
    expect(flows.length).toBe(0);
  });

  // -------------------------------------------------------------------
  // REG-144-17/18/19 — bounded exec via allowlist guard
  // -------------------------------------------------------------------

  it('REG-144-17: ALLOWED.includes() guard + execFile suppresses command_injection', async () => {
    const code = `
const { execFile } = require('child_process');
const ALLOWED = ['npm', 'yarn', 'pnpm'];

module.exports.run = function (req, res) {
  const tool = req.query.tool;
  if (!ALLOWED.includes(tool)) {
    throw new Error('unknown tool');
  }
  execFile(tool, ['install']);
};
`;
    const ir = await analyze(code, 'safe-exec.js', 'javascript');
    const flows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(flows.length).toBe(0);
  });

  it('REG-144-18: Set.has() guard + execFile suppresses command_injection', async () => {
    const code = `
const { execFile } = require('child_process');
const TOOLS = new Set(['npm', 'yarn', 'pnpm']);

module.exports.run = function (req) {
  const tool = req.query.tool;
  if (!TOOLS.has(tool)) throw new Error('unknown');
  execFile(tool, ['install']);
};
`;
    const ir = await analyze(code, 'safe-exec-set.js', 'javascript');
    const flows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(flows.length).toBe(0);
  });

  it('REG-144-19: indexOf() < 0 guard + execFile suppresses command_injection', async () => {
    const code = `
const { execFile } = require('child_process');
const CMDS = ['npm', 'yarn', 'pnpm'];

module.exports.run = function (req) {
  const tool = req.query.tool;
  if (CMDS.indexOf(tool) < 0) {
    throw new Error('unknown');
  }
  execFile(tool, ['install']);
};
`;
    const ir = await analyze(code, 'safe-exec-indexof.js', 'javascript');
    const flows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(flows.length).toBe(0);
  });

  it('REG-144-17: precision guard — arbitrary variable name is NOT an allowlist', async () => {
    // `data.includes(...)` on an unnamed variable must NOT emit the
    // command-allowlist sanitizer — the name doesn't look like an
    // allowlist (no SHOUTY_CASE and no "allowed"/"tools"/etc.
    // substring). Asserted directly against the sanitizer set: no
    // `js_command_allowlist_guard` entry should be present.
    const code = `
const { execFile } = require('child_process');

module.exports.run = function (req, data) {
  const tool = req.query.tool;
  if (!data.includes(tool)) {
    throw new Error('unknown');
  }
  execFile(tool, ['install']);
};
`;
    const ir = await analyze(code, 'unsafe-exec.js', 'javascript');
    const cmdAllow = (ir.taint.sanitizers ?? []).filter(
      s => s.type === 'js_command_allowlist_guard',
    );
    expect(cmdAllow.length).toBe(0);
  });

  it('REG-144-17: precision guard — allowlist without terminator does NOT sanitize', async () => {
    // The guard body must terminate (throw / return). A logging-only
    // guard body is not a real gate; the sanitizer must NOT be emitted
    // so recall stays intact once a flow-baseline improvement lands.
    const code = `
const { execFile } = require('child_process');
const ALLOWED = ['npm', 'yarn'];

module.exports.run = function (req) {
  const tool = req.query.tool;
  if (!ALLOWED.includes(tool)) {
    console.warn('unknown tool');
  }
  execFile(tool, ['install']);
};
`;
    const ir = await analyze(code, 'no-throw.js', 'javascript');
    const cmdAllow = (ir.taint.sanitizers ?? []).filter(
      s => s.type === 'js_command_allowlist_guard',
    );
    expect(cmdAllow.length).toBe(0);
  });
});
