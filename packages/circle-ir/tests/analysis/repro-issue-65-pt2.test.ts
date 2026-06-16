/**
 * Repro for cognium-dev#65 part 2 — Python `shlex.quote` lost through `+` concat.
 *
 * Before the fix, the engine reported a `command_injection` flow for code
 * like:
 *
 *   host = request.args.get("host", "")
 *   cmd  = "ping -c 3 " + shlex.quote(host)
 *   subprocess.run(cmd, shell=True, ...)
 *
 * The `shlex.quote()` sanitizer at the assignment line was correctly
 * detected (`taint.sanitizers` listed it as covering `command_injection`)
 * but the alias `cmd` produced by `buildPythonTaintedVars` was emitted as
 * an unsanitized source by `detectExpressionScanFlows`, so the flow on
 * the next line came through with `sanitized: false`.
 *
 * Fix (taint-propagation-pass.ts): when the alias-creation line carries a
 * sanitizer whose method name appears in the RHS, record the sink types
 * it covers per alias and suppress matching expression-scan flows.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#65 pt2 — Python shlex.quote concat sanitizer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasCmdiFlow = (flows: Array<{ sink_type?: string }> | undefined) =>
    (flows ?? []).some((f) => f.sink_type === 'command_injection');

  it('FP: cmd = "ping " + shlex.quote(host); subprocess.run(cmd, shell=True) — must NOT flag', async () => {
    const code = `
import shlex
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    cmd = "ping -c 3 " + shlex.quote(host)
    subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
`;
    const r = await analyze(code, 'fp.py', 'python');
    expect(hasCmdiFlow(r.taint.flows)).toBe(false);
  });

  it('FP: f-string alias with shlex.quote — must NOT flag', async () => {
    // Same root cause through Python f-string interpolation rather than `+`.
    const code = `
import shlex
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    cmd = f"ping -c 3 {shlex.quote(host)}"
    subprocess.run(cmd, shell=True)
`;
    const r = await analyze(code, 'fp_fstr.py', 'python');
    expect(hasCmdiFlow(r.taint.flows)).toBe(false);
  });

  it('TP regression: no sanitizer, raw concat — must STILL flag', async () => {
    const code = `
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    cmd = "ping -c 3 " + host
    subprocess.run(cmd, shell=True)
`;
    const r = await analyze(code, 'tp.py', 'python');
    expect(hasCmdiFlow(r.taint.flows)).toBe(true);
  });

  it('TP regression: shlex.quote sanitizes command_injection but NOT sql_injection', async () => {
    // The per-alias sanitizer coverage must be sink-type-aware. shlex.quote
    // covers command_injection only; if the alias later flows to an SQL
    // sink, the SQLi flow must NOT be suppressed.
    const code = `
import shlex
from flask import request
def handler():
    name = request.args.get("name", "")
    q = "SELECT * FROM users WHERE name = '" + shlex.quote(name) + "'"
    cur.execute(q)
`;
    const r = await analyze(code, 'tp_sqli.py', 'python');
    const sqliFlows = (r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection');
    expect(sqliFlows.length).toBeGreaterThanOrEqual(1);
  });

  it('TP regression: bare shlex.quote call without assignment does not sanitize source', async () => {
    // `shlex.quote(host)` alone (no assignment, not feeding the sink) does
    // NOT sanitize the underlying `host` variable. If `host` itself reaches
    // a command-injection sink, the flow must still fire.
    const code = `
import shlex
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    _ = shlex.quote(host)
    subprocess.run("ping -c 3 " + host, shell=True)
`;
    const r = await analyze(code, 'tp_bare.py', 'python');
    expect(hasCmdiFlow(r.taint.flows)).toBe(true);
  });
});
