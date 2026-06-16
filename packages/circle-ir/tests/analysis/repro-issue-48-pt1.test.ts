/**
 * Repro for cognium-dev#48 part 1 — Python `subprocess.*` FP on safe shape.
 *
 * Before the fix, every call to `subprocess.run`, `subprocess.call`,
 * `subprocess.check_output`, `subprocess.check_call`, and `subprocess.Popen`
 * was emitted as a `command_injection` sink regardless of whether arg[0] was
 * a list literal or whether `shell=True` was passed. The flow detector then
 * paired it with any tainted variable in scope, producing false positives on
 * the canonical safe shape:
 *
 *   subprocess.run(["ping", "-c", "3", "--", host], shell=False, ...)
 *
 * Python invokes `execve(argv)` directly in that shape — there is no shell
 * to interpret metacharacters, so a tainted element in the list cannot
 * escape into shell injection.
 *
 * Fix (taint-matcher.ts): added `isSafePythonSubprocessCall` and a skip in
 * `findSinks`. The sink is suppressed when:
 *   - language === 'python'
 *   - pattern.type === 'command_injection'
 *   - pattern.class === 'subprocess'
 *   - arg[0] expression starts with `[`
 *   - no `shell=True` kwarg appears
 *
 * The single-string form (`subprocess.run("ping " + host)`) and any call
 * with `shell=True` (even with a list) continue to fire — those are real
 * arg-injection / shell-injection vectors per CWE-78.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#48 pt1 — Python subprocess safe-shape FP', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasCmdiFlow = (flows: Array<{ sink_type?: string }> | undefined) =>
    (flows ?? []).some((f) => f.sink_type === 'command_injection');

  const hasCmdiSink = (sinks: Array<{ type?: string }> | undefined) =>
    (sinks ?? []).some((s) => s.type === 'command_injection');

  it('FP: subprocess.run([list], shell=False) — must NOT flag', async () => {
    const code = `
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    result = subprocess.run(["ping", "-c", "3", "--", host],
                            shell=False, capture_output=True, timeout=10)
    return result.stdout
`;
    const r = await analyze(code, 'safe1.py', 'python');
    expect(hasCmdiSink(r.taint.sinks)).toBe(false);
    expect(hasCmdiFlow(r.taint.flows)).toBe(false);
  });

  it('FP: subprocess.run([list]) — default shell=False — must NOT flag', async () => {
    const code = `
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    subprocess.run(["ping", "-c", "3", host])
`;
    const r = await analyze(code, 'safe2.py', 'python');
    expect(hasCmdiSink(r.taint.sinks)).toBe(false);
    expect(hasCmdiFlow(r.taint.flows)).toBe(false);
  });

  it('FP: subprocess.Popen([list]) — must NOT flag', async () => {
    const code = `
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    p = subprocess.Popen(["ping", "-c", "3", host])
    p.wait()
`;
    const r = await analyze(code, 'safe3.py', 'python');
    expect(hasCmdiSink(r.taint.sinks)).toBe(false);
    expect(hasCmdiFlow(r.taint.flows)).toBe(false);
  });

  it('FP: subprocess.check_output([list]) — must NOT flag', async () => {
    const code = `
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    return subprocess.check_output(["dig", "+short", host])
`;
    const r = await analyze(code, 'safe4.py', 'python');
    expect(hasCmdiSink(r.taint.sinks)).toBe(false);
    expect(hasCmdiFlow(r.taint.flows)).toBe(false);
  });

  it('TP: subprocess.run("str " + tainted, shell=True) — must FLAG', async () => {
    const code = `
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    subprocess.run("ping -c 3 " + host, shell=True)
`;
    const r = await analyze(code, 'vuln1.py', 'python');
    expect(hasCmdiSink(r.taint.sinks)).toBe(true);
    expect(hasCmdiFlow(r.taint.flows)).toBe(true);
  });

  it('TP: subprocess.run("str " + tainted) default shell=False — single-string form, still FLAG', async () => {
    // The single-string form treats arg[0] as the executable name. If that
    // string is built from tainted input, an attacker controls which binary
    // (or path) is executed — still a CWE-78 vector even without a shell.
    const code = `
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    subprocess.run("ping " + host)
`;
    const r = await analyze(code, 'vuln2.py', 'python');
    expect(hasCmdiSink(r.taint.sinks)).toBe(true);
    expect(hasCmdiFlow(r.taint.flows)).toBe(true);
  });

  it('TP: subprocess.run([list], shell=True) — shell=True overrides safe-shape skip', async () => {
    const code = `
import subprocess
from flask import request
def handler():
    host = request.args.get("host", "")
    subprocess.run(["sh", "-c", "ping " + host], shell=True)
`;
    const r = await analyze(code, 'vuln3.py', 'python');
    expect(hasCmdiSink(r.taint.sinks)).toBe(true);
    expect(hasCmdiFlow(r.taint.flows)).toBe(true);
  });

  it('TP regression: os.system(tainted) — unrelated sink, must STILL flag', async () => {
    // Make sure the subprocess-specific skip does not leak into other
    // command_injection sinks (os.system, os.popen, etc.).
    const code = `
import os
from flask import request
def handler():
    host = request.args.get("host", "")
    os.system("ping " + host)
`;
    const r = await analyze(code, 'vuln_os.py', 'python');
    expect(hasCmdiSink(r.taint.sinks)).toBe(true);
    expect(hasCmdiFlow(r.taint.flows)).toBe(true);
  });
});
