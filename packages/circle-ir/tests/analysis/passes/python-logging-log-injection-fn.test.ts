/**
 * Sprint 53 — cognium-dev #193: Python `logging.Logger.<level>(fmt, *args)`
 * positional-arg log_injection FN.
 *
 * `log.warning("login user=%s", user)` does not flag CWE-117 when the
 * format string is constant and the taint flows through positional args
 * (`user` at position 1). Existing sink registry in
 * `config-loader.ts:1744-1757` registers `logger.warning` / `logging.warning`
 * with `arg_positions: [0]` only — the format string at position 0 is
 * constant, so taint in positions 1..N is invisible.
 *
 * Fix shape (Phase 3): extend `arg_positions` to `[0, 1, 2, 3, 4]` on
 * every Python `logging.Logger.<level>` entry so taint at any of the
 * first five positional slots flags. Python's logging format-string
 * mechanism interpolates positional args into the message via `%`
 * substitution — taint in any positional arg ends up rendered into the
 * log line and is therefore an injection vector.
 *
 * Recall locks: literal-arg-only calls produce zero flows.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countLogSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'log_injection').length;
const countLogFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'log_injection').length;

describe('cognium-dev #193 — Python logging.Logger positional-arg log_injection FN', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FN — log.warning("user=%s", user) with tainted user fires log_injection', async () => {
    const code = `import logging
from flask import Flask, request
app = Flask(__name__)
log = logging.getLogger("app")

@app.route("/login")
def login():
    user = request.args.get("u", "")
    log.warning("login user=%s", user)
    return "ok"
`;
    const r = await analyze(code, 'app.py', 'python');
    expect(countLogSinks(r.taint?.sinks)).toBeGreaterThan(0);
    expect(countLogFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('FN — log.error(fmt, ip, user) with tainted user in arg 2 fires log_injection', async () => {
    const code = `import logging
from flask import Flask, request
app = Flask(__name__)
log = logging.getLogger("app")

@app.route("/err")
def err():
    user = request.args.get("u", "")
    ip = "127.0.0.1"
    log.error("ip=%s user=%s", ip, user)
    return "ok"
`;
    const r = await analyze(code, 'app2.py', 'python');
    expect(countLogFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — log.warning("startup complete") constant only produces zero log_injection', async () => {
    const code = `import logging
log = logging.getLogger("app")
log.warning("startup complete")
`;
    const r = await analyze(code, 'boot.py', 'python');
    expect(countLogFlows(r.taint?.flows)).toBe(0);
  });

  it('recall — log.warning("user=%s", "anonymous") literal arg produces zero log_injection', async () => {
    const code = `import logging
log = logging.getLogger("app")
log.warning("user=%s", "anonymous")
`;
    const r = await analyze(code, 'boot2.py', 'python');
    expect(countLogFlows(r.taint?.flows)).toBe(0);
  });
});
