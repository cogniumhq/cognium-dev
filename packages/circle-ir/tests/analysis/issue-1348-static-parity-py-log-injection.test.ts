/**
 * cognium-dev #1348 — static-parity py `log_injection`: a module-level
 * `on_login(user)` that logs its parameter must keep the flow, as the JS
 * `onLogin(user)` export does (#1151). The #292 bare-parameter gate dropped it.
 *
 * Mirrors the sast-validation manifest path
 * `python-vuln-demo/fpcorpus/log_injection_tp.py` (not vendored here).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const logInj = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'log_injection' && !f.sanitized);

/** Byte-aligned with the static-parity py fixture (`log_injection_tp.py`). */
const staticParityPy = `"""TP (CWE-117) — log injection: untrusted input logged unneutralized."""
import logging
log = logging.getLogger("app")
def on_login(user):
    log.info("login user=%s", user) if False else log.info("login user=" + user)  # SINK (CWE-117)
`;

const withLogin = (def: string, body = '    log.info("login user=" + user)\n') =>
  `import logging\nlog = logging.getLogger("app")\n${def}\n${body}`;

describe('#1348 static-parity py log_injection (module-level channel handler)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports log_injection on the static-parity py fixture', async () => {
    const ir = await analyze(staticParityPy, 'log_injection_tp.py', 'python');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });

  it('reports log_injection for a plain module-level on_login(user)', async () => {
    const ir = await analyze(withLogin('def on_login(user):'), 'app.py', 'python');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });

  it('keeps the flow when __all__ lists the handler', async () => {
    const ir = await analyze(`__all__ = ["on_login"]\n${withLogin('def on_login(user):')}`, 'app.py', 'python');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });

  it('stays gated when __all__ does not list the handler', async () => {
    const ir = await analyze(`__all__ = ["other"]\n${withLogin('def on_login(user):')}`, 'app.py', 'python');
    expect(logInj(ir)).toHaveLength(0);
  });

  it('stays gated for a private _on_login(user)', async () => {
    const ir = await analyze(withLogin('def _on_login(user):'), 'app.py', 'python');
    expect(logInj(ir)).toHaveLength(0);
  });

  it('stays gated for a function name outside the channel-handler set', async () => {
    const ir = await analyze(withLogin('def record(user):'), 'app.py', 'python');
    expect(logInj(ir)).toHaveLength(0);
  });

  it('stays gated for on_login without a request-shaped parameter', async () => {
    const ir = await analyze(withLogin('def on_login(name):', '    log.info("login user=" + name)\n'), 'app.py', 'python');
    expect(logInj(ir)).toHaveLength(0);
  });

  it('stays gated for an on_login method inside a class', async () => {
    const code = `import logging
log = logging.getLogger("app")
class Audit:
    def on_login(self, user):
        log.info("login user=" + user)
`;
    const ir = await analyze(code, 'app.py', 'python');
    expect(logInj(ir)).toHaveLength(0);
  });
});
