/**
 * Tests for cognium-dev #133 — info-disclosure-stacktrace (CWE-209)
 * FP suppression for two shapes:
 *
 *   1. JS `res.json({error: err.message})` — `.message` is a
 *      developer-controlled single-line description (e.g.
 *      `new Error('Validation failed')`), not a stack trace. The
 *      rule's canonical CWE-209 scope is stack-trace disclosure; the
 *      `.message` arm of `isExceptionExpression` is dropped.
 *      Additionally `argIsException` no longer short-circuits on a
 *      bare `arg.variable === 'err'` match when the expression text is
 *      a containing object literal — it defers to the regex on the
 *      full expression text. `.stack`, `.toString()`, `.getStackTrace()`,
 *      full error object, and `traceback.format_exc()` remain in scope.
 *
 *   2. Python `f.write(API_KEY)` where `f` came from `open(...)` (either
 *      `with open(path, 'w') as f:` or `f = open(path, 'w')`) within
 *      the prior 10 lines. File-handle writes are not response leaks.
 *      Implemented as a backward-scan guard inside
 *      `detectResponseLeakCall()`; never regresses real response leaks
 *      because response writers are never produced by `open(...)`.
 *
 * Recall lock: `res.json({error: err.stack})` and Python
 * `return traceback.format_exc()` continue to fire.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countStacktraceFindings = (
  findings: Array<{ rule_id?: string }> | undefined,
) =>
  (findings ?? []).filter((f) => f.rule_id === 'info-disclosure-stacktrace')
    .length;

describe('cognium-dev #133 — info-disclosure-stacktrace FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP-suppression: `.message` is not a stack trace
  // -------------------------------------------------------------------------

  it('JS — res.json({stdout, error: err.message}): no finding', async () => {
    const code = `const express = require('express');
const { execFile } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
  execFile('ping', ['-c', '1', '127.0.0.1'], (err, stdout) => {
    if (err) {
      return res.status(500).json({ ok: false, error: err.message });
    }
    res.json({ ok: true, stdout });
  });
});
`;
    const r = await analyze(code, 'safe_routes.js', 'javascript');
    expect(countStacktraceFindings(r.findings)).toBe(0);
  });

  it('JS — res.send("failed: " + err.message): no finding', async () => {
    const code = `const express = require('express');
const app = express();

app.get('/work', (_req, res) => {
  try {
    doWork();
  } catch (err) {
    res.status(500).send('failed: ' + err.message);
  }
});

function doWork() { throw new Error('bad'); }
`;
    const r = await analyze(code, 'safe.js', 'javascript');
    expect(countStacktraceFindings(r.findings)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // FP-suppression: Python file-handle writes
  // -------------------------------------------------------------------------

  it('Python — with open(path,"w") as f: f.write(API_KEY): no finding', async () => {
    const code = `import os

API_KEY = os.environ["API_KEY"]

def save_secret(path: str) -> None:
    def _opener(p, flags):
        return os.open(p, flags, 0o600)
    with open(path, 'w', opener=_opener) as f:
        f.write(API_KEY)
`;
    const r = await analyze(code, 'safe_sensitive_info_exposure.py', 'python');
    expect(countStacktraceFindings(r.findings)).toBe(0);
  });

  it('Python — f = open(path,"w"); f.write(SECRET); f.close(): no finding', async () => {
    const code = `import os

SECRET = os.environ.get("SECRET", "")

def persist(path: str) -> None:
    f = open(path, 'w')
    f.write(SECRET)
    f.close()
`;
    const r = await analyze(code, 'persist.py', 'python');
    expect(countStacktraceFindings(r.findings)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall: real stack-trace disclosures still fire
  // -------------------------------------------------------------------------

  it('Recall — JS res.json({error: err.stack}): emits finding', async () => {
    const code = `const express = require('express');
const app = express();

app.get('/leak', (_req, res) => {
  try {
    throw new Error('boom');
  } catch (err) {
    res.status(500).json({ error: err.stack });
  }
});
`;
    const r = await analyze(code, 'leak.js', 'javascript');
    expect(countStacktraceFindings(r.findings)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — Python return traceback.format_exc() in handler: emits finding', async () => {
    const code = `import traceback
from flask import Flask

app = Flask(__name__)

@app.route('/leak')
def leak():
    try:
        raise RuntimeError('boom')
    except Exception:
        return traceback.format_exc()
`;
    const r = await analyze(code, 'leak.py', 'python');
    expect(countStacktraceFindings(r.findings)).toBeGreaterThanOrEqual(1);
  });
});
