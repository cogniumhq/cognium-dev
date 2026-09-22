/**
 * #458 — a Python starred parameter name (`*args`, `**kwargs`,
 * `**httplib_request_kw`) reaches the cross-file resolver's tainted-var map,
 * and `*` is a regex quantifier. `new RegExp(`\b${name}\b`)` in
 * `CrossFileResolver.findTaintedParams` (and two sibling sites) threw
 * "Nothing to repeat", failing the whole project analysis closed via
 * `analyzeProject` / `analyzeForAPI`. Per-file `analyze()` never hit that path.
 *
 * These pin that starred names no longer crash the project pass, and that
 * ordinary cross-file param taint still resolves (the escape is transparent to
 * every normal identifier).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';

describe('#458 — Python starred-parameter names do not crash analyzeProject', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['**kwargs', 'def f(**kwargs):\n    os.system(kwargs["cmd"])\n'],
    ['*args', 'def f(*args):\n    os.system(args[0])\n'],
    ['both', 'def f(a, *args, **kwargs):\n    os.system(kwargs.get("cmd"))\n'],
    ['**httplib_request_kw', 'def request(method, url, **httplib_request_kw):\n    return httplib_request_kw\n'],
  ])('does not throw on %s', async (_n, body) => {
    const code = `import os\n${body}`;
    await expect(analyzeProject([{ filePath: 'a.py', language: 'python', code }])).resolves.toBeDefined();
    // per-file was never affected, but assert it too
    await expect(analyze(code, 'a.py', 'python')).resolves.toBeDefined();
  });

  it('a starred param mixed with a real cross-file flow still analyzes and keeps the flow', async () => {
    const r = await analyzeProject([
      {
        filePath: 'controller.py',
        language: 'python',
        code: `from helper import run
from flask import Flask, request
app = Flask(__name__)
@app.route('/s')
def s():
  u = request.args.get('u')
  return run(u)
`,
      },
      {
        filePath: 'helper.py',
        language: 'python',
        code: `import os
def run(cmd, *args, **kwargs):
    os.system(cmd)
`,
      },
    ]);
    // The point is: no throw, and the real controller->helper flow survives the
    // presence of `*args`/`**kwargs` on the same signature.
    const paths = r.taint_paths ?? [];
    expect(paths.some(p => p.source.file !== p.sink.file)).toBe(true);
  });
});
