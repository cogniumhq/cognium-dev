/**
 * cognium-dev #817 — flow-combo c01 Python open_redirect FN (cross-file xfile shape).
 * Controller reads request query; helper calls redirect on the param.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — Python cross-file open_redirect (c01)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `from flask import request
from helper import run

def handle():
    url = request.args.get("url")
    run(url)
`;

  const helper = `from flask import redirect

def run(target):
    return redirect(target)
`;

  it('cross-file http_query → helper open_redirect sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.py', language: 'python' },
      { code: controller, filePath: 'controller.py', language: 'python' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'open_redirect');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.py' && p.sink.file === 'helper.py',
    );
    expect(xfile, 'expected controller.py → helper.py open_redirect').toBeTruthy();
  });

  it('helper alone — no spurious open_redirect without tainted param', async () => {
    const r = await analyzeProject([{ code: helper, filePath: 'helper.py', language: 'python' }]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'open_redirect');
    expect(flows).toHaveLength(0);
  });
});
