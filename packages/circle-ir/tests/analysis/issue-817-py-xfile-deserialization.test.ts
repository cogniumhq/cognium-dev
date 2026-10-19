/**
 * cognium-dev #817 — flow-combo c01 Python deserialization FN (cross-file xfile shape).
 * Controller reads request body; helper calls pickle.loads on the param.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — Python cross-file deserialization (c01)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `from flask import request
from helper import run

def handle():
    payload = request.get_data()
    run(payload)
`;

  const helper = `import pickle

def run(data):
    return pickle.loads(data)
`;

  it('cross-file http_body → helper deserialization sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.py', language: 'python' },
      { code: controller, filePath: 'controller.py', language: 'python' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'deserialization');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.py' && p.sink.file === 'helper.py',
    );
    expect(xfile, 'expected controller.py → helper.py deserialization').toBeTruthy();

    const helperFlows = (r.files.find(f => f.file === 'helper.py')?.analysis.taint.flows ?? [])
      .filter(f => f.sink_type === 'deserialization');
    expect(helperFlows.length).toBeGreaterThanOrEqual(1);
  });

  it('helper alone — no spurious deserialization without tainted param', async () => {
    const r = await analyzeProject([{ code: helper, filePath: 'helper.py', language: 'python' }]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'deserialization');
    expect(flows).toHaveLength(0);
  });
});
