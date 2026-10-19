/**
 * cognium-dev #817 — flow-combo c01 JS deserialization FN (cross-file xfile shape).
 * Controller reads req.body; helper calls node-serialize.unserialize on the param.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — JS cross-file deserialization (c01)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `const { run } = require('./helper');

function handle(req) {
  const payload = req.body.payload;
  run(payload);
}

module.exports = { handle };
`;

  const helper = `const serialize = require('node-serialize');

function run(data) {
  return serialize.unserialize(data);
}

module.exports = { run };
`;

  it('cross-file http_body → helper deserialization sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
      { code: controller, filePath: 'controller.js', language: 'javascript' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'deserialization');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.js' && p.sink.file === 'helper.js',
    );
    expect(xfile, 'expected controller.js → helper.js deserialization').toBeTruthy();
  });

  it('helper alone — no spurious deserialization without tainted param', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
    ]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'deserialization');
    expect(flows).toHaveLength(0);
  });
});
