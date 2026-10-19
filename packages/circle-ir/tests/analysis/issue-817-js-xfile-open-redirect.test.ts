/**
 * cognium-dev #817 — flow-combo c01 JS open_redirect FN (cross-file xfile shape).
 * Controller reads req.query; helper calls res.redirect on the param.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — JS cross-file open_redirect (c01)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `const { run } = require('./helper');

function handle(req, res) {
  const url = req.query.url;
  run(res, url);
}

module.exports = { handle };
`;

  const helper = `function run(res, target) {
  res.redirect(target);
}

module.exports = { run };
`;

  it('cross-file http_query → helper open_redirect sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
      { code: controller, filePath: 'controller.js', language: 'javascript' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'open_redirect');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.js' && p.sink.file === 'helper.js',
    );
    expect(xfile, 'expected controller.js → helper.js open_redirect').toBeTruthy();

    const helperFlows = (r.files.find(f => f.file === 'helper.js')?.analysis.taint.flows ?? [])
      .filter(f => f.sink_type === 'open_redirect');
    expect(helperFlows.length).toBeGreaterThanOrEqual(1);
  });

  it('helper alone — no spurious open_redirect without tainted param', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
    ]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'open_redirect');
    expect(flows).toHaveLength(0);
  });
});
