/**
 * cognium-dev #817 — flow-combo c01 JS log_injection FN (cross-file xfile shape).
 * Controller reads req.body; helper logs the param via console.log.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — JS cross-file log_injection (c01)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `const { run } = require('./helper');

function handle(req) {
  const msg = req.body.msg;
  run(msg);
}

module.exports = { handle };
`;

  const helper = `function run(data) {
  console.log(data);
}

module.exports = { run };
`;

  it('cross-file http_body → helper log_injection sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
      { code: controller, filePath: 'controller.js', language: 'javascript' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'log_injection');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.js' && p.sink.file === 'helper.js',
    );
    expect(xfile, 'expected controller.js → helper.js log_injection').toBeTruthy();

    const helperFlows = (r.files.find(f => f.file === 'helper.js')?.analysis.taint.flows ?? [])
      .filter(f => f.sink_type === 'log_injection');
    expect(helperFlows.length).toBeGreaterThanOrEqual(1);
  });

  it('helper alone — no spurious log_injection without tainted param', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
    ]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'log_injection');
    expect(flows).toHaveLength(0);
  });
});
