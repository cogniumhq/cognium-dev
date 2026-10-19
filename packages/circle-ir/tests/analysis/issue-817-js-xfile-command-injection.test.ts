/**
 * cognium-dev #817 — cve-intake-b PAT-CVE JS command_injection FN (cross-file xfile shape).
 * Controller reads req.body; helper runs child_process.exec on the param.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — JS cross-file command_injection (PAT-CVE xfile)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `const { run } = require('./helper');

function handle(req) {
  const cmd = req.body.cmd;
  run(cmd);
}

module.exports = { handle };
`;

  const helper = `const { exec } = require('child_process');

function run(command) {
  exec(command);
}

module.exports = { run };
`;

  it('cross-file http_body → helper command_injection sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
      { code: controller, filePath: 'controller.js', language: 'javascript' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'command_injection');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.js' && p.sink.file === 'helper.js',
    );
    expect(xfile, 'expected controller.js → helper.js command_injection').toBeTruthy();
  });

  it('helper alone — no spurious command_injection without tainted param', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
    ]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter(
      (f) => f.sink_type === 'command_injection',
    );
    expect(flows).toHaveLength(0);
  });
});
