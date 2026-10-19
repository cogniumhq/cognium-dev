/**
 * cognium-dev #817 — variant stored JS xss FN (cross-file xfile shape).
 * Controller reads req.body; helper assigns to innerHTML.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — JS cross-file xss (variant stored xfile)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `const { render } = require('./helper');

function handle(req) {
  const html = req.body.html;
  render(html);
}

module.exports = { handle };
`;

  const helper = `function render(markup) {
  document.getElementById('panel').innerHTML = markup;
}

module.exports = { render };
`;

  it('cross-file http_body → helper innerHTML xss sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
      { code: controller, filePath: 'controller.js', language: 'javascript' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'xss');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) => p.source.file === 'controller.js' && p.sink.file === 'helper.js',
    );
    expect(xfile, 'expected controller.js → helper.js xss').toBeTruthy();
  });

  it('helper alone — no spurious xss without tainted param', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'helper.js', language: 'javascript' },
    ]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'xss');
    expect(flows).toHaveLength(0);
  });
});
