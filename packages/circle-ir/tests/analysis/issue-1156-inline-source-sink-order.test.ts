/**
 * cognium-dev#1156 — When `io_input` (e.g. `parser.parse(...)`) and `path_traversal`
 * (`readFileSync`) match the same line, inline colocation must not emit a flow if the
 * sink is nested only inside the source's argument list (sink runs before the source
 * returns). The opposite shape (source nested in sink args) must still report.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#1156 — inline source/sink order on one line', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('drops io_input → path_traversal when readFileSync is only inside parse(...) args', async () => {
    const code = `
import * as fs from 'fs';
export function load(parser: any, abs: string) {
  return parser.parse(fs.readFileSync(abs, 'utf-8'));
}
`;
    const r = await analyze(code, 'bom.ts', 'typescript');
    const bad = r.taint.flows.filter(
      f => f.source_type === 'io_input' && f.sink_type === 'path_traversal' && f.source_line === 4 && f.sink_line === 4,
    );
    expect(bad).toEqual([]);
  });

  it('keeps a same-line inline flow when the taint source is nested in readFileSync args', async () => {
    const code = `
import * as fs from 'fs';
export function bad(req: any) {
  return fs.readFileSync(JSON.parse(req.query.p).path, 'utf-8');
}
`;
    const r = await analyze(code, 'x.ts', 'typescript');
    const hit = r.taint.flows.some(
      f =>
        f.source_line === 4 &&
        f.sink_line === 4 &&
        f.sink_type === 'path_traversal' &&
        f.path.some(p => p.variable === '<inline>'),
    );
    expect(hit).toBe(true);
  });
});
