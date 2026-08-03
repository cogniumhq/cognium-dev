/**
 * Narrow DOM `.value` source coverage (framework-coverage expansion, final thread).
 *
 * A `.value` read off a DOM element accessor is a `dom_input` source (DOM-based
 * XSS). `getElementById` / `querySelector` were already covered; this adds the
 * remaining element-accessor siblings — `getElementsByName` /
 * `getElementsByClassName` / `getElementsByTagName` / `querySelectorAll`.
 *
 * Narrowness matters: a bare `.value` was deliberately removed in the past for
 * false positives (`result.value`, `node.value` in non-browser code). These
 * patterns require the `document.` receiver, so only real DOM access matches —
 * pinned by the negative test.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

describe('DOM .value dom_input source', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const domSources = (r: Awaited<ReturnType<typeof analyze>>) =>
    r.taint.sources.filter((s) => s.type === 'dom_input');

  const accessors: Array<[string, string]> = [
    ['getElementsByName', "document.getElementsByName('q')[0].value"],
    ['getElementsByClassName', "document.getElementsByClassName('q')[0].value"],
    ['getElementsByTagName', "document.getElementsByTagName('input')[0].value"],
    ['querySelectorAll', "document.querySelectorAll('#q')[0].value"],
  ];

  for (const [name, expr] of accessors) {
    it(`document.${name}(...)[0].value registers a dom_input source and flows`, async () => {
      const code = [`const v = ${expr};`, 'document.write(v);'].join('\n');
      const r = await analyze(code, 'a.js', 'javascript');
      expect(domSources(r).some((s) => s.variable === 'v')).toBe(true);
      expect((r.taint.flows ?? []).length).toBeGreaterThan(0);
    });
  }

  it('getElementById .value still fires (regression lock)', async () => {
    const code = ["const v = document.getElementById('q').value;", 'document.write(v);'].join('\n');
    const r = await analyze(code, 'a.js', 'javascript');
    expect(domSources(r).length).toBeGreaterThan(0);
  });

  it('a bare non-DOM .value read is NOT a dom_input source (narrowness)', async () => {
    const code = ['const v = config.value;', 'document.write(v);'].join('\n');
    const r = await analyze(code, 'a.js', 'javascript');
    expect(domSources(r).length).toBe(0);
  });
});
