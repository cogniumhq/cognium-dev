/**
 * cognium-dev #1173: in `let q: string = <source>` the forward-taint scan took
 * the type (`string`) as the tainted name, so sink-filter Stage 7 (6d) dropped
 * every JS/TS xss sink fed by a type-annotated declaration.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { buildJavaScriptTaintedVars } from '../../src/analysis/passes/language-sources-pass.js';

const component = (decl: string, sink: string) => `import { ActivatedRoute } from '@angular/router';
export class C {
  constructor (private readonly route: ActivatedRoute, private readonly el: any) {}
  f () {
    ${decl}
    ${sink}
  }
}
`;

describe('#1173: TS type-annotated tainted declarations', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('tracks the declared name, not the type', () => {
    const m = buildJavaScriptTaintedVars(`const q: string = req.query.q as string\n`, 'typescript');
    expect(m.has('q')).toBe(true);
    expect(m.has('string')).toBe(false);
  });

  it('generic and union annotations', () => {
    const m = buildJavaScriptTaintedVars(`let a: Array<string> = req.body.items\nlet b: string | undefined = req.query.b\n`, 'typescript');
    expect([...m.keys()]).toEqual(expect.arrayContaining(['a', 'b']));
  });

  for (const sink of ['this.el.nativeElement.innerHTML = q', 'document.write(q)', 'this.el.insertAdjacentHTML("beforeend", q)']) {
    it(`xss flow kept with \`let q: string\`: ${sink}`, async () => {
      const ir = await analyze(component('let q: string = this.route.snapshot.queryParams.q', sink), 'c.component.ts', 'typescript');
      expect(ir.taint.flows.some(f => f.sink_type === 'xss' && f.sink_line === 6)).toBe(true);
    });
  }

  it('an arrow-function initializer is not mistaken for an annotation', () => {
    const m = buildJavaScriptTaintedVars(`const f: (x: string) => string = (x) => x\n`, 'typescript');
    expect(m.has('string')).toBe(false);
  });
});
