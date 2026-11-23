/**
 * cognium-dev #1171: Angular `DomSanitizer.bypassSecurityTrust*` is an xss sink
 * (#184). It was also listed as a JS XSS sanitizer, so the sink line filtered
 * itself out and the sink never fired. (The Juice Shop original declares
 * `let queryParam: string = …`; that annotation is a separate gap, #1173.)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const component = (stmt: string) => `import { ActivatedRoute } from '@angular/router';
import { DomSanitizer } from '@angular/platform-browser';
export class SearchResultComponent {
  searchValue: any;
  constructor (private readonly route: ActivatedRoute, private readonly sanitizer: DomSanitizer) {}
  filterTable () {
    let queryParam = this.route.snapshot.queryParams.q
    queryParam = queryParam.trim()
    ${stmt}
  }
}
`;

async function xss(code: string) {
  const ir = await analyze(code, 'search-result.component.ts', 'typescript');
  return { sinks: ir.taint.sinks.filter(s => s.type === 'xss'), flows: ir.taint.flows.filter(f => f.sink_type === 'xss') };
}

describe('#1171: Angular bypassSecurityTrust* fires as an xss sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('route query param into bypassSecurityTrustHtml is a flow (Juice Shop localXss shape)', async () => {
    const r = await xss(component('this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)'));
    expect(r.sinks.map(s => s.line)).toContain(9);
    expect(r.flows.some(f => f.sink_line === 9)).toBe(true);
  });

  it('each bypassSecurityTrust* variant is a sink', async () => {
    for (const m of ['Html', 'Script', 'Style', 'Url']) {
      const r = await xss(component(`const v = this.sanitizer.bypassSecurityTrust${m}(queryParam)`));
      expect(r.sinks.some(s => s.line === 9)).toBe(true);
    }
  });

  it('a literal argument is not a flow', async () => {
    const r = await xss(component(`this.searchValue = this.sanitizer.bypassSecurityTrustHtml('<b>hi</b>')`));
    expect(r.flows.filter(f => f.sink_line === 9)).toHaveLength(0);
  });

  it('a real sanitizer on the line still suppresses (DOMPurify)', async () => {
    const r = await xss(component('document.body.innerHTML = DOMPurify.sanitize(queryParam)'));
    expect(r.flows.filter(f => f.sink_line === 9)).toHaveLength(0);
  });
});
