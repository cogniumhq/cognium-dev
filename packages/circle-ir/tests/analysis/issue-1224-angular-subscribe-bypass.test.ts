/**
 * cognium-dev #1224: HTTP/service response through `.subscribe` into
 * `DomSanitizer.bypassSecurityTrust*` (Juice Shop restfulXss shape).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const juiceShopShape = `import { Component } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'
import { ProductService } from './product.service'
@Component({ selector: 'x', template: '' })
export class X {
  constructor (private readonly sanitizer: DomSanitizer, private readonly productService: ProductService) {}
  load () {
    this.productService.search('').subscribe((tableData: any[]) => {
      for (let i = 0; i < tableData.length; i++) {
        tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
      }
    })
  }
}
`;

describe('#1224: subscribe callback body into bypassSecurityTrustHtml', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('service subscribe payload property reaches bypass sink (Juice Shop restfulXss)', async () => {
    const ir = await analyze(juiceShopShape, 'search-result.component.ts', 'typescript');
    const xssFlows = ir.taint.flows.filter(f => f.sink_type === 'xss');
    expect(ir.taint.sinks.some(s => s.type === 'xss')).toBe(true);
    expect(xssFlows.length).toBeGreaterThan(0);
  });

  it('literal-only subscribe callback does not create a flow', async () => {
    const code = `import { DomSanitizer } from '@angular/platform-browser'
export class X {
  constructor (private readonly sanitizer: DomSanitizer) {}
  load () {
    ({ subscribe: (cb: (d: string) => void) => cb('<b>ok</b>') }).subscribe((data) => {
      this.sanitizer.bypassSecurityTrustHtml('<b>static</b>')
    })
  }
  sanitizer!: DomSanitizer
}
`;
    const ir = await analyze(code, 'x.ts', 'typescript');
    const sinkLines = ir.taint.flows.filter(f => f.sink_type === 'xss').map(f => f.sink_line);
    expect(sinkLines).not.toContain(6);
  });
});
