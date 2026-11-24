/**
 * cognium-dev #1381: taint through subscribe callback into instance method (param rename).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const shape3 = `import { DomSanitizer } from '@angular/platform-browser'
export class X {
  constructor (private readonly sanitizer: DomSanitizer) {}
  trust (data: any[]) {
    for (let i = 0; i < data.length; i++) {
      data[i].description = this.sanitizer.bypassSecurityTrustHtml(data[i].description)
    }
  }
  load () {
    ({ subscribe: (cb: (d: any[]) => void) => cb([{ description: '<img src=x onerror=alert(1)>' }]) }).subscribe((d) => {
      this.trust(d)
    })
  }
}
`;

const observerShape = `import { DomSanitizer } from '@angular/platform-browser'
export class X {
  constructor (private readonly sanitizer: DomSanitizer) {}
  trust (data: any[]) {
    for (let i = 0; i < data.length; i++) {
      data[i].description = this.sanitizer.bypassSecurityTrustHtml(data[i].description)
    }
  }
  load () {
    ({ subscribe: (o: { next: (d: any[]) => void }) => o.next([]) }).subscribe({
      next: (payload) => { this.trust(payload) }
    })
  }
}
`;

describe('#1381: subscribe → this.trust(param)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('callback forwards renamed param into method that contains sink', async () => {
    const ir = await analyze(shape3, 'x.ts', 'typescript');
    const xssFlows = ir.taint.flows.filter(f => f.sink_type === 'xss');
    expect(xssFlows.length).toBeGreaterThan(0);
  });

  it('observer next: forwards payload into method that contains sink', async () => {
    const ir = await analyze(observerShape, 'x.ts', 'typescript');
    const xssFlows = ir.taint.flows.filter(f => f.sink_type === 'xss');
    expect(xssFlows.length).toBeGreaterThan(0);
  });
});