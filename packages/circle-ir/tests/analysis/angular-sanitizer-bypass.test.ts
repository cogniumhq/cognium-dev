/**
 * Angular `DomSanitizer.bypassSecurityTrust*` calls are XSS sinks for browser
 * and route input, including the `ActivatedRoute` snapshot maps
 * (`route.snapshot.queryParamMap.get('q')`, `route.snapshot.paramMap.get('id')`).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type Flow = { source_line: number; sink_line: number; sink_type: string };
const xss = (r: { taint: { flows?: Flow[] } }): Array<[number, number]> =>
  (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => [f.source_line, f.sink_line]);

describe('Angular DomSanitizer bypass sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('each bypass method fed by URL or route input', async () => {
    const code = [
      "import { Component } from '@angular/core';",
      "import { DomSanitizer } from '@angular/platform-browser';",
      "import { ActivatedRoute } from '@angular/router';",
      "@Component({ selector: 'app-banner', template: '<div [innerHTML]=\"html\"></div>' })",
      'export class BannerComponent {',
      '  html: any;',
      '  constructor(private sanitizer: DomSanitizer, private route: ActivatedRoute) {',
      "    const msg = new URLSearchParams(window.location.search).get('msg');",
      '    this.html = this.sanitizer.bypassSecurityTrustHtml(msg);',
      '  }',
      '  frame() {',
      "    const id = this.route.snapshot.queryParamMap.get('id');",
      '    return this.sanitizer.bypassSecurityTrustResourceUrl(id);',
      '  }',
      '  link() {',
      '    const h = location.hash.slice(1);',
      '    return this.sanitizer.bypassSecurityTrustUrl(h);',
      '  }',
      '  script() {',
      "    const p = this.route.snapshot.paramMap.get('p');",
      '    return this.sanitizer.bypassSecurityTrustScript(p);',
      '  }',
      '  style() {',
      "    const s = this.route.snapshot.queryParams['style'];",
      '    return this.sanitizer.bypassSecurityTrustStyle(s);',
      '  }',
      '}',
    ].join('\n');
    expect(xss(await analyze(code, 'banner.component.ts', 'typescript'))).toEqual([
      [8, 9], [12, 13], [16, 17], [20, 21], [24, 25],
    ]);
  });

  it('no flow: literal markup, sanitised value, a constant URL', async () => {
    const code = [
      "import DOMPurify from 'dompurify';",
      'export class SafeComponent {',
      '  constructor(private sanitizer: DomSanitizer, private route: ActivatedRoute) {}',
      '  literal() {',
      "    return this.sanitizer.bypassSecurityTrustHtml('<b>hi</b>');",
      '  }',
      '  cleaned() {',
      "    const m = this.route.snapshot.queryParamMap.get('m');",
      '    return this.sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize(m));',
      '  }',
      '  fixed() {',
      "    const base = 'https://www.youtube.com/embed/';",
      '    return this.sanitizer.bypassSecurityTrustResourceUrl(base);',
      '  }',
      '}',
    ].join('\n');
    expect(xss(await analyze(code, 'safe.component.ts', 'typescript'))).toEqual([]);
  });
});
