/**
 * cognium-dev#736 (slice, case 6): a namespace-qualified `Evil.UrlEncoder` must not
 * receive framework `UrlEncoder.Default.Encode` sanitizer credit.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function xss(code: string) {
  const r = await analyze(code, 'PermalinkBuilder.cs', 'csharp');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss');
}

const link = (expr: string, extra = '') => `${extra}
public class PermalinkBuilder {
  public object Run(string title) {
    ${expr}
  }
}`;

const ENCODED = `var slug = Evil.UrlEncoder.Default.Encode(title);
    return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`;

describe('cognium-dev#736 — qualified non-framework UrlEncoder', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports xss when the encoder is a qualified project type', async () => {
    expect((await xss(link(ENCODED))).length).toBeGreaterThanOrEqual(1);
  });

  it('stays clean for the fully qualified framework encoder', async () => {
    const code = link(
      `var slug = System.Text.Encodings.Web.UrlEncoder.Default.Encode(title);
    return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`,
    );
    expect(await xss(code)).toHaveLength(0);
  });

  it('stays clean for unqualified UrlEncoder with the framework import', async () => {
    const code = link(
      `var slug = UrlEncoder.Default.Encode(title);
    return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`,
      'using System.Text.Encodings.Web;',
    );
    expect(await xss(code)).toHaveLength(0);
  });
});
