/**
 * cognium-dev#736 — `+=` onto a UrlEncoder-credited variable must drop the credit
 * when the appended value is raw (case 1 of the follow-up to #733).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { CSharpCredit } from '../../src/analysis/passes/csharp-sanitizer-credit.js';

async function xss(code: string) {
  const r = await analyze(code, 'PermalinkBuilder.cs', 'csharp');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss');
}

const link = (expr: string, extra = '') => `using System.Text.Encodings.Web;
${extra}
public class PermalinkBuilder {
  public object Run(string title) {
    ${expr}
  }
}`;

describe('cognium-dev#736 — UrlEncoder credit ends on raw +=', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports when a raw value is appended after encode', async () => {
    const code = link(`var slug = UrlEncoder.Default.Encode(title);
slug += title;
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('reports when a raw operand is inside a longer append', async () => {
    const code = link(`var slug = UrlEncoder.Default.Encode(title);
slug += "/" + title;
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports the unencoded control', async () => {
    const code = link(`var slug = title;
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('stays clean when only an encoded value is appended', async () => {
    const code = link(`var slug = UrlEncoder.Default.Encode(title);
slug += UrlEncoder.Default.Encode(title);
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`);
    expect(await xss(code)).toHaveLength(0);
  });

  it('stays clean when only a literal is appended after encode', async () => {
    const code = link(`var slug = UrlEncoder.Default.Encode(title);
slug += "/edit";
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`);
    expect(await xss(code)).toHaveLength(0);
  });

  it('literal += does not grant sanitizer credit to an uncredited name', () => {
    const code = `using System.Text.Encodings.Web;
public class PermalinkBuilder {
  public object Run(string title) {
    var slug = title;
    slug += "/edit";
    return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");
  }
}`;
    const methods = [{ name: 'Run', start_line: 3, end_line: 8 }];
    const credit = new CSharpCredit(code, methods);
    expect(credit.sanitizedVarsAt('xss', 6).has('slug')).toBe(false);
  });
});
