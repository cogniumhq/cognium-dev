/**
 * cognium-dev#736 — case 4: UrlDecode after UrlEncoder.Encode must not keep credit.
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

describe('cognium-dev#736 — decode after encode drops UrlEncoder credit', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports when UrlDecode wraps UrlEncoder.Encode', async () => {
    const code = link(`var slug = System.Net.WebUtility.UrlDecode(UrlEncoder.Default.Encode(title));
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('reports for HttpUtility.UrlDecode spelling', async () => {
    const code = link(`var slug = HttpUtility.UrlDecode(UrlEncoder.Default.Encode(title));
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`, 'using System.Web;');
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('stays clean when only encode is assigned', async () => {
    const code = link(`var slug = UrlEncoder.Default.Encode(title);
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`);
    expect(await xss(code)).toHaveLength(0);
  });

  it('stays clean when UrlDecode applies to a constant only', async () => {
    const code = link(`var slug = System.Net.WebUtility.UrlDecode("%2F");
return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`);
    expect(await xss(code)).toHaveLength(0);
  });

  it('credit helper: decode-over-encode is not sanitized', () => {
    const code = `using System.Text.Encodings.Web;
public class PermalinkBuilder {
  public object Run(string title) {
    var slug = System.Net.WebUtility.UrlDecode(UrlEncoder.Default.Encode(title));
    return Html.Raw(slug);
  }
}`;
    const methods = [{ name: 'Run', start_line: 2, end_line: 6 }];
    const credit = new CSharpCredit(code, methods);
    const sinkLine = 5;
    expect(credit.sanitizedVarsAt('xss', sinkLine).has('slug')).toBe(false);
  });
});
