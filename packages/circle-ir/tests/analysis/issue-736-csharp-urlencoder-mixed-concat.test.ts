/**
 * cognium-dev#736 — case 2: a new variable built from an encoded segment plus a
 * raw operand must not inherit UrlEncoder credit (follow-up to #733).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function xss(code: string) {
  const r = await analyze(code, 'SafeLink.cs', 'csharp');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss');
}

const link = (expr: string, extra = '') => `using System.Text.Encodings.Web;
${extra}
public class SafeLink {
  public object Run(string input, bool flag) {
    ${expr}
  }
}`;

describe('cognium-dev#736 — mixed concat drops encode credit', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports when a new variable combines encoded and raw operands', async () => {
    const code = link(`var seg = UrlEncoder.Default.Encode(input);
    var link = "/p/" + seg + input;
    return Html.Raw("<a href=\\"" + link + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('stays clean when the concat uses only the encoded segment', async () => {
    const code = link(`var seg = UrlEncoder.Default.Encode(input);
    var link = "/p/" + seg;
    return Html.Raw("<a href=\\"" + link + "\\">link</a>");`);
    expect(await xss(code)).toHaveLength(0);
  });
});
