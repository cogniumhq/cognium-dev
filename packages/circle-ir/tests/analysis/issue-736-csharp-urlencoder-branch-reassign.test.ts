/**
 * cognium-dev#736 — case 3: reassignment inside a branch drops UrlEncoder credit.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { CSharpCredit } from '../../src/analysis/passes/csharp-sanitizer-credit.js';

async function xss(code: string) {
  const r = await analyze(code, 'SafeLink.cs', 'csharp');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss');
}

const link = (expr: string) => `using System.Text.Encodings.Web;
public class SafeLink {
  public object Run(string input, bool flag) {
    ${expr}
  }
}`;

describe('cognium-dev#736 — branch reassignment drops encode credit', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports when a branch reassigns the encoded variable from raw input', async () => {
    const code = link(`var seg = UrlEncoder.Default.Encode(input);
    if (flag) { seg = input; }
    return Html.Raw("<a href=\\"/p/" + seg + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('reports when reassignment is on its own line inside the block', async () => {
    const code = link(`var seg = UrlEncoder.Default.Encode(input);
    if (flag) {
      seg = input;
    }
    return Html.Raw("<a href=\\"/p/" + seg + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('stays clean when the branch keeps the encoded value', async () => {
    const code = link(`var seg = UrlEncoder.Default.Encode(input);
    if (flag) { seg = UrlEncoder.Default.Encode(input); }
    return Html.Raw("<a href=\\"/p/" + seg + "\\">link</a>");`);
    expect(await xss(code)).toHaveLength(0);
  });

  it('credit helper drops encode on nested reassignment', () => {
    const code = `using System.Text.Encodings.Web;
public class SafeLink {
  public object Run(string input, bool flag) {
    var seg = UrlEncoder.Default.Encode(input);
    if (flag) { seg = input; }
    return Html.Raw("<a href=\\"/p/" + seg + "\\">link</a>");
  }
}`;
    const methods = [{ name: 'Run', start_line: 3, end_line: 8 }];
    const credit = new CSharpCredit(code, methods);
    expect(credit.sanitizedVarsAt('xss', 7).has('seg')).toBe(false);
  });
});
