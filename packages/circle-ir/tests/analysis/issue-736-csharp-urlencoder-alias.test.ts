/**
 * cognium-dev#736 (slice, case 5): a `using UrlEncoder = …` alias must not credit
 * the framework encoder unless the alias resolves to `System.Text.Encodings.Web.UrlEncoder`.
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

const ENCODED = `var slug = UrlEncoder.Default.Encode(title);
    return Html.Raw("<a href=\\"/p/" + slug + "\\">link</a>");`;

describe('cognium-dev#736 — UrlEncoder using-alias shadowing', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('still fires when UrlEncoder aliases a project type', async () => {
    const code = link(
      ENCODED,
      `namespace My.Fake {
  public static class Encoder {
    public static class Default { public static string Encode(string s) => s; }
  }
}
using UrlEncoder = My.Fake.Encoder;`,
    );
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('stays clean when UrlEncoder aliases the framework type', async () => {
    const code = link(
      ENCODED,
      `using System.Text.Encodings.Web;
using UrlEncoder = System.Text.Encodings.Web.UrlEncoder;`,
    );
    expect(await xss(code)).toHaveLength(0);
  });

  it('stays clean with a direct System.Text.Encodings.Web import (no alias)', async () => {
    const code = link(ENCODED, 'using System.Text.Encodings.Web;');
    expect(await xss(code)).toHaveLength(0);
  });
});
