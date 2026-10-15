/**
 * cognium-dev#564 — `UrlEncoder.Default.Encode(x)` percent-encodes `<`, `"`
 * and `'`, so a value placed in an HTML attribute or text position through it
 * is not xss. A project type that merely shares the name is not credited.
 *
 * SAST regression fixture — the "fires" handlers are deliberately vulnerable.
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
  public object Run(string input) {
    ${expr}
  }
}`;

const ENCODED = `var seg = UrlEncoder.Default.Encode(input);
    return Html.Raw("<a href=\\"/p/" + seg + "\\">link</a>");`;

describe('cognium-dev#564 — UrlEncoder.Default.Encode credits xss', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('percent-encoded segment placed in Html.Raw is clean', async () => {
    expect(await xss(link(ENCODED))).toHaveLength(0);
  });

  it('encoder applied inline is clean', async () => {
    const code = link(`return Html.Raw("<a href=\\"/p/" + UrlEncoder.Default.Encode(input) + "\\">link</a>");`);
    expect(await xss(code)).toHaveLength(0);
  });

  it('still fires: the unencoded twin', async () => {
    const code = link(`return Html.Raw("<a href=\\"/p/" + input + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: a raw operand next to the encoded one', async () => {
    const code = link(`var seg = UrlEncoder.Default.Encode(input);
    return Html.Raw("<a href=\\"/p/" + seg + "\\">" + input + "</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: the encoded name is reassigned from the raw value', async () => {
    const code = link(`var seg = UrlEncoder.Default.Encode(input);
    seg = input;
    return Html.Raw("<a href=\\"/p/" + seg + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: a project type named UrlEncoder with its own Encode', async () => {
    const shadow = `public static class UrlEncoder {
  public static class Default { public static string Encode(string s) { return s; } }
}`;
    const code = link(ENCODED, shadow);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: a project UrlEncoder class with an instance Encode', async () => {
    const shadow = `public class UrlEncoder { public static UrlEncoder Default = new UrlEncoder(); public string Encode(string s) { return s; } }`;
    const code = link(ENCODED, shadow);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: the HtmlEncoder-free class-less Encode is not credited', async () => {
    const code = link(`var seg = Codec.Encode(input);
    return Html.Raw("<a href=\\"/p/" + seg + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('HtmlEncoder for the attribute plus UrlEncoder for the path segment is clean', async () => {
    const code = link(`var label = HtmlEncoder.Default.Encode(input);
    var seg = UrlEncoder.Default.Encode(input);
    return Html.Raw("<a title=\\"" + label + "\\" href=\\"/p/" + seg + "\\">link</a>");`);
    expect(await xss(code)).toHaveLength(0);
  });

  it('still fires: HtmlEncoder for the attribute, raw value in the path segment', async () => {
    const code = link(`var label = HtmlEncoder.Default.Encode(input);
    return Html.Raw("<a title=\\"" + label + "\\" href=\\"/p/" + input + "\\">link</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: the encoder is applied to a different variable', async () => {
    const code = link(`var seg = UrlEncoder.Default.Encode("fixed");
    return Html.Raw("<a href=\\"/p/" + seg + "\\">" + input + "</a>");`);
    expect((await xss(code)).length).toBeGreaterThanOrEqual(1);
  });
});
