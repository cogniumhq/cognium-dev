/**
 * cognium-dev#580 — the C# `Content(body, contentType)` xss sink ignored the
 * content type and the receiver. `Content(q, "text/plain")` and a project
 * type's own `Content` method were reported as CWE-79.
 *
 * The sink now holds only for the inherited controller helper (unqualified,
 * `this.` or `base.`) with an HTML or unknown content type. The one-argument
 * overload is unchanged.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flows = async (body: string, extra = ''): Promise<string[]> => {
  const code = `using System.Net.Mime;
using Microsoft.AspNetCore.Mvc;
public class Preview : Controller {
  public IActionResult Render(string mode) {
    var text = Request.Query["text"].ToString();
${body}
  }
}
${extra}`;
  const r = await analyze(code, 'Preview.cs', 'csharp');
  return (r.taint?.flows ?? []).map(f => `${f.sink_type}@${f.sink_line}`);
};

describe('#580 C# Content() xss honours the content type and receiver', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('text/html body still fires', async () => {
    expect(await flows('    return Content(text, "text/html");')).toEqual(['xss@6']);
  });

  it('text/html with a charset, built by concatenation, still fires', async () => {
    expect(await flows('    return Content("<p>" + text + "</p>", "text/html; charset=utf-8");')).toEqual(['xss@6']);
  });

  it('this.Content with MediaTypeNames.Text.Html still fires', async () => {
    expect(await flows('    return this.Content(text, MediaTypeNames.Text.Html);')).toEqual(['xss@6']);
  });

  it('a computed content type is unknown and still fires', async () => {
    expect(await flows('    return Content(text, mode);')).toEqual(['xss@6']);
  });

  it('the one-argument overload is unchanged', async () => {
    expect(await flows('    return Content(text);')).toEqual(['xss@6']);
  });

  it('text/plain is clean', async () => {
    expect(await flows('    return Content(text, "text/plain");')).toEqual([]);
  });

  it('application/json is clean', async () => {
    expect(await flows('    return Content(text, "application/json");')).toEqual([]);
  });

  it('MediaTypeNames.Text.Plain is clean', async () => {
    expect(await flows('    return base.Content(text, MediaTypeNames.Text.Plain);')).toEqual([]);
  });

  it("a project type's own Content method is not the sink", async () => {
    const out = await flows(
      '    var card = new Card();\n    card.Content(text);\n    return Ok();',
      'public class Card { public void Content(string s) { } }',
    );
    expect(out.filter(f => f.startsWith('xss@'))).toEqual([]);
  });
});
