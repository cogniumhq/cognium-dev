/**
 * cognium-dev#580 (enclosing-type slice) — the C# `Content(body)` xss sink is
 * the inherited MVC helper, so an unqualified `Content(...)` call counts only
 * inside a type that can inherit it. A type with no base class, or one that
 * declares its own `Content`, calls its own method and is not the sink.
 *
 * A type deriving from `Controller` / `ControllerBase` / `PageModel`, from a
 * base the analysis cannot see, or a `partial` class (base may live in another
 * part) keeps the sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const xss = async (code: string): Promise<string[]> => {
  const r = await analyze(`using Microsoft.AspNetCore.Mvc;\n${code}`, 'Page.cs', 'csharp');
  return (r.taint?.flows ?? []).filter(f => f.sink_type === 'xss').map(f => `xss@${f.sink_line}`);
};

const action = (decl: string, extra = '') => `${decl}
{
  ${extra}
  public IActionResult Show()
  {
    var text = Request.Query["text"].ToString();
    return Content(text, "text/html");
  }
}`;

describe('#580 C# Content() needs an enclosing type that can inherit it', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('Controller, ControllerBase and PageModel keep the sink', async () => {
    for (const decl of ['public class A : Controller', 'public class B : ControllerBase', 'public class C : PageModel',
      'public class D : Microsoft.AspNetCore.Mvc.ControllerBase, IDisposable']) {
      expect((await xss(action(decl))).length).toBe(1);
    }
  });

  it('a project base class the analysis cannot see keeps the sink', async () => {
    expect((await xss(action('public class Docs : SiteControllerBase'))).length).toBe(1);
  });

  it('a partial class with no base in this part keeps the sink', async () => {
    // Base may be declared in another partial; empty bases must not drop Content().
    expect((await xss(action('public partial class A'))).length).toBe(1);
  });

  it('a type with no base class and its own Content method is not the sink', async () => {
    const code = `public class Card
{
  public string Content(string s, string kind) { return s; }
  public void Show(string q)
  {
    var text = Request.Query["text"].ToString();
    Content(text, "text/html");
  }
}`;
    expect(await xss(code)).toEqual([]);
  });

  it('a type with no base class and no Content method is not the sink', async () => {
    const code = `public class Card
{
  public void Show(string q)
  {
    var text = Request.Query["text"].ToString();
    Content(text, "text/html");
  }
}`;
    expect(await xss(code)).toEqual([]);
  });

  it('an interface-only base list with no Content of its own is not the sink', async () => {
    const code = `public class Card : IDisposable
{
  public void Dispose() { }
  public void Show(string q)
  {
    var text = Request.Query["text"].ToString();
    Content(text, "text/html");
  }
}`;
    expect(await xss(code)).toEqual([]);
  });

  it('an unseen base with its own Content method hides the inherited helper', async () => {
    const code = `public class Card : SiteBase
{
  public void Content(string s, string kind) { }
  public void Show(string q)
  {
    var text = Request.Query["text"].ToString();
    Content(text, "text/html");
  }
}`;
    expect(await xss(code)).toEqual([]);
  });

  it('a controller that declares its own Content overload keeps the helper call', async () => {
    const code = `public class Page : Controller
{
  public string Content(string s, string kind, int n) { return s; }
  public IActionResult Show()
  {
    var text = Request.Query["text"].ToString();
    return Content(text, "text/html");
  }
}`;
    expect((await xss(code)).length).toBe(1);
  });

  it('a nested type is judged by its own base list', async () => {
    const code = `public class Outer : Controller
{
  public class Card
  {
    public void Show(string q)
    {
      var text = Request.Query["text"].ToString();
      Content(text, "text/html");
    }
  }
}`;
    expect(await xss(code)).toEqual([]);
  });
});
