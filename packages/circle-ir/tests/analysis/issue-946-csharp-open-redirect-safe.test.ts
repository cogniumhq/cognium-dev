/**
 * cognium-dev #946 — C# flow-combo / flow-quartet `open_redirect` safe mirrors
 * (validate helper + early-exit IsLocalUrl shapes from gates-nightly).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const openRedirect = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint?.flows ?? []).filter((f) => f.sink_type === 'open_redirect' && !f.sanitized);

describe('#946 C# open_redirect validate helpers stay clean', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('inline IsLocalUrl guard stays clean', async () => {
    const code = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult M(string next) {
    if (Url.IsLocalUrl(next)) { return Redirect(next); }
    return Redirect("/");
  }
}`;
    expect(openRedirect(await analyze(code, 'C.cs', 'csharp'))).toHaveLength(0);
  });

  it('Pick helper with IsLocalUrl branch stays clean at Redirect(Pick(next))', async () => {
    const code = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  private string Pick(string u) {
    if (Url.IsLocalUrl(u)) return u;
    return "/";
  }
  public IActionResult M(string next) { return Redirect(Pick(next)); }
}`;
    expect(openRedirect(await analyze(code, 'C.cs', 'csharp'))).toHaveLength(0);
  });

  it('early exit on non-local URL stays clean on final Redirect', async () => {
    const code = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult M(string url) {
    if (!Url.IsLocalUrl(url)) return Redirect("/");
    return Redirect(url);
  }
}`;
    expect(openRedirect(await analyze(code, 'C.cs', 'csharp'))).toHaveLength(0);
  });

  it('unguarded Redirect(tainted) still fires', async () => {
    const code = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult M(string next) { return Redirect(next); }
}`;
    expect(openRedirect(await analyze(code, 'C.cs', 'csharp')).length).toBeGreaterThan(0);
  });
});

describe('#946 C# open_redirect host-equality guards', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const run = async (body: string) =>
    openRedirect(await analyze(`using Microsoft.AspNetCore.Mvc;
public class V01BaselineSafe {
  public object Run(string input) {
${body}
  }
}`, 'V01BaselineSafe.cs', 'csharp'));

  it('Uri(...).Host == literal ternary picks the tainted redirect only on the true side (V01BaselineSafe)', async () => {
    expect(await run(`    var host = new Uri(input, UriKind.RelativeOrAbsolute).Host;
        return host == "app.example.com" ? Redirect(input) : Redirect("/home");`)).toHaveLength(0);
  });

  it('inline new Uri(x).Host == literal in the ternary condition stays clean', async () => {
    expect(await run(`    return new Uri(input).Host == "app.example.com" ? Redirect(input) : Redirect("/home");`)).toHaveLength(0);
  });

  it('host-equality if guard with a UriKind argument stays clean', async () => {
    expect(await run(`    var host = new Uri(input, UriKind.Absolute).Host;
    if (host == "app.example.com") { return Redirect(input); }
    return Redirect("/home");`)).toHaveLength(0);
  });

  it('tainted redirect on the false side of the ternary still fires', async () => {
    expect((await run(`    var host = new Uri(input, UriKind.RelativeOrAbsolute).Host;
        return host == "app.example.com" ? Redirect("/home") : Redirect(input);`)).length).toBeGreaterThan(0);
  });

  it('tainted redirect on both sides still fires', async () => {
    expect((await run(`    var host = new Uri(input, UriKind.RelativeOrAbsolute).Host;
        return host == "app.example.com" ? Redirect(input) : Redirect(input + "/x");`)).length).toBeGreaterThan(0);
  });

  it('a ternary on something other than the host still fires', async () => {
    expect((await run(`    return input.Length > 3 ? Redirect(input) : Redirect("/home");`)).length).toBeGreaterThan(0);
  });

  it('host compared against a variable, not a literal, still fires', async () => {
    expect((await run(`    var host = new Uri(input, UriKind.RelativeOrAbsolute).Host;
    var other = input;
        return host == other ? Redirect(input) : Redirect("/home");`)).length).toBeGreaterThan(0);
  });

  it('V01BaselineTp control still fires', async () => {
    expect((await run(`    var target = input;
        return Redirect(target);`)).length).toBeGreaterThan(0);
  });
});
