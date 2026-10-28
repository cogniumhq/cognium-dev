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
