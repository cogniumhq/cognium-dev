/**
 * Regression tests for skillsregistry #49 (SSRF) and #51 (XSS) — precision FPs
 * surfaced by the published-skills audit, triaged as in-boundary circle-ir
 * detector over-firing.
 *
 * #51 — the classless `print`/`println` XSS entries (Java "inferred receiver"
 *       fallbacks) leaked to Python `print()` (stdout, never an XSS sink).
 *       Now scoped to `languages: ['java']`.
 * #49 — the classless `fetch` SSRF sink matched SDK/ORM entity lookups
 *       (`client.channels.fetch(id)`), not just the global Web `fetch(url)`.
 *       A SinkFilter stage (15e) drops the non-global member-receiver form.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('repro skillsregistry#51: XSS only on HTML sinks, not Python stdout', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does NOT flag Python print(user_input) as XSS (stdout is not an HTML sink)', async () => {
    const code = `
from fastapi.responses import JSONResponse
def handler(user_input):
    print(user_input)
    return JSONResponse({"echo": user_input})
`;
    const r = await analyze(code, 'server.py', 'python');
    const flows = (r.taint?.flows ?? []).map(f => f.sink_type);
    expect(flows).not.toContain('xss');
  });

  it('STILL flags a real Java servlet PrintWriter.print as XSS', async () => {
    const code = `
import java.io.PrintWriter;
public class S {
  void doGet(javax.servlet.http.HttpServletRequest req,
             javax.servlet.http.HttpServletResponse resp) throws Exception {
    String name = req.getParameter("name");
    PrintWriter out = resp.getWriter();
    out.print(name);
  }
}`;
    const r = await analyze(code, 'S.java', 'java');
    const flows = (r.taint?.flows ?? []).map(f => f.sink_type);
    expect(flows).toContain('xss');
  });

  it('STILL flags a Java inferred-receiver println as XSS', async () => {
    const code = `
public class T {
  void doGet(javax.servlet.http.HttpServletRequest req) throws Exception {
    String name = req.getParameter("name");
    out.println(name);
  }
}`;
    const r = await analyze(code, 'T.java', 'java');
    const flows = (r.taint?.flows ?? []).map(f => f.sink_type);
    expect(flows).toContain('xss');
  });
});

describe('repro skillsregistry#49: SSRF only on global fetch, not SDK entity lookups', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does NOT flag discord.js client.channels.fetch(id) / users.fetch(id) as SSRF', async () => {
    const code = `
async function lookup(client, id) {
  const ch = await client.channels.fetch(id);
  const u = await client.users.fetch(id);
  return [ch, u];
}
`;
    const r = await analyze(code, 'discord.js', 'javascript');
    const flows = (r.taint?.flows ?? []).map(f => f.sink_type);
    expect(flows).not.toContain('ssrf');
  });

  it('STILL flags bare fetch(userUrl) as SSRF', async () => {
    const code = `async function h(req){ const u = req.query.url; return await fetch(u); }`;
    const r = await analyze(code, 'a.js', 'javascript');
    const flows = (r.taint?.flows ?? []).map(f => f.sink_type);
    expect(flows).toContain('ssrf');
  });

  it('STILL flags window.fetch(userUrl) as SSRF (global receiver)', async () => {
    const code = `async function h(req){ const u = req.query.url; return await window.fetch(u); }`;
    const r = await analyze(code, 'b.js', 'javascript');
    const flows = (r.taint?.flows ?? []).map(f => f.sink_type);
    expect(flows).toContain('ssrf');
  });
});

describe('repro skillsregistry#49b: anchored host allow-list reject-guard suppresses SSRF', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const ssrfFires = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.flows ?? []).some(f => f.sink_type === 'ssrf');

  it('SUPPRESSES fetch guarded by an anchored host-allowlist regex reject-guard', async () => {
    const code = `async function proxy(userUrl) {
  if (!/^https:\\/\\/(www\\.)?fidensa\\.(com|dev)\\//.test(userUrl)) throw new Error('bad');
  return await fetch(userUrl);
}`;
    expect(ssrfFires(await analyze(code, 'p.js', 'javascript'))).toBe(false);
  });

  it('SUPPRESSES fetch guarded by a startsWith("https://host/") reject-guard', async () => {
    const code = `async function proxy(userUrl) {
  if (!userUrl.startsWith("https://api.github.com/")) return null;
  return await fetch(userUrl);
}`;
    expect(ssrfFires(await analyze(code, 'q.js', 'javascript'))).toBe(false);
  });

  it('SUPPRESSES fetch of a var derived one-hop from the guarded URL', async () => {
    const code = `async function proxy(userUrl) {
  if (!/^https:\\/\\/ok\\.example\\.com\\//.test(userUrl)) throw new Error('bad');
  const full = userUrl + "?x=1";
  return await fetch(full);
}`;
    expect(ssrfFires(await analyze(code, 'r.js', 'javascript'))).toBe(false);
  });

  it('STILL fires for a scheme-only guard (host not constrained)', async () => {
    const code = `async function proxy(userUrl) {
  if (!/^https?:\\/\\//.test(userUrl)) throw new Error('bad');
  return await fetch(userUrl);
}`;
    expect(ssrfFires(await analyze(code, 's.js', 'javascript'))).toBe(true);
  });

  it('STILL fires when the guard is on a different variable than the fetch arg', async () => {
    const code = `async function proxy(a, b) {
  if (!/^https:\\/\\/ok\\.com\\//.test(a)) throw new Error('bad');
  return await fetch(b);
}`;
    expect(ssrfFires(await analyze(code, 't.js', 'javascript'))).toBe(true);
  });
});
