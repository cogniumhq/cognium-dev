/**
 * cognium-dev #501 — classic ASP.NET `http_param` sources only matched a
 * receiver literally named `Request`. Juliet names the parameter `req`, so
 * `req.QueryString` / `req.Cookies` seeded nothing and every downstream flow
 * was lost. The declared type (`HttpRequest` / `HttpRequestBase`) is what
 * makes the read a request source; the identifier is not.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const run = (code: string) => analyze(code, 'P.cs', 'csharp');

type Result = Awaited<ReturnType<typeof run>>;

const commandFindings = (r: Result) =>
  generateFindings(
    r.taint.sources, r.taint.sinks, r.dfg, 'P.cs',
    undefined, 'csharp', r.taint.sanitizers ?? [], r.types, r.taint.flows,
  ).filter(f => f.type === 'command_injection');

describe('#501 C# HttpRequest sources follow the declared type, not the name Request', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('fires command_injection when the parameter is named req', async () => {
    const r = await run([
      'using System.Web;',
      'using System.Diagnostics;',
      'public class P { public void Bad(HttpRequest req) {',
      '  string data = req.QueryString["id"];',
      '  Process.Start("cmd.exe /c " + data);',
      '} }',
    ].join('\n'));
    expect(r.taint.sources.filter(s => s.type === 'http_param' && s.variable === 'data').length)
      .toBeGreaterThan(0);
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection' && !f.sanitized);
    expect(flows.length).toBeGreaterThan(0);
    expect(commandFindings(r).some(f => f.cwe === 'CWE-78')).toBe(true);
  });

  it('still fires when the parameter is literally named Request', async () => {
    const r = await run([
      'using System.Web;',
      'using System.Diagnostics;',
      'public class P { public void Bad(HttpRequest Request) {',
      '  string data = Request.QueryString["id"];',
      '  Process.Start("cmd.exe /c " + data);',
      '} }',
    ].join('\n'));
    expect((r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection' && !f.sanitized).length)
      .toBeGreaterThan(0);
  });

  it('seeds http_param from req.Cookies and req.Params.Get', async () => {
    const cookies = await run([
      'using System.Web;',
      'using System.Diagnostics;',
      'public class P { public void Bad(HttpRequest req) {',
      '  var cookieSources = req.Cookies;',
      '  string data = cookieSources[0].Value;',
      '  Process.Start("cmd.exe /c " + data);',
      '} }',
    ].join('\n'));
    expect(cookies.taint.sources.some(s => s.type === 'http_param' && s.variable === 'cookieSources'))
      .toBe(true);

    const params = await run([
      'using System.Web;',
      'using System.Diagnostics;',
      'public class P { public void Bad(HttpRequestBase req) {',
      '  string data = req.Params.Get("id");',
      '  Process.Start("cmd.exe /c " + data);',
      '} }',
    ].join('\n'));
    expect(params.taint.sources.some(s => s.type === 'http_param' && s.variable === 'data')).toBe(true);
    expect((params.taint.flows ?? []).some(f => f.sink_type === 'command_injection' && !f.sanitized))
      .toBe(true);
  });

  it('does not treat an undeclared req as an HttpRequest', async () => {
    const r = await run([
      'using System.Diagnostics;',
      'public class P { public void Bad(string req) {',
      '  string data = req;',
      '  Process.Start("cmd.exe /c " + data);',
      '} }',
    ].join('\n'));
    expect(r.taint.sources.filter(s => s.type === 'http_param')).toHaveLength(0);
  });
});
