/**
 * C# sanitizer and guard credit (#518, #520, #286 A).
 *
 * Every mechanism is paired with a near miss that must still be reported: a
 * credit rule is only safe if the shapes just outside it keep firing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const real = async (code: string, type: string) => {
  const ir = await analyze(code, 'T.cs', 'csharp');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === type);
};
const anyFlow = async (code: string) => (await analyze(code, 'T.cs', 'csharp')).taint.flows ?? [];

const cls = (members: string) => `
using System; using System.IO; using System.Linq; using System.Net; using System.Net.Http;
using System.Text; using System.Text.RegularExpressions; using System.Threading.Tasks;
using System.Data.SqlClient; using System.DirectoryServices; using System.Xml;
using Microsoft.AspNetCore.Mvc; using System.Text.Encodings.Web;
public class T : Controller {
  static SqlConnection conn;
${members}
}
`;

describe('C# sanitizer in a same-file helper (#518 A)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a helper that returns an encoded value is an xss sanitizer', async () => {
    const code = cls(`
  static string Clean(string x) { return WebUtility.HtmlEncode(x); }
  public object Run(string input) {
    var v = Clean(input);
    return Html.Raw("<div>" + v + "</div>");
  }`);
    expect(await real(code, 'xss')).toHaveLength(0);
  });

  it('a helper that returns its argument unchanged is not', async () => {
    const code = cls(`
  static string Tidy(string x) { return x; }
  public object Run(string input) {
    var v = Tidy(input);
    return Html.Raw("<div>" + v + "</div>");
  }`);
    expect((await real(code, 'xss')).length).toBeGreaterThanOrEqual(1);
  });

  it('a helper with one unsanitized return path is not', async () => {
    const code = cls(`
  static string Clean(string x) {
    if (x.Length > 10) return x;
    return WebUtility.HtmlEncode(x);
  }
  public object Run(string input) {
    var v = Clean(input);
    return Html.Raw("<div>" + v + "</div>");
  }`);
    expect((await real(code, 'xss')).length).toBeGreaterThanOrEqual(1);
  });

  it('HtmlEncoder.Default.Encode is an xss sanitizer (#520)', async () => {
    const code = cls(`
  public async Task Run() {
    var q = Request.Query["q"];
    await Response.WriteAsync("<div>" + HtmlEncoder.Default.Encode(q) + "</div>");
  }`);
    expect(await anyFlow(code)).toHaveLength(0);
  });
});

describe('C# LDAP and XPath escaping (#518 C)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('escaping both parentheses clears ldap injection', async () => {
    const code = cls(`
  public void Run(string input) {
    var safe = input.Replace("\\\\", "\\\\5c").Replace("*", "\\\\2a")
                    .Replace("(", "\\\\28").Replace(")", "\\\\29");
    var s = new DirectorySearcher("(uid=" + safe + ")");
    s.FindOne();
  }`);
    expect(await real(code, 'ldap_injection')).toHaveLength(0);
  });

  it('escaping only one parenthesis does not', async () => {
    const code = cls(`
  public void Run(string input) {
    var half = input.Replace("(", "\\\\28");
    var s = new DirectorySearcher("(uid=" + half + ")");
    s.FindOne();
  }`);
    expect((await real(code, 'ldap_injection')).length).toBeGreaterThanOrEqual(1);
  });

  it('SecurityElement.Escape clears xpath injection', async () => {
    const code = cls(`
  public void Run(XmlDocument doc, string input) {
    string name = System.Security.SecurityElement.Escape(input);
    string query = "//users/user[name/text()='" + name +
                   "']/secret/text()";
    doc.SelectSingleNode(query);
  }`);
    expect(await real(code, 'xpath_injection')).toHaveLength(0);
  });
});

describe('C# allowlist and numeric guards (#518)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const ldap = (guard: string) => cls(`
  public void Run(string input) {
${guard}
    var searcher = new DirectorySearcher(new DirectoryEntry("LDAP://corp"));
    searcher.Filter = "(uid=" + input + ")";
    searcher.FindOne();
  }`);

  it('an anchored regex allowlist with an early return clears the sink', async () => {
    const code = ldap(`    if (!Regex.IsMatch(input, "^[A-Za-z0-9_]+$"))
      return;`);
    expect(await real(code, 'ldap_injection')).toHaveLength(0);
  });

  it('an unanchored regex does not', async () => {
    const code = ldap(`    if (!Regex.IsMatch(input, "[A-Za-z0-9_]+"))
      return;`);
    expect((await real(code, 'ldap_injection')).length).toBeGreaterThanOrEqual(1);
  });

  it('an allowlist that admits a metacharacter does not', async () => {
    const code = ldap(`    if (!Regex.IsMatch(input, "^[A-Za-z0-9_()*]+$"))
      return;`);
    expect((await real(code, 'ldap_injection')).length).toBeGreaterThanOrEqual(1);
  });

  it('an inline All(char.IsLetterOrDigit) guard clears the sink', async () => {
    const code = cls(`
  public void Run(XmlDocument doc, string input) {
    if (input.All(char.IsLetterOrDigit)) doc.SelectSingleNode("//user[name='" + input + "']");
  }`);
    expect(await real(code, 'xpath_injection')).toHaveLength(0);
  });

  it('a guard on a different variable does not', async () => {
    const code = cls(`
  public void Run(XmlDocument doc, string input, string other) {
    if (other.All(char.IsLetterOrDigit)) doc.SelectSingleNode("//user[name='" + input + "']");
  }`);
    expect((await real(code, 'xpath_injection')).length).toBeGreaterThanOrEqual(1);
  });

  const compile = (extra: string) => cls(`
  public void Run(string data) {
    int? parsedNum = null;
    try { parsedNum = int.Parse(data); } catch (FormatException) { }
    if (parsedNum != null)
    {
      StringBuilder sourceCode = new StringBuilder("");
      sourceCode.Append("public class C { public int Sum() { return (10 + " + data.ToString() + "); } }");
${extra}
      var provider = System.CodeDom.Compiler.CodeDomProvider.CreateProvider("CSharp");
      provider.CompileAssemblyFromSource(new System.CodeDom.Compiler.CompilerParameters(), sourceCode.ToString());
    }
  }`);

  it('a value proven numeric is safe in the builder it was appended to', async () => {
    expect(await real(compile(''), 'code_injection')).toHaveLength(0);
  });

  it('the same builder with one unvalidated append is not', async () => {
    const code = cls(`
  public void Run(string data, string other) {
    int? parsedNum = null;
    try { parsedNum = int.Parse(data); } catch (FormatException) { }
    if (parsedNum != null)
    {
      StringBuilder sourceCode = new StringBuilder("");
      sourceCode.Append("return (10 + " + data.ToString() + ");");
      sourceCode.Append(other);
      var provider = System.CodeDom.Compiler.CodeDomProvider.CreateProvider("CSharp");
      provider.CompileAssemblyFromSource(new System.CodeDom.Compiler.CompilerParameters(), sourceCode.ToString());
    }
  }`);
    expect((await real(code, 'code_injection')).length).toBeGreaterThanOrEqual(1);
  });
});

describe('C# ssrf: constant host and host allowlist (#518 B, D)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const fetch = (body: string, extra = '') => cls(`
  public async Task Run(string input) {
${body}
  }
${extra}`);

  it('a URL literal that fixes the host is not ssrf', async () => {
    const code = fetch(`    var v = System.Uri.EscapeDataString(input);
    await new HttpClient().GetAsync("https://api.internal.example.com/?x=" + v);`);
    expect(await anyFlow(code)).toHaveLength(0);
  });

  it('a URL literal that leaves the host open is', async () => {
    const code = fetch(`    await new HttpClient().GetAsync("https://api.internal.example.com" + input);`);
    expect((await real(code, 'ssrf')).length).toBeGreaterThanOrEqual(1);
  });

  it('a host compared to a constant guards the request', async () => {
    const code = fetch(`    var host = new Uri(input).Host;
    if (host == "api.internal.example.com") await new HttpClient().GetAsync(input);`);
    expect(await real(code, 'ssrf')).toHaveLength(0);
  });

  it('the same guard held in a bool', async () => {
    const code = fetch(`    var ok = new System.Uri(input).Host == "api.internal.example.com";
    if (ok) await new HttpClient().GetAsync(input);`);
    expect(await real(code, 'ssrf')).toHaveLength(0);
  });

  it('the same guard in a helper, with an early return', async () => {
    const code = fetch(`    if (!IsAllowed(input))
      return;
    await new HttpClient().GetAsync(input);`, `
  static readonly string[] Allowed = { "api.internal.example.com" };
  static bool IsAllowed(string candidate) {
    return System.Array.IndexOf(Allowed, new System.Uri(candidate).Host) >= 0;
  }`);
    expect(await real(code, 'ssrf')).toHaveLength(0);
  });

  it('a helper that does not look at the host is no guard', async () => {
    const code = fetch(`    if (!IsAllowed(input))
      return;
    await new HttpClient().GetAsync(input);`, `
  static bool IsAllowed(string candidate) {
    return candidate.Length < 200;
  }`);
    expect((await real(code, 'ssrf')).length).toBeGreaterThanOrEqual(1);
  });

  it('a guard on another value does not cover the request', async () => {
    const code = cls(`
  public async Task Run(string input, string other) {
    var host = new Uri(other).Host;
    if (host == "api.internal.example.com") await new HttpClient().GetAsync(input);
  }`);
    expect((await real(code, 'ssrf')).length).toBeGreaterThanOrEqual(1);
  });

  it('BaseAddress set next to constructor arguments, relative path in a variable', async () => {
    const code = fetch(`    var handler = new HttpClientHandler { AllowAutoRedirect = false };
    var client = new HttpClient(handler) { BaseAddress = new System.Uri("https://api.internal.example.com/") };
    var relative = "lookup/" + System.Uri.EscapeDataString(input);
    await client.GetAsync(relative);`);
    expect(await anyFlow(code)).toHaveLength(0);
  });
});

describe('C# callee: the tainted argument must reach the sink (#286 A)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const wrapper = (callee: string) => cls(`
  public IActionResult Find() {
    var name = Request.Query["name"].ToString();
    RunByName(name);
    return Ok();
  }
  private void RunByName(string n) {
${callee}
  }`);

  it('a parameterised query in the callee is clean', async () => {
    const code = wrapper(`    var cmd = new SqlCommand("SELECT * FROM u WHERE n = @n", conn);
    cmd.Parameters.AddWithValue("@n", n);
    cmd.ExecuteReader();`);
    expect(await real(code, 'sql_injection')).toHaveLength(0);
  });

  it('a concatenated query in the callee is reported', async () => {
    const code = wrapper(`    var cmd = new SqlCommand("SELECT * FROM u WHERE n = '" + n + "'", conn);
    cmd.ExecuteReader();`);
    expect((await real(code, 'sql_injection')).length).toBeGreaterThanOrEqual(1);
  });

  it('and still is in a file with Windows line endings', async () => {
    const code = wrapper(`    var cmd = new SqlCommand("SELECT * FROM u WHERE n = '" + n + "'", conn);
    cmd.ExecuteReader();`).replace(/\n/g, '\r\n');
    expect((await real(code, 'sql_injection')).length).toBeGreaterThanOrEqual(1);
  });
});
