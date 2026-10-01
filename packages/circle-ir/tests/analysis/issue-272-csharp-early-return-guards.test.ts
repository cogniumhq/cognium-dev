/**
 * #272 (remaining clusters) and #286-B — a validating predicate followed by an
 * EARLY RETURN is a guard, and the value reaching a later sink is validated.
 *
 *   if (Array.IndexOf(Allowed, u.Host) < 0) return;   // host allow-list
 *   if (!input.All(char.IsLetterOrDigit)) return;     // character class
 *
 * Both safe mirrors were clean of their family finding after #272's earlier
 * fixes and still reported, because the guard itself was never credited.
 *
 * Scoped to predicates that are self-evidently validating — allow-list
 * membership and character-class checks. A user-defined boolean helper
 * (`if (!IsAllowed(input)) return;`, #286-B) is deliberately NOT credited:
 * trusting an arbitrary predicate by name would silence a real flow whenever
 * the helper does not actually validate, and no test would catch it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flows = async (code: string) => {
  const r = await analyze(code, 'P.cs', 'csharp');
  return r.taint?.flows ?? [];
};

describe('#272 C# early-return guards are credited', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('credits a host allow-list checked on a derivation of the tainted value', async () => {
    // The guard validates `u.Host`; the sink uses `input`, from which `u` was
    // built. Allow-listing the host constrains where `input` can point.
    expect(await flows(`using System; using System.Net.Http; using System.Threading.Tasks;
public class P { static string[] Allowed = {"a.com"};
 public async Task R(string input) {
  var u = new Uri(input);
  if (Array.IndexOf(Allowed, u.Host) < 0) return;
  var c = new HttpClient();
  await c.GetStringAsync(input);
} }`)).toHaveLength(0);
  });

  it('credits a character-class validation', async () => {
    expect(await flows(`using System.Linq; using System.Xml;
public class P { public void R(string input, XmlDocument doc) {
  if (!input.All(char.IsLetterOrDigit)) return;
  doc.SelectSingleNode("/a[@b='" + input + "']");
} }`)).toHaveLength(0);
  });

  it('credits allow-list membership via Contains', async () => {
    expect(await flows(`using System.Collections.Generic; using System.Net.Http; using System.Threading.Tasks;
public class P { static HashSet<string> Allowed = new HashSet<string>();
 public async Task R(string input) {
  if (!Allowed.Contains(input)) return;
  var c = new HttpClient();
  await c.GetStringAsync(input);
} }`)).toHaveLength(0);
  });

  it('still reports with no guard at all', async () => {
    expect((await flows(`using System.Net.Http; using System.Threading.Tasks;
public class P { public async Task R(string input) {
  var c = new HttpClient();
  await c.GetStringAsync(input);
} }`)).length).toBeGreaterThan(0);
  });

  it('still reports when the guard body FALLS THROUGH', async () => {
    // Only the rejecting direction counts — a guard that logs and continues
    // has not stopped anything.
    expect((await flows(`using System.Linq; using System.Xml;
public class P { public void R(string input, XmlDocument doc) {
  if (!input.All(char.IsLetterOrDigit)) { System.Console.WriteLine("odd"); }
  doc.SelectSingleNode("/a[@b='" + input + "']");
} }`)).length).toBeGreaterThan(0);
  });

  it('still reports when the sink precedes the guard', async () => {
    expect((await flows(`using System.Linq; using System.Xml;
public class P { public void R(string input, XmlDocument doc) {
  doc.SelectSingleNode("/a[@b='" + input + "']");
  if (!input.All(char.IsLetterOrDigit)) return;
} }`)).length).toBeGreaterThan(0);
  });

  it('still reports when an UNRELATED variable is the one guarded', async () => {
    expect((await flows(`using System.Linq; using System.Xml;
public class P { public void R(string input, string other, XmlDocument doc) {
  if (!other.All(char.IsLetterOrDigit)) return;
  doc.SelectSingleNode("/a[@b='" + input + "']");
} }`)).length).toBeGreaterThan(0);
  });
});
