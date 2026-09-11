/**
 * cognium-dev #272 — C# allowlist character strip was not credited.
 *
 * `var safe = Regex.Replace(input, "[^a-zA-Z0-9]", "");` deletes every character
 * *not* in the set, so the survivors are exactly the set. With no metacharacter
 * left, the value is inert for the injection families whose exploitation
 * requires one — yet the sink still fired.
 *
 * Added to `CSHARP_SANITIZER_RES`, which already seeds from
 * `V = sanitizer(...)` assignments and takes a transitive closure over
 * derivations, so `"(cn=" + safe + ")"` stays sanitized.
 *
 * The negatives are the substance of this file. A **negated** class is what
 * makes the argument work, and the surviving set has to be metacharacter-free:
 *
 *   "[^a-zA-Z0-9]"   deletes all but alphanumerics        -> credited
 *   "[<>]"           a blacklist; enumerates what to drop -> NOT credited
 *   "[^a-zA-Z0-9']"  keeps the single quote alive         -> NOT credited
 *   <variable>       computed, possibly attacker-shaped   -> NOT credited
 *   replacement "';DROP"                                  -> NOT credited
 *
 * The quote case matters most: crediting it would suppress a real SQL injection,
 * because a surviving `'` defeats the escaping the query depends on.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const unsan = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === type && !f.sanitized);

const cs = (body: string[], extraUsing: string[] = []) =>
  analyze(
    [
      'using System.Text.RegularExpressions;',
      ...extraUsing,
      'public class T {',
      '    public object Run(string input, object ctx) {',
      ...body.map(l => '        ' + l),
      '    }',
      '}',
    ].join('\n'),
    'T.cs',
    'csharp'
  );

const STRIP = 'var safe = Regex.Replace(input, "[^a-zA-Z0-9]", "");';

describe('#272 C# allowlist strip is credited across the metacharacter families', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('ldap_injection — DirectorySearcher after the strip', async () => {
    const r = await cs([
      STRIP,
      'return new System.DirectoryServices.DirectorySearcher("(cn=" + safe + ")").FindOne();',
    ]);
    expect(unsan(r, 'ldap_injection').length).toBe(0);
  });

  it('xpath_injection — SelectSingleNode after the strip', async () => {
    const r = await cs([
      STRIP,
      'return ((System.Xml.XmlDocument)ctx).SelectSingleNode("//user[@name=\'" + safe + "\']");',
    ]);
    expect(unsan(r, 'xpath_injection').length).toBe(0);
  });

  it('command_injection — shell argument after the strip', async () => {
    const r = await cs([
      STRIP,
      'System.Diagnostics.Process.Start("/bin/sh", "-c \\"grep " + safe + "\\"");',
      'return null;',
    ]);
    expect(unsan(r, 'command_injection').length).toBe(0);
  });

  it('sql_injection — concatenated query after the strip', async () => {
    const r = await cs([
      STRIP,
      'return new System.Data.SqlClient.SqlCommand("SELECT * FROM u WHERE n=\'" + safe + "\'", null);',
    ]);
    expect(unsan(r, 'sql_injection').length).toBe(0);
  });

  it('the same sinks WITHOUT the strip still fire', async () => {
    const ldap = await cs([
      'return new System.DirectoryServices.DirectorySearcher("(cn=" + input + ")").FindOne();',
    ]);
    expect(unsan(ldap, 'ldap_injection').length).toBeGreaterThan(0);

    const sql = await cs([
      'return new System.Data.SqlClient.SqlCommand("SELECT * FROM u WHERE n=\'" + input + "\'", null);',
    ]);
    expect(unsan(sql, 'sql_injection').length).toBeGreaterThan(0);
  });
});

describe('#272 the strip must be a metacharacter-free ALLOWLIST', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a blacklist class is NOT credited', async () => {
    // `[<>]` enumerates what to remove and silently misses everything else.
    const r = await cs([
      'var safe = Regex.Replace(input, "[<>]", "");',
      'return new System.DirectoryServices.DirectorySearcher("(cn=" + safe + ")").FindOne();',
    ]);
    expect(unsan(r, 'ldap_injection').length).toBeGreaterThan(0);
  });

  it('an allowlist that KEEPS a quote is NOT credited', async () => {
    // The most important negative: a surviving `'` defeats the query's escaping,
    // so crediting this would suppress a real SQL injection.
    const r = await cs([
      'var safe = Regex.Replace(input, "[^a-zA-Z0-9\']", "");',
      'return new System.Data.SqlClient.SqlCommand("SELECT * FROM u WHERE n=\'" + safe + "\'", null);',
    ]);
    expect(unsan(r, 'sql_injection').length).toBeGreaterThan(0);
  });

  it('a computed (non-literal) pattern is NOT credited', async () => {
    const r = await analyze(
      [
        'using System.Text.RegularExpressions;',
        'public class T {',
        '    public object Run(string input, string pattern) {',
        '        var safe = Regex.Replace(input, pattern, "");',
        '        return new System.DirectoryServices.DirectorySearcher("(cn=" + safe + ")").FindOne();',
        '    }',
        '}',
      ].join('\n'),
      'T.cs',
      'csharp'
    );
    expect(unsan(r, 'ldap_injection').length).toBeGreaterThan(0);
  });

  it('an unsafe replacement string is NOT credited', async () => {
    const r = await cs([
      'var safe = Regex.Replace(input, "[^a-zA-Z0-9]", "\';DROP");',
      'return new System.Data.SqlClient.SqlCommand("SELECT * FROM u WHERE n=\'" + safe + "\'", null);',
    ]);
    expect(unsan(r, 'sql_injection').length).toBeGreaterThan(0);
  });
});
