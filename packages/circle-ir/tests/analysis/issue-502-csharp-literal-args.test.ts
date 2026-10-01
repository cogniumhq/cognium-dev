/**
 * C# compile-time literal arguments — split out of #502.
 *
 * `extractCSharpArguments` set `literal` only for `string_literal`, so `null`,
 * `true`, `42` and `'c'` all came back `literal: null` and were
 * indistinguishable from a variable. A sink taint-gated on that argument
 * therefore registered.
 *
 * The measured case is Juliet's DB-setup helper
 * `new SqlCommand(null, connection)`, reported as CWE-89 with a SQL argument
 * that is literally `null` — 1,523 signatures over the 10 scored CWE families
 * once #502 gave those files a source.
 *
 * A compile-time constant cannot carry taint, so a sink on one is always
 * wrong; this removes false positives only.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sinksOf = async (code: string) => {
  const r = await analyze(code, 'P.cs', 'csharp');
  return (r.taint?.sinks ?? []);
};
const litOf = async (code: string) => {
  const r = await analyze(code, 'P.cs', 'csharp');
  return (r.calls ?? []).find(c => c.method_name === 'SqlCommand')?.arguments?.[0]?.literal ?? null;
};

const ctor = (arg: string) => `using System.Data.SqlClient;
public class P { public void R(SqlConnection conn, string sql) {
  var cmd = new SqlCommand(${arg}, conn);
} }`;

describe('C# literal arguments are not taint-carrying (#502)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('null is recognised as a literal and registers no sink', async () => {
    expect(await litOf(ctor('null'))).toBe('null');
    expect(await sinksOf(ctor('null'))).toHaveLength(0);
  });

  it.each([
    ['boolean', 'true'],
    ['integer', '42'],
    ['real', '1.5'],
    ['character', "'c'"],
    ['verbatim string', '@"SELECT 1"'],
  ])('%s literal registers no sink', async (_label, arg) => {
    expect(await sinksOf(ctor(arg))).toHaveLength(0);
  });

  it('a quoted string literal still registers no sink (unchanged)', async () => {
    expect(await sinksOf(ctor('"SELECT 1"'))).toHaveLength(0);
  });

  it('a variable argument still registers the sink', async () => {
    const sinks = await sinksOf(ctor('sql'));
    expect(sinks.some(s => s.type === 'sql_injection')).toBe(true);
  });

  it('an interpolated string is NOT a literal — it is the genuine injection shape', async () => {
    const code = `using System.Data.SqlClient;
public class P { public void R(string input, SqlConnection conn) {
  var cmd = new SqlCommand($"SELECT {input}", conn);
} }`;
    const sinks = await sinksOf(code);
    expect(sinks.some(s => s.type === 'sql_injection')).toBe(true);
  });

  it('concatenation with a variable still registers the sink', async () => {
    const code = `using System.Data.SqlClient;
public class P { public void R(string input, SqlConnection conn) {
  var cmd = new SqlCommand("SELECT " + input, conn);
} }`;
    expect((await sinksOf(code)).some(s => s.type === 'sql_injection')).toBe(true);
  });
});
