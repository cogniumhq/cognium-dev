/**
 * Java `try`, `try`-with-resources, `catch` and `finally` in the DFG: locals
 * declared there get defs, resources are defs scoped to the statement, and
 * uses inside and after reach them.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { buildDFG } from '../../src/core/extractors/dfg.js';
import { analyze } from '../../src/index.js';

const CODE = `class A {
  int f(javax.sql.DataSource ds, String id) throws Exception {
    try (java.sql.Connection c = ds.getConnection(); java.sql.Statement s = c.createStatement(); existing) {
      String q = "SELECT * FROM t WHERE id = '" + id + "'";
      java.sql.ResultSet rs = s.executeQuery(q);
      return rs.next() ? 1 : 0;
    } catch (java.sql.SQLException | IllegalStateException e) {
      String m = e.getMessage();
      return m.length();
    } finally {
      int z = 1;
    }
  }
}`;

describe('Java DFG: try statements', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('records defs for resources, try-body, catch-parameter and finally locals', async () => {
    const dfg = buildDFG(await parse(CODE, 'java'));
    const at = (v: string) => dfg.defs.find(d => d.variable === v);
    expect(at('c')).toMatchObject({ line: 3, kind: 'local' });
    expect(at('s')).toMatchObject({ line: 3, kind: 'local' });
    expect(at('q')).toMatchObject({ line: 4 });
    expect(at('rs')).toMatchObject({ line: 5 });
    expect(at('e')).toMatchObject({ line: 7 });
    expect(at('m')).toMatchObject({ line: 8 });
    expect(at('z')).toMatchObject({ line: 11 });
    // `existing` is a use of an outer variable, not a new def
    expect(at('existing')).toBeUndefined();
  });

  it('links uses inside the try to those defs', async () => {
    const dfg = buildDFG(await parse(CODE, 'java'));
    const def = (v: string) => dfg.defs.find(d => d.variable === v)!.id;
    const useOf = (v: string, line: number) => dfg.uses.find(u => u.variable === v && u.line === line);
    expect(useOf('s', 5)?.def_id).toBe(def('s'));
    expect(useOf('q', 5)?.def_id).toBe(def('q'));
    expect(useOf('rs', 6)?.def_id).toBe(def('rs'));
    expect(useOf('e', 8)?.def_id).toBe(def('e'));
    expect(useOf('id', 4)?.def_id).toBe(dfg.defs.find(d => d.variable === 'id' && d.kind === 'param')!.id);
    expect(dfg.chains?.some(c => c.from_def === def('q') && c.to_def === def('rs'))).toBe(true);
  });

  it('a value declared before the try and assigned inside reaches a use after it', async () => {
    const code = `class B { String g(String in) {
  String out = "";
  try { out = in.trim(); } catch (RuntimeException e) { out = "x"; }
  return out;
} }`;
    const dfg = buildDFG(await parse(code, 'java'));
    const ret = dfg.uses.find(u => u.variable === 'out' && u.line === 4);
    expect(ret?.def_id).not.toBeNull();
  });

  it('leaves JavaScript try statements as they were', async () => {
    const dfg = buildDFG(await parse(`function f(x) { try { const y = x; } catch (e) { } }`, 'javascript'), undefined, 'javascript');
    expect(dfg.defs.find(d => d.variable === 'y')).toBeUndefined();
  });

  it('a tainted value used inside a try-with-resources body now reaches its sink through locals', async () => {
    const ir = await analyze(`import java.sql.*; import javax.servlet.http.*;
class C { int f(HttpServletRequest req, javax.sql.DataSource ds) throws Exception {
  String id = req.getParameter("id");
  try (Connection c = ds.getConnection(); Statement s = c.createStatement()) {
    String q = "SELECT * FROM t WHERE id = '" + id + "'";
    ResultSet rs = s.executeQuery(q);
    return rs.next() ? 1 : 0;
  }
} }`, 'C.java', 'java');
    expect(ir.taint.flows?.some(f => f.sink_type === 'sql_injection' && f.sink_line === 6)).toBe(true);
  });
});
