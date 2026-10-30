import { describe, it, expect } from 'vitest';
import {
  analyzeProject,
  deriveStableIds,
  pathSetOf,
  pathSetDiff,
  diffPathSets,
  pinFacts,
  changeOf,
  normalizeCwe,
  declAt,
  PATH_KEY_SCHEME,
} from '../../src/index.js';
import type { ProjectAnalysis, SupportedLanguage, StableIdFile, CircleIR } from '../../src/index.js';

type Src = Record<string, string>;

async function project(files: Src, language: SupportedLanguage = 'java'): Promise<ProjectAnalysis> {
  return analyzeProject(Object.entries(files).map(([filePath, code]) => ({ code, filePath, language })));
}

const DAO = 'src/app/Dao.java';

/** Two SQL paths in one method, from two request parameters. */
const BASE = `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Dao {
  public void find(HttpServletRequest req, Connection c) throws Exception {
    String id = req.getParameter("id");
    Statement s = c.createStatement();
    s.executeQuery("SELECT * FROM t WHERE id = " + id);
    String name = req.getParameter("name");
    s.execute("DELETE FROM t WHERE n = '" + name + "'");
  }
}`;

/** BASE with lines inserted above and inside: nothing about the paths changes. */
const SHIFTED = `package app;
import java.sql.*;
import javax.servlet.http.*;
// a comment that moves every line down

public class Dao {
  /** A helper added above, unrelated to the paths. */
  public int unrelated(int x) {
    return x + 1;
  }

  public void find(HttpServletRequest req, Connection c) throws Exception {

    String id = req.getParameter("id");
    Statement s = c.createStatement();
    // still concatenated
    s.executeQuery("SELECT * FROM t WHERE id = " + id);
    String name = req.getParameter("name");

    s.execute("DELETE FROM t WHERE n = '" + name + "'");
  }
}`;

/** Both sinks fixed with bind parameters. */
const FIXED = `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Dao {
  public void find(HttpServletRequest req, Connection c) throws Exception {
    String id = req.getParameter("id");
    PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id = ?");
    p.setString(1, id);
    p.executeQuery();
    String name = req.getParameter("name");
    PreparedStatement d = c.prepareStatement("DELETE FROM t WHERE n = ?");
    d.setString(1, name);
    d.execute();
  }
}`;

/** Only the first sink fixed. */
const PARTIAL = `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Dao {
  public void find(HttpServletRequest req, Connection c) throws Exception {
    String id = req.getParameter("id");
    PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id = ?");
    p.setString(1, id);
    p.executeQuery();
    String name = req.getParameter("name");
    Statement s = c.createStatement();
    s.execute("DELETE FROM t WHERE n = '" + name + "'");
  }
}`;

/** The method holding the paths is removed. */
const REMOVED = `package app;
public class Dao {
  public int unrelated(int x) {
    return x + 1;
  }
}`;

/** Overloads: the same body shape in two methods that differ only by parameter types. */
const OVERLOADS = `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Dao {
  public void find(HttpServletRequest req, Connection c) throws Exception {
    String id = req.getParameter("id");
    c.createStatement().executeQuery("SELECT * FROM t WHERE id = " + id);
  }
  public void find(HttpServletRequest req, Connection c, int limit) throws Exception {
    String id = req.getParameter("id");
    c.createStatement().executeQuery("SELECT * FROM t WHERE id = " + id + " LIMIT " + limit);
  }
  static class Inner {
    public void run(HttpServletRequest req, Connection c) throws Exception {
      String q = req.getParameter("q");
      c.createStatement().execute(q);
    }
  }
}`;

describe('pathSetOf — one tree', () => {
  it('lists every path of the class, keyed and sorted, with qualified declarations for Java', async () => {
    const set = pathSetOf(await project({ [DAO]: BASE }), { cwe: 'CWE-89' });
    expect(set.scheme).toBe(PATH_KEY_SCHEME);
    expect(set.cwe).toBe('CWE-89');
    expect(set.paths).toHaveLength(2);
    expect(set.declKeySchemes).toEqual(['qualified@0.1']);
    expect(set.files).toEqual([DAO]);
    const keys = set.paths.map(p => p.key);
    expect([...keys].sort()).toEqual(keys);
    expect(new Set(keys).size).toBe(2);
    for (const p of set.paths) {
      expect(p.key).toMatch(/^[a-z2-7]{26}$/);
      expect(p.state).toBe('present');
      expect(p.variants).toBe(1);
      expect(p.sink.decl).toEqual({
        scheme: 'qualified@0.1',
        id: `${DAO}#app.Dao.find(HttpServletRequest,Connection)`,
        name: 'app.Dao.find(HttpServletRequest,Connection)',
      });
      expect(p.sink.call).toMatchObject({ class: 'Statement', argPositions: [0] });
      expect(p.source.type).toBe('http_param');
      // no line number in an anchor
      expect(p.source.anchor).not.toMatch(/\|#?\d+\|/);
      expect(p.sink.anchor).toContain('sql_injection:Statement.');
    }
    expect(set.paths.map(p => p.sink.call.method).sort()).toEqual(['execute', 'executeQuery']);
  });

  it('selects by CWE in any spelling and returns nothing for another class', async () => {
    const p = await project({ [DAO]: BASE });
    expect(pathSetOf(p, { cwe: 89 }).paths).toHaveLength(2);
    expect(pathSetOf(p, { cwe: 'cwe-089' }).paths).toHaveLength(2);
    const none = pathSetOf(p, { cwe: 'CWE-78' });
    expect(none.paths).toEqual([]);
    expect(none.files).toEqual([]);
  });

  it('separates overloads and nested types', async () => {
    const set = pathSetOf(await project({ [DAO]: OVERLOADS }), { cwe: 'CWE-89' });
    const decls = set.paths.map(p => p.sink.decl.name).sort();
    expect(decls).toContain('app.Dao.find(HttpServletRequest,Connection)');
    expect(decls).toContain('app.Dao.find(HttpServletRequest,Connection,int)');
    expect(decls.some(d => d.startsWith('app.') && d.endsWith('Inner.run(HttpServletRequest,Connection)'))).toBe(true);
    expect(new Set(set.paths.map(p => p.key)).size).toBe(set.paths.length);
  });

  it('is deterministic', async () => {
    const a = pathSetOf(await project({ [DAO]: BASE }), { cwe: 89 });
    const b = pathSetOf(await project({ [DAO]: BASE }), { cwe: 89 });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe('pathSetDiff — two trees', () => {
  it('keeps every key across an edit that only shifts lines', async () => {
    const d = pathSetDiff(await project({ [DAO]: BASE }), await project({ [DAO]: SHIFTED }), { cwe: 89 });
    expect(d.counts).toEqual({ removed: 0, sanitized: 0, unchanged: 2, added: 0, other: 0 });
    for (const e of d.entries) {
      expect(e.before?.sink.line).not.toBe(e.after?.sink.line);
    }
  });

  it('reports a complete fix as every path closed', async () => {
    const d = pathSetDiff(await project({ [DAO]: BASE }), await project({ [DAO]: FIXED }), { cwe: 89 });
    expect(d.counts.unchanged).toBe(0);
    expect(d.counts.added).toBe(0);
    expect(d.counts.removed + d.counts.sanitized).toBe(2);
    for (const e of d.entries) expect(['removed', 'sanitized']).toContain(e.change);
  });

  it('reports an incomplete fix: one path closed, one unchanged', async () => {
    const d = pathSetDiff(await project({ [DAO]: BASE }), await project({ [DAO]: PARTIAL }), { cwe: 89 });
    expect(d.counts.unchanged).toBe(1);
    expect(d.counts.removed + d.counts.sanitized).toBe(1);
    const open = d.entries.find(e => e.change === 'unchanged');
    expect(open?.after?.sink.call.method).toBe('execute');
  });

  it('reports a removal as removed and the reverse as added', async () => {
    const base = await project({ [DAO]: BASE });
    const gone = await project({ [DAO]: REMOVED });
    const d = pathSetDiff(base, gone, { cwe: 89 });
    expect(d.counts).toMatchObject({ removed: 2, unchanged: 0 });
    expect(d.entries.every(e => e.state.after === 'absent' && e.after === undefined)).toBe(true);
    const r = pathSetDiff(gone, base, { cwe: 89 });
    expect(r.counts).toMatchObject({ added: 2 });
    expect(r.pins.before.pathCount).toBe(0);
    expect(r.pins.after.pathCount).toBe(2);
  });

  it('carries per-pin facts over the union of path files', async () => {
    const d = pathSetDiff(await project({ [DAO]: BASE, 'src/app/Other.java': 'package app; public class Other {}' }), await project({ [DAO]: REMOVED }), { cwe: 89 });
    expect(d.pins.before.complete).toBe(true);
    expect(d.pins.before.flags).toEqual([]);
    expect(d.pins.after.pathCount).toBe(0);
    expect(typeof d.pins.after.unresolved.total).toBe('number');
  });
});

describe('pathSetDiff — moves and sanitizer-only fixes', () => {
  it('a method moved to another type is removed + added, never matched', async () => {
    const moved = BASE.replace('public class Dao {', 'public class Dao {\n  static class Repo {').replace(/\}\s*$/, '}\n}');
    const d = pathSetDiff(await project({ [DAO]: BASE }), await project({ [DAO]: moved }), { cwe: 89 });
    expect(d.counts).toMatchObject({ removed: 2, added: 2, unchanged: 0 });
    const added = d.entries.filter(e => e.change === 'added');
    expect(added.every(e => e.after?.sink.decl.name.includes('Repo.find('))).toBe(true);
  });

  it('a fix that only adds a sanitizer closes the path (removed or sanitized), never unchanged', async () => {
    const XSS = (expr: string): string => `package app;
import java.io.*;
import javax.servlet.http.*;
public class View {
  public void show(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String q = req.getParameter("q");
    resp.getWriter().print("<p>" + ${expr} + "</p>");
  }
}`;
    const d = pathSetDiff(
      await project({ 'src/app/View.java': XSS('q') }),
      await project({ 'src/app/View.java': XSS('org.owasp.encoder.Encode.forHtml(q)') }),
      { cwe: 79 },
    );
    expect(d.entries.length).toBeGreaterThan(0);
    expect(d.counts.unchanged).toBe(0);
    expect(d.counts.removed + d.counts.sanitized).toBeGreaterThan(0);
  });
});

describe('ids@0.1 declarations (JavaScript)', () => {
  const JS = `const express = require('express');
const { exec } = require('child_process');
const app = express();
function run(req, res) {
  const cmd = req.query.cmd;
  exec('ls ' + cmd);
  res.send('ok');
}
app.get('/run', run);
`;
  const JS_SHIFTED = `const express = require('express');
const { exec } = require('child_process');

// moved down
const app = express();
function helper(x) { return x * 2; }

function run(req, res) {
  const cmd = req.query.cmd;

  exec('ls ' + cmd);
  res.send('ok');
}
app.get('/run', run);
`;
  const FILE = 'src/run.js';

  async function withIds(code: string): Promise<{ p: ProjectAnalysis; ids: Record<string, StableIdFile> }> {
    const p = await project({ [FILE]: code }, 'javascript');
    return { p, ids: { [FILE]: await deriveStableIds(code, FILE, 'javascript') } };
  }

  it('keys paths by stable declaration ids when the caller supplies them', async () => {
    const { p, ids } = await withIds(JS);
    const set = pathSetOf(p, { cwe: 78, stableIds: ids });
    expect(set.paths.length).toBeGreaterThan(0);
    expect(set.declKeySchemes).toEqual(['ids@0.1']);
    const runDecl = ids[FILE].decls.find(d => d.name === 'run');
    expect(set.paths[0].sink.decl).toMatchObject({ scheme: 'ids@0.1', id: runDecl?.id });
  });

  it('keeps keys across a line shift under ids@0.1', async () => {
    const a = await withIds(JS);
    const b = await withIds(JS_SHIFTED);
    const d = pathSetDiff(a.p, b.p, { cwe: 78, stableIds: { before: a.ids, after: b.ids } });
    expect(d.entries.length).toBeGreaterThan(0);
    expect(d.entries.every(e => e.change === 'unchanged')).toBe(true);
  });
});

describe('pure helpers', () => {
  it('changeOf is the set table', () => {
    expect(changeOf('present', 'absent')).toBe('removed');
    expect(changeOf('present', 'sanitized')).toBe('sanitized');
    expect(changeOf('present', 'present')).toBe('unchanged');
    expect(changeOf('absent', 'present')).toBe('added');
    expect(changeOf('sanitized', 'present')).toBe('added');
    expect(changeOf('sanitized', 'absent')).toBe('other');
    expect(changeOf('absent', 'sanitized')).toBe('other');
    expect(changeOf('sanitized', 'sanitized')).toBe('other');
  });

  it('normalizeCwe accepts the usual spellings and refuses others', () => {
    expect(normalizeCwe('CWE-89')).toBe('CWE-89');
    expect(normalizeCwe(' cwe-0079 ')).toBe('CWE-79');
    expect(normalizeCwe(22)).toBe('CWE-22');
    expect(() => normalizeCwe('SQLi')).toThrow(/not a CWE id/);
  });

  it('diffPathSets refuses two different classes', () => {
    const empty = (cwe: string) => ({ scheme: PATH_KEY_SCHEME, cwe, paths: [], declKeySchemes: [], files: [] });
    expect(() => diffPathSets(empty('CWE-89'), empty('CWE-79'))).toThrow(/cannot diff/);
  });

  it('declAt falls back to the call extractor method, then the module', () => {
    const ir = {
      types: [],
      calls: [{ method_name: 'f', receiver: null, arguments: [], location: { line: 3, column: 0 }, in_method: 'handler' }],
    } as unknown as CircleIR;
    expect(declAt('a.py', ir, 3)).toEqual({ scheme: 'qualified@0.1', id: 'a.py#<module>.handler', name: '<module>.handler' });
    expect(declAt('a.py', ir, 9)).toEqual({ scheme: 'qualified@0.1', id: 'a.py#<module>', name: '<module>' });
  });

  it('declAt names a field initializer as <init> and uses the module decl when no function holds the line', () => {
    const ir = {
      types: [{ name: 'A', kind: 'class', package: null, extends: null, implements: [], annotations: [], methods: [], fields: [], start_line: 1, end_line: 5 }],
      calls: [],
    } as unknown as CircleIR;
    expect(declAt('A.java', ir, 2).name).toBe('A.<init>');
    const ids = {
      scheme: 'ids@0.1', file: 'm.js', language: 'javascript', module: 'm', partial: false,
      decls: [{ id: 'moduleid', kind: 'module', name: 'm', qualified_name: 'm', start_line: 1, end_line: 10 }],
    } as unknown as StableIdFile;
    expect(declAt('m.js', ir, 2, ids)).toEqual({ scheme: 'ids@0.1', id: 'moduleid', name: 'm' });
  });

  it('pinFacts counts unresolved edges, unresolved cross-file calls, budgets and parse errors', () => {
    const file = (name: string, unresolved: string[], parseOk = true) => ({
      file: name,
      analysis: {
        unresolved: unresolved.map(type => ({ type, reason: '', context: { code: '', line: 1 } })),
        parse_status: { success: parseOk, has_errors: !parseOk, error_count: parseOk ? 0 : 1, error_locations: [] },
      },
    });
    const project = {
      files: [file('a.java', ['virtual_dispatch', 'reflection']), file('b.java', ['dynamic_call'], false), file('c.java', ['taint_propagation'], false)],
      cross_file_calls: [
        { id: '1', from: { file: 'a.java', method: 'm', line: 1 }, to: { file: 'z.java', method: 'n', line: 1 }, args_mapping: [], resolved: false },
        { id: '2', from: { file: 'y.java', method: 'm', line: 1 }, to: { file: 'z.java', method: 'n', line: 1 }, args_mapping: [], resolved: false },
        { id: '3', from: { file: 'a.java', method: 'm', line: 1 }, to: { file: 'b.java', method: 'n', line: 1 }, args_mapping: [], resolved: true },
      ],
      cross_file_budget_exceeded: true,
      per_file_budget_exceeded: true,
      project_size_budget_exceeded: true,
    } as unknown as ProjectAnalysis;
    const facts = pinFacts(project, new Set(['a.java', 'b.java']), 4);
    expect(facts).toEqual({
      pathCount: 4,
      unresolved: { total: 4, byType: { virtual_dispatch: 1, taint_propagation: 1, reflection: 1, dynamic_call: 1 }, onPathFiles: 3 },
      crossFileCallsUnresolved: 1,
      complete: false,
      flags: ['cross_file_budget_exceeded', 'parse-error:b.java', 'per_file_budget_exceeded', 'project_size_budget_exceeded'],
    });
  });
});
