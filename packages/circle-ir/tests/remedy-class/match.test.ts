import { describe, it, expect } from 'vitest';
import {
  analyzeProject,
  pathSetDiff,
  remedyClassOf,
  loadSafeConstructTable,
  TableRefused,
} from '../../src/index.js';
import type { ProjectAnalysis, RemedyClassResult } from '../../src/index.js';

/*
 * Synthetic tables and Java fixtures written for these tests. They use the
 * `safe-construct-table@0.1` vocabulary; row ids, wording and code are this
 * file's own.
 */

const HEAD = (cwe: number, extraSources = ''): string => `format: safe-construct-table@0.1
check-set: example/java
cwe: ${cwe}
cwe-list-version: '4.20'
language: java
version: 1.0.0
settles: signal
sources:
  doc:
    kind: vendor-docs
    publisher: Example
    title: Example API notes
    url: https://example.org/api
    fetched: '2026-10-29'
    quote: Example.
${extraSources}`;

const SQL_TABLE = `${HEAD(89)}
sinks:
  - id: stmt
    call: { type: java.sql.Statement, methods: [execute, executeQuery, executeUpdate], arg: 0 }
  - id: prep
    call: { type: java.sql.Connection, methods: [prepareStatement], arg: 0 }
constructs:
  - id: S89-1
    class: safe
    remedy-class: bind-parameters
    applies-to: [stmt, prep]
    match:
      all:
        - { name: p, call: { type: java.sql.Connection, methods: [prepareStatement], arg: 0 }, arg-is: untainted, role: sink-replacement }
        - { name: b, call: { type: java.sql.PreparedStatement, methods: ["set*"], arg: 1 }, arg-is: tainted, role: binder }
        - { order: [p, b] }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: S89-2
    class: safe
    remedy-class: identifier-allowlist
    applies-to: [stmt]
    match: { call: { type: java.lang.Object, methods: ["*"], arg: 0 }, arg-is: from-allowlist, role: sink-replacement }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: W89-1
    class: weak
    remedy-class: bind-parameters
    applies-to: [prep]
    match: { call: { type: java.sql.Connection, methods: [prepareStatement], arg: 0 }, arg-is: tainted, role: sink-replacement }
    level: SHOULD
    basis: own
    sources: [doc]
  - id: W89-9
    class: weak
    remedy-class: bind-parameters
    applies-to: [stmt]
    retired: 1.0.0
    match: { sink-removed: true }
    level: SHOULD
    basis: own
    sources: [doc]
`;

const CMD_TABLE = `${HEAD(78)}
sinks:
  - id: exec
    call: { type: java.lang.Runtime, methods: [exec], arg: 0 }
  - id: pb
    call: { type: java.lang.ProcessBuilder, ctor: true, methods: [], arg: all }
constructs:
  - id: S78-1
    class: safe
    remedy-class: argument-vector
    applies-to: [exec, pb]
    match:
      all:
        - { call: { type: java.lang.Object, methods: ["*"], arg: 0 }, arg-is: untainted, role: sink-replacement }
        - { missing: { call: { type: java.lang.Object, methods: ["*"], arg: 0 }, arg-literal-in: [sh, bash, cmd], role: sink-replacement } }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: S78-2
    class: safe
    remedy-class: library-call
    applies-to: [exec, pb]
    match: { sink-removed: true }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: W78-1
    class: weak
    remedy-class: argument-vector
    applies-to: [exec, pb]
    match:
      all:
        - { call: { type: java.lang.Object, methods: ["*"], arg: 0 }, arg-literal-in: [sh, bash, cmd], role: sink-replacement }
        - { call: { type: java.lang.Object, methods: ["*"], arg: all }, arg-is: tainted, role: sink-replacement }
    level: SHOULD
    basis: own
    sources: [doc]
`;

const XSS_TABLE = `${HEAD(79)}
sinks:
  - id: writer
    call: { type: java.io.PrintWriter, methods: [print, println, write], arg: 0 }
  - id: view
    template: { engine: thymeleaf, construct: "th:utext" }
constructs:
  - id: S79-1
    class: safe
    remedy-class: contextual-encoding
    applies-to: [writer]
    context: html-content
    match: { call: { type: org.owasp.encoder.Encode, static: true, methods: [forHtml], arg: 0 }, arg-is: tainted, role: sanitizer }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: W79-1
    class: weak
    remedy-class: contextual-encoding
    applies-to: [writer]
    context: js-string
    match: { call: { type: org.owasp.encoder.Encode, static: true, methods: [forHtml], arg: 0 }, role: sanitizer }
    level: SHOULD
    basis: own
    sources: [doc]
  - id: S79-2
    class: safe
    remedy-class: auto-escaping-template
    applies-to: [view]
    match: { template: { engine: thymeleaf, construct: "th:text" }, role: sink-replacement }
    level: SHOULD
    basis: cited
    sources: [doc]
`;

const FILE = 'src/main/java/demo/Handler.java';

async function project(code: string): Promise<ProjectAnalysis> {
  return analyzeProject([{ code, filePath: FILE, language: 'java' }]);
}

async function observe(cwe: number, table: string, before: string, after: string): Promise<RemedyClassResult> {
  const b = await project(before);
  const a = await project(after);
  return remedyClassOf(pathSetDiff(b, a, { cwe }), b, a, loadSafeConstructTable(table));
}

const sqlClass = (body: string): string => `package demo;
import java.sql.*;
import javax.servlet.http.*;
public class Handler {
  public int find(HttpServletRequest req, Connection c) throws SQLException {
${body}
  }
}`;

const SQL_BASE = sqlClass(`    String id = req.getParameter("id");
    Statement s = c.createStatement();
    ResultSet rs = s.executeQuery("SELECT n FROM t WHERE id = '" + id + "'");
    return rs.next() ? 1 : 0;`);

const SQL_BIND = sqlClass(`    String id = req.getParameter("id");
    PreparedStatement p = c.prepareStatement("SELECT n FROM t WHERE id = ?");
    p.setString(1, id);
    ResultSet rs = p.executeQuery();
    return rs.next() ? 1 : 0;`);

const SQL_BIND_TRY = sqlClass(`    String id = req.getParameter("id");
    try (PreparedStatement p = c.prepareStatement("SELECT n FROM t WHERE id = ?")) {
      p.setString(1, id);
      ResultSet rs = p.executeQuery();
      return rs.next() ? 1 : 0;
    }`);

const SQL_PARSE = sqlClass(`    int id = Integer.parseInt(req.getParameter("id"));
    Statement s = c.createStatement();
    ResultSet rs = s.executeQuery("SELECT n FROM t WHERE id = " + id);
    return rs.next() ? 1 : 0;`);

const SQL_GONE = `package demo;
public class Handler {
  public int other() { return 0; }
}`;

const cmdClass = (body: string, imports = ''): string => `package demo;
import java.io.*;
import java.util.*;
import javax.servlet.http.*;
${imports}public class Handler {
  public int log(HttpServletRequest req) throws Exception {
${body}
  }
}`;

const CMD_BASE = cmdClass(`    String rev = req.getParameter("rev");
    Process p = Runtime.getRuntime().exec("git log " + rev);
    return p.waitFor();`);

const CMD_ARGV = cmdClass(`    String rev = req.getParameter("rev");
    Process p = new ProcessBuilder(List.of("git", "log", "--end-of-options", rev)).start();
    return p.waitFor();`);

const CMD_SHELL = cmdClass(`    String rev = req.getParameter("rev");
    Process p = new ProcessBuilder("sh", "-c", "git log " + rev).start();
    return p.waitFor();`);

const CMD_LIBRARY = cmdClass(`    String rev = req.getParameter("rev");
    return rev.length();`);

const xssClass = (body: string): string => `package demo;
import java.io.*;
import javax.servlet.http.*;
public class Handler {
  public void show(HttpServletRequest req, HttpServletResponse resp) throws IOException {
${body}
  }
}`;

const XSS_BASE = xssClass(`    String q = req.getParameter("q");
    PrintWriter out = resp.getWriter();
    out.print("<p>" + q + "</p>");`);

const XSS_ENCODED = xssClass(`    String q = req.getParameter("q");
    PrintWriter out = resp.getWriter();
    out.print("<p>" + org.owasp.encoder.Encode.forHtml(q) + "</p>");`);

describe('remedyClassOf — CWE-89', () => {
  it('a bind-parameter fix matches the bind row, and only it', async () => {
    const r = await observe(89, SQL_TABLE, SQL_BASE, SQL_BIND);
    expect(r.sinks).toHaveLength(1);
    const s = r.sinks[0];
    expect(s).toMatchObject({ match: 'S89-1', class: 'safe', change: 'removed', taintSeeds: 'sources' });
    expect(s.sink).toMatchObject({ tableSink: 'stmt', via: 'call', file: FILE });
    expect(s.rows.map(x => x.id)).toEqual(['S89-1']);
    expect(s.rows[0]).toMatchObject({ class: 'safe', remedyClass: 'bind-parameters' });
    expect(s.rows[0].steps.map(x => [x.path, x.holds])).toEqual([
      ['/match/all/0', true],
      ['/match/all/1', true],
      ['/match/all/2', true],
    ]);
    expect(s.rows[0].steps[0].at?.file).toBe(FILE);
    // the allowlist row is observed and does not hold (the SQL text is a constant, not a choice)
    expect(s.abstainedRows).toEqual([]);
    expect(s.reason).toBeUndefined();
    expect(s.anchor).toBe(`${s.pathKey}:sink`);
  });

  it('carries the table identity, digest included', async () => {
    const r = await observe(89, SQL_TABLE, SQL_BASE, SQL_BIND);
    const digest = loadSafeConstructTable(SQL_TABLE).digest;
    expect(r.table).toEqual({ format: 'safe-construct-table@0.1', cwe: 89, language: 'java', version: '1.0.0', digest });
    expect(r.sinks[0].table).toEqual(r.table);
  });

  it('matches the bind row inside try-with-resources', async () => {
    const r = await observe(89, SQL_TABLE, SQL_BASE, SQL_BIND_TRY);
    expect(r.sinks[0].match).toBe('S89-1');
  });

  it('reports a closed path no row describes as unrecognized, or abstained when only an unobservable row applies', async () => {
    const r = await observe(89, SQL_TABLE, SQL_BASE, SQL_PARSE);
    expect(r.sinks.length).toBeGreaterThan(0);
    for (const s of r.sinks) {
      expect(['abstained', 'unrecognized']).toContain(s.match);
      expect(s.rows).toEqual([]);
      expect(s.class).toBeUndefined();
    }
    const noAllowlist = SQL_TABLE.replace(/ {2}- id: S89-2[\s\S]*?sources: \[doc\]\n/, '');
    const r2 = await observe(89, noAllowlist, SQL_BASE, SQL_PARSE);
    expect(r2.sinks.length).toBeGreaterThan(0);
    for (const s of r2.sinks) expect(s).toMatchObject({ match: 'unrecognized', reason: 'no-row-holds' });
  });

  it('reports declaration-not-found when the method is gone and no row can hold', async () => {
    const r = await observe(89, SQL_TABLE, SQL_BASE, SQL_GONE);
    expect(r.sinks).toHaveLength(1);
    // the retired sink-removed row is skipped, so nothing can hold
    expect(r.sinks[0]).toMatchObject({ match: 'unrecognized', reason: 'declaration-not-found' });
    // a template-only row on the sink would make it abstain instead
    const withTemplate = SQL_TABLE.replace('constructs:\n', `constructs:
  - id: S89-8
    class: safe
    remedy-class: bind-parameters
    applies-to: [stmt]
    match: { template: { engine: jsp, construct: "sql:query" } }
    level: SHOULD
    basis: cited
    sources: [doc]
`);
    const r2 = await observe(89, withTemplate, SQL_BASE, SQL_GONE);
    expect(r2.sinks[0]).toMatchObject({ match: 'abstained', abstainedRows: [{ id: 'S89-8', reason: 'template-not-read' }] });
  });

  it('labels a sink the table does not list as sink-not-in-table', async () => {
    const promptOnly = SQL_TABLE.replace("  - id: stmt\n    call: { type: java.sql.Statement, methods: [execute, executeQuery, executeUpdate], arg: 0 }\n", '')
      .replace(/applies-to: \[stmt, prep\]/, 'applies-to: [prep]')
      .replace(/applies-to: \[stmt\]/g, 'applies-to: [prep]');
    const r = await observe(89, promptOnly, SQL_BASE, SQL_BIND);
    expect(r.sinks[0]).toMatchObject({ match: 'unrecognized', reason: 'sink-not-in-table', sink: { tableSink: 'unlisted' }, rows: [] });
  });

  it('observes nothing for a path that stayed open', async () => {
    const r = await observe(89, SQL_TABLE, SQL_BASE, SQL_BASE.replace('return rs.next() ? 1 : 0;', '\n    return rs.next() ? 1 : 0;'));
    expect(r.sinks).toEqual([]);
  });

  it('is deterministic', async () => {
    const a = await observe(89, SQL_TABLE, SQL_BASE, SQL_BIND);
    const b = await observe(89, SQL_TABLE, SQL_BASE, SQL_BIND);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe('remedyClassOf — CWE-78', () => {
  it('an argument vector with a constant program matches the argv row', async () => {
    const r = await observe(78, CMD_TABLE, CMD_BASE, CMD_ARGV);
    expect(r.sinks).toHaveLength(1);
    expect(r.sinks[0]).toMatchObject({ match: 'S78-1', class: 'safe', sink: { tableSink: 'exec' } });
    expect(r.sinks[0].sink.tableSinkMatch).toBe('unresolved');
  });

  it('an argument vector that keeps the shell matches the weak row', async () => {
    const r = await observe(78, CMD_TABLE, CMD_BASE, CMD_SHELL);
    const closed = r.sinks.find(s => s.sink.tableSink === 'exec');
    expect(closed).toMatchObject({ match: 'W78-1', class: 'weak' });
    expect(closed?.rows.map(x => x.id)).toEqual(['W78-1']);
  });

  it('removing the process call matches the library-call row', async () => {
    const r = await observe(78, CMD_TABLE, CMD_BASE, CMD_LIBRARY);
    expect(r.sinks[0]).toMatchObject({ match: 'S78-2', class: 'safe', change: 'removed' });
  });
});

describe('remedyClassOf — CWE-79 (sanitizer role, multiple, template rows)', () => {
  it('an encoder that two rows describe is multiple, with no class', async () => {
    const r = await observe(79, XSS_TABLE, XSS_BASE, XSS_ENCODED);
    expect(r.sinks).toHaveLength(1);
    const s = r.sinks[0];
    expect(s.match).toBe('multiple');
    expect(s.class).toBeUndefined();
    expect(s.rows.map(x => [x.id, x.class, x.context])).toEqual([
      ['S79-1', 'safe', 'html-content'],
      ['W79-1', 'weak', 'js-string'],
    ]);
  });
});

describe('remedyClassOf — inputs', () => {
  it('throws TableRefused on a refused table, with its problems', async () => {
    const b = await project(SQL_BASE);
    const a = await project(SQL_BIND);
    const diff = pathSetDiff(b, a, { cwe: 89 });
    const bad = loadSafeConstructTable(SQL_TABLE.replace('role: binder', 'role: setter'));
    let caught: unknown;
    try {
      remedyClassOf(diff, b, a, bad);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TableRefused);
    expect((caught as TableRefused).problems[0]).toMatchObject({ code: 'bad-value' });
    expect((caught as TableRefused).digest).toBe(bad.digest);
  });

  it('refuses a table of another CWE', async () => {
    const b = await project(SQL_BASE);
    const a = await project(SQL_BIND);
    expect(() => remedyClassOf(pathSetDiff(b, a, { cwe: 89 }), b, a, loadSafeConstructTable(CMD_TABLE))).toThrow(/table is CWE-78/);
  });
});
