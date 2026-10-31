import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import {
  capabilities, DRIVER, SCHEMA_VERSION, readTree, runPathSetDiff, runRemedyClass,
  type RunResult,
} from '../src/index.js';

/* Synthetic trees and table written for these tests. */

let tmp: string;
const write = (root: string, files: Record<string, string>): string => {
  for (const [p, code] of Object.entries(files)) {
    const full = join(root, p);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, code);
  }
  return root;
};
const tree = (name: string, files: Record<string, string>): string => write(join(tmp, name), files);

const SQL = 'src/main/java/demo/Dao.java';
const sql = (body: string): string => `package demo;
import java.sql.*;
import javax.servlet.http.*;
public class Dao {
  public int find(HttpServletRequest req, Connection c) throws SQLException {
    String id = req.getParameter("id");
${body}
  }
}`;
const SQL_BASE = sql(`    ResultSet rs = c.createStatement().executeQuery("SELECT n FROM t WHERE id = '" + id + "'");
    return rs.next() ? 1 : 0;`);
const SQL_FIX = sql(`    PreparedStatement p = c.prepareStatement("SELECT n FROM t WHERE id = ?");
    p.setString(1, id);
    ResultSet rs = p.executeQuery();
    return rs.next() ? 1 : 0;`);

const IO = 'src/main/java/demo/Reader.java';
const io = (body: string): string => `package demo;
import java.nio.file.*;
import javax.servlet.http.*;
public class Reader {
  private final Path base = Path.of("/srv/data");
  public byte[] read(HttpServletRequest req) throws Exception {
    String name = req.getParameter("name");
${body}
  }
}`;
const IO_BASE = io(`    return Files.readAllBytes(base.resolve(name));`);
const IO_CHECKED = io(`    Path real = base.resolve(name).toRealPath();
    if (!real.startsWith(base.toRealPath())) {
      throw new IllegalArgumentException("outside");
    }
    return Files.readAllBytes(real);`);

const TABLE = `format: safe-construct-table@0.1
check-set: example/java
cwe: 89
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
sinks:
  - id: stmt
    call: { type: java.sql.Statement, methods: [execute, executeQuery], arg: 0 }
constructs:
  - id: S89-1
    class: safe
    remedy-class: bind-parameters
    applies-to: [stmt]
    match:
      all:
        - { name: p, call: { type: java.sql.Connection, methods: [prepareStatement], arg: 0 }, arg-is: untainted }
        - { name: b, call: { type: java.sql.PreparedStatement, methods: ["set*"], arg: 1 }, arg-is: tainted, role: binder }
        - { order: [p, b] }
    level: SHOULD
    basis: cited
    sources: [doc]
`;

let sqlPair: { before: string; after: string };
let ioPair: { before: string; after: string };

beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), 'code-facts-'));
  sqlPair = { before: tree('sql-before', { [SQL]: SQL_BASE }), after: tree('sql-after', { [SQL]: SQL_FIX }) };
  ioPair = { before: tree('io-before', { [IO]: IO_BASE }), after: tree('io-after', { [IO]: IO_CHECKED }) };
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const site = (r: RunResult) => r.anchors.find(a => a.anchor === 'site');
const paths = (r: RunResult) => r.anchors.filter(a => a.anchor !== 'site');

describe('identity', () => {
  it('declares its driver, schema and capabilities', () => {
    expect(DRIVER).toEqual({ id: 'code-facts', family: 'static', version: '0.1.0' });
    expect(SCHEMA_VERSION).toBe('0.1');
    expect(capabilities()).toEqual(['path-set-diff', 'remedy-class', 'dependency-calls']);
  });
});

describe('readTree', () => {
  it('reads the language files only, sorted, skipping excluded directories and links', () => {
    const root = tree('walk', {
      'b/B.java': 'class B {}', 'a/A.java': 'class A {}', 'a/notes.txt': 'x',
      'target/Gen.java': 'class Gen {}', 'node_modules/x/X.java': 'class X {}',
    });
    symlinkSync(join(root, 'a/A.java'), join(root, 'a/Link.java'));
    const files = readTree(root, 'java');
    expect(files.map(f => f.path)).toEqual(['a/A.java', 'b/B.java']);
    expect(files[0].digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(readTree(root, 'java', []).map(f => f.path)).toContain('target/Gen.java');
  });
});

describe('runPathSetDiff', () => {
  it('reports each path of the class by key, and a site anchor with per-version facts', async () => {
    const r = await runPathSetDiff(sqlPair, {}, { cwe: 89, language: 'java' });
    expect(r).toMatchObject({ driver: DRIVER, schemaVersion: '0.1', capability: 'path-set-diff' });
    expect(r.environmentDigest).toMatch(/^sha256:/);
    expect(paths(r)).toHaveLength(1);
    expect(paths(r)[0].observation).toMatchObject({ change: 'removed', state: { before: 'present', after: 'absent' } });
    expect(site(r)?.observation).toMatchObject({ cwe: 'CWE-89', counts: { removed: 1 }, pins: { before: { complete: true } } });
  });

  it('computes branch facts itself: a containment check reads as guarded', async () => {
    const r = await runPathSetDiff(ioPair, {}, { cwe: 22, language: 'java' });
    const entries = paths(r).map(a => a.observation as { change: string });
    expect(entries.map(e => e.change)).toEqual(['guarded']);
  });

  it('is deterministic, and an unrelated file changes only the site digest', async () => {
    const a = await runPathSetDiff(sqlPair, {}, { cwe: 89, language: 'java' });
    const b = await runPathSetDiff(sqlPair, {}, { cwe: 89, language: 'java' });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    const extra = { before: sqlPair.before, after: tree('sql-after-extra', { [SQL]: SQL_FIX, 'src/main/java/demo/Other.java': 'package demo; class Other {}' }) };
    const c = await runPathSetDiff(extra, {}, { cwe: 89, language: 'java' });
    expect(paths(c)[0].inputDigest).toBe(paths(a)[0].inputDigest);
    expect(site(c)?.inputDigest).not.toBe(site(a)?.inputDigest);
  });
});

describe('runRemedyClass', () => {
  it('observes the row a closed sink matches, with the table digest', async () => {
    const r = await runRemedyClass(sqlPair, { table: TABLE }, { cwe: 89, language: 'java' });
    expect(r.capability).toBe('remedy-class');
    const sinks = paths(r);
    expect(sinks).toHaveLength(1);
    expect(sinks[0].observation).toMatchObject({ match: 'S89-1', class: 'safe', table: { cwe: 89, version: '1.0.0' } });
    expect(site(r)?.observation).toMatchObject({ sinks: 1, byMatch: { row: 1 }, scope: 'closed' });
  });

  it('reuses a path-set-diff result and gives the same answer', async () => {
    const ps = await runPathSetDiff(sqlPair, {}, { cwe: 89, language: 'java' });
    const a = await runRemedyClass(sqlPair, { table: TABLE }, { cwe: 89, language: 'java' });
    const b = await runRemedyClass(sqlPair, { table: TABLE }, { cwe: 89, language: 'java', pathSet: ps });
    expect(JSON.stringify(b)).toBe(JSON.stringify(a));
    await expect(runRemedyClass(sqlPair, { table: TABLE }, { cwe: 89, language: 'java', pathSet: { ...ps, capability: 'remedy-class' } }))
      .rejects.toThrow(/path-set-diff result/);
    await expect(runRemedyClass(sqlPair, { table: TABLE }, { cwe: 89, language: 'java', pathSet: { ...ps, anchors: [] } }))
      .rejects.toThrow(/no site anchor/);
  });

  it('refuses a table it cannot read, with no observation', async () => {
    await expect(runRemedyClass(sqlPair, { table: TABLE.replace('role: binder', 'role: setter') }, { cwe: 89, language: 'java' }))
      .rejects.toMatchObject({ name: 'TableRefused' });
  });

  it('scope all also observes sinks of paths left open', async () => {
    const open = { before: sqlPair.before, after: tree('sql-open', { [SQL]: SQL_BASE.replace('return rs', '\n    return rs') }) };
    const closed = await runRemedyClass(open, { table: TABLE }, { cwe: 89, language: 'java' });
    expect(paths(closed)).toHaveLength(0);
    const all = await runRemedyClass(open, { table: TABLE }, { cwe: 89, language: 'java', scope: 'all' });
    expect(paths(all)).toHaveLength(1);
    expect(paths(all)[0].observation).toMatchObject({ change: 'unchanged', match: 'unrecognized' });
    expect(site(all)?.observation).toMatchObject({ scope: 'all', byMatch: { unrecognized: 1 } });
  });
});

describe('templates (Java trees)', () => {
  const CTRL = 'src/main/java/demo/SearchController.java';
  const CONTROLLER = `package demo;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
@org.springframework.stereotype.Controller
public class SearchController {
  @GetMapping("/search")
  public String search(@RequestParam String q, Model model) {
    model.addAttribute("q", q);
    return "search";
  }
}`;
  const VIEW = 'src/main/webapp/WEB-INF/views/search.jsp';
  const XSS_TABLE = TABLE.replace('cwe: 89', 'cwe: 79').replace(/sinks:[\s\S]*$/, `sinks:
  - id: cout
    template: { engine: jsp, construct: "c:out" }
constructs:
  - id: S79-2
    class: safe
    remedy-class: auto-escaping-template
    applies-to: [cout]
    match: { template: { engine: jsp, construct: "c:out", attribute: escapeXml, value: [absent, "true"] }, role: sink-replacement }
    level: SHOULD
    basis: cited
    sources: [doc]
`);

  it('reads views beside the code: a fix in the view is observed with its row and changes the path digest', async () => {
    const pair = {
      before: tree('view-before', { [CTRL]: CONTROLLER, [VIEW]: '<p>Results for ${q}</p>' }),
      after: tree('view-after', { [CTRL]: CONTROLLER, [VIEW]: '<p>Results for <c:out value="${q}"/></p>' }),
    };
    const ps = await runPathSetDiff(pair, {}, { cwe: 79, language: 'java' });
    const e = paths(ps)[0].observation as { change: string; templateChanged?: boolean };
    expect(e).toMatchObject({ change: 'unchanged', templateChanged: true });
    const r = await runRemedyClass(pair, { table: XSS_TABLE }, { cwe: 79, language: 'java', pathSet: ps });
    expect(paths(r)[0].observation).toMatchObject({ match: 'S79-2', templateChanged: true });
    const same = { before: pair.before, after: tree('view-after-2', { [CTRL]: CONTROLLER, [VIEW]: '<p>Results for <c:out value="${q}" escapeXml="true"/></p>' }) };
    const ps2 = await runPathSetDiff(same, {}, { cwe: 79, language: 'java' });
    expect(paths(ps2)[0].inputDigest).not.toBe(paths(ps)[0].inputDigest);
  });
});

describe('outputContext', () => {
  it('is passed through when asked for and absent otherwise', async () => {
    const plain = await runRemedyClass(sqlPair, { table: TABLE }, { cwe: 89, language: 'java' });
    expect((site(plain)?.observation as Record<string, unknown>).outputContext).toBeUndefined();
    expect((paths(plain)[0].observation as { sink: Record<string, unknown> }).sink.outputContext).toBeUndefined();
    const asked = await runRemedyClass(sqlPair, { table: TABLE }, { cwe: 89, language: 'java', outputContext: true });
    expect(site(asked)?.observation).toMatchObject({ outputContext: true });
    expect((paths(asked)[0].observation as { sink: Record<string, unknown> }).sink.outputContext).toBe('unknown');
  });
});

