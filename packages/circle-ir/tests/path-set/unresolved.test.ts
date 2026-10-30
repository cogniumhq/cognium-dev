import { describe, it, expect } from 'vitest';
import { analyzeProject, pathSetOf, pathSetDiff } from '../../src/index.js';
import type { ProjectAnalysis } from '../../src/index.js';

/* Synthetic Java written for these tests. */
const FILE = 'src/main/java/demo/Repo.java';

const JPA = `package demo;
import javax.persistence.EntityManager;
import javax.servlet.http.*;
public class Repo {
  private EntityManager em;
  public Object find(HttpServletRequest req) {
    String name = req.getParameter("name");
    return em.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'").getResultList();
  }
}`;

const PROJECT_IFACE = `package demo;
import java.sql.*;
import javax.servlet.http.*;
interface Cleaner { String clean(String s); }
class Strip implements Cleaner { public String clean(String s) { return s.trim(); } }
class Upper implements Cleaner { public String clean(String s) { return s.toUpperCase(); } }
public class Repo {
  private Cleaner cleaner;
  public int find(HttpServletRequest req, Connection c) throws SQLException {
    String name = req.getParameter("name");
    String v = cleaner.clean(name);
    ResultSet rs = c.createStatement().executeQuery("SELECT 1 FROM t WHERE n = '" + v + "'");
    return rs.next() ? 1 : 0;
  }
}`;

const PLAIN = `package demo;
import java.sql.*;
import javax.servlet.http.*;
public class Repo {
  public int find(HttpServletRequest req, Connection c) throws SQLException {
    String name = req.getParameter("name");
    ResultSet rs = c.createStatement().executeQuery("SELECT 1 FROM t WHERE n = '" + name + "'");
    return rs.next() ? 1 : 0;
  }
}`;

const load = (code: string): Promise<ProjectAnalysis> => analyzeProject([{ code, filePath: FILE, language: 'java' }]);

describe('unresolved edges per path', () => {
  it('the sink call dispatched on a library interface: one site, at the sink, not in the project', async () => {
    const set = pathSetOf(await load(JPA), { cwe: 89 });
    expect(set.paths).toHaveLength(1);
    expect(set.paths[0].unresolved.count).toBe(1);
    expect(set.paths[0].unresolved.sites[0]).toMatchObject({
      file: FILE, line: 8, type: 'virtual_dispatch', atSink: true, inProject: false,
    });
  });

  it('a dispatch on a project interface the resolver binds is not unresolved', async () => {
    const set = pathSetOf(await load(PROJECT_IFACE), { cwe: 89 });
    expect(set.paths.length).toBeGreaterThan(0);
    expect(set.paths.every(p => p.unresolved.count === 0)).toBe(true);
  });

  it('an unresolved dispatch on a path line whose candidates are project types: in the project, not at the sink', async () => {
    const p = await load(PROJECT_IFACE);
    p.files[0].analysis.unresolved.push({
      type: 'virtual_dispatch', reason: 'several_implementations',
      context: { code: 'cleaner.clean(name)', line: 11, candidates: ['Strip.clean', 'Upper.clean'] },
    } as never);
    p.files[0].analysis.unresolved.push({
      type: 'reflection', reason: 'elsewhere', context: { code: 'x()', line: 3 },
    } as never);
    const sites = pathSetOf(p, { cwe: 89 }).paths.flatMap(x => x.unresolved.sites);
    expect(sites.length).toBeGreaterThan(0);
    expect(sites.every(s => s.line === 11)).toBe(true);
    expect(sites[0]).toMatchObject({ type: 'virtual_dispatch', atSink: false, inProject: true });
  });

  it('a path with nothing unresolved reports zero', async () => {
    const set = pathSetOf(await load(PLAIN), { cwe: 89 });
    expect(set.paths.every(p => p.unresolved.count === 0 && p.unresolved.sites.length === 0)).toBe(true);
  });

  it('an unresolved cross-file call from a path line is a site; one elsewhere is not', async () => {
    const p = await load(PLAIN);
    p.cross_file_calls = [
      { id: 'x1', from: { file: FILE, method: 'find', line: 6 }, to: { file: 'src/main/java/demo/Other.java', method: 'go', line: 3 }, args_mapping: [], resolved: false },
      { id: 'x2', from: { file: FILE, method: 'find', line: 2 }, to: { file: 'src/main/java/demo/Other.java', method: 'go', line: 3 }, args_mapping: [], resolved: false },
      { id: 'x3', from: { file: FILE, method: 'find', line: 7 }, to: { file: 'src/main/java/demo/Other.java', method: 'go', line: 3 }, args_mapping: [], resolved: true },
    ];
    const set = pathSetOf(p, { cwe: 89 });
    expect(set.paths[0].unresolved.sites).toEqual([
      { file: FILE, line: 6, type: 'cross_file_call', reason: 'unresolved_cross_file_call', code: 'find -> src/main/java/demo/Other.java#go', atSink: false, inProject: true },
    ]);
  });

  it('is carried on both sides of a diff', async () => {
    const d = pathSetDiff(await load(JPA), await load(JPA.replace('return em', '\n    return em')), { cwe: 89 });
    expect(d.entries[0].before?.unresolved.count).toBe(1);
    expect(d.entries[0].after?.unresolved.sites[0].line).toBe(9);
  });
});
