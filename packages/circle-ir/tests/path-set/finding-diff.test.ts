/**
 * S-C7 `finding-diff` (conformis.security, techspec #210): changed lines, and
 * the findings at the new version with a source or sink on a changed line and
 * no match at the old version.
 */
import { describe, it, expect } from 'vitest';
import { analyzeProject, deriveStableIds, findingDiff, diffLines, splitLines } from '../../src/index.js';
import type { FindingDiffSide, StableIdFile } from '../../src/index.js';

const DAO = 'src/app/Dao.java';

const BASE = `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Dao {
  public void find(HttpServletRequest req, Connection c) throws Exception {
    String id = req.getParameter("id");
    PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id = ?");
    p.setString(1, id);
    p.executeQuery();
  }
}`;

/** The fix adds a concatenated query on a new line: a new weakness. */
const ADDS_SQLI = `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Dao {
  public void find(HttpServletRequest req, Connection c) throws Exception {
    String id = req.getParameter("id");
    PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id = ?");
    p.setString(1, id);
    p.executeQuery();
    c.createStatement().executeQuery("SELECT * FROM audit WHERE id = " + id);
  }
}`;

/** Lines moved down, nothing else changed. */
const SHIFTED = `package app;
import java.sql.*;
import javax.servlet.http.*;
// a comment that moves every line down

public class Dao {
  public void find(HttpServletRequest req, Connection c) throws Exception {
    String id = req.getParameter("id");
    PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id = ?");
    p.setString(1, id);
    p.executeQuery();
  }
}`;

async function side(code: string, withIds: boolean): Promise<FindingDiffSide> {
  const project = await analyzeProject([{ code, filePath: DAO, language: 'java' }]);
  const out: FindingDiffSide = { project, texts: { [DAO]: code } };
  if (withIds) out.stableIds = { [DAO]: (await deriveStableIds(code, DAO, 'java')) as StableIdFile };
  return out;
}

describe('diffLines', () => {
  it('reports inserted lines and maps the rest to their old lines', () => {
    const d = diffLines(['a', 'b', 'c'], ['a', 'x', 'b', 'c']);
    expect(d?.changed).toEqual([2]);
    expect(d?.toOld.get(3)).toBe(2);
    expect(d?.toOld.get(4)).toBe(3);
  });
  it('maps carried lines through replacements and deletions in the middle', () => {
    const d = diffLines(['a', 'b', 'c', 'd', 'e', 'f'], ['a', 'x', 'c', 'e', 'y', 'f']);
    expect(d?.changed).toEqual([2, 5]);
    expect(d?.toOld.get(3)).toBe(3);
    expect(d?.toOld.get(4)).toBe(5);
    expect(d?.toOld.get(6)).toBe(6);
    const e = diffLines(['p', 'q', 'r', 's'], ['q', 'p', 's', 'r']);
    expect(e?.changed.length).toBeGreaterThan(0);
    for (const [n, o] of e?.toOld ?? []) expect(['p', 'q', 'r', 's'][o - 1]).toBe(['q', 'p', 's', 'r'][n - 1]);
  });
  it('gives up past maxD', () => {
    expect(diffLines(['a', 'b'], ['c', 'd'], 1)).toBeNull();
  });
  it('splits like an editor', () => {
    expect(splitLines('a\nb\n')).toEqual(['a', 'b']);
    expect(splitLines('')).toEqual([]);
  });
});

describe('findingDiff', () => {
  for (const withIds of [false, true]) {
    const by = withIds ? 'stable-id' : 'rule-file-line';
    it(`reports a new SQL injection on a changed line (${by})`, async () => {
      const r = findingDiff(await side(BASE, withIds), await side(ADDS_SQLI, withIds));
      expect(r.changedLines[DAO]).toEqual([10]);
      const sqli = r.newFindings.filter(f => f.rule === 'sql_injection');
      expect(sqli).toHaveLength(1);
      expect(sqli[0]).toMatchObject({ file: DAO, line: 10, kind: 'flow', cwe: 'CWE-89' });
      expect(sqli[0].onChangedLine).toContain('sink');
    });

    it(`reports nothing when only lines moved (${by})`, async () => {
      const r = findingDiff(await side(BASE, withIds), await side(SHIFTED, withIds));
      expect(r.newFindings.filter(f => f.kind === 'flow')).toEqual([]);
    });
  }

  it('lists a file that changed but was not analysed as partial', async () => {
    const before = await side(BASE, false);
    const after = await side(BASE, false);
    after.texts['README.md'] = 'new\n';
    const r = findingDiff(before, after);
    expect(r.partial).toContainEqual({ file: 'README.md', reason: 'not-analysed' });
  });

  it('treats an over-large diff as all changed and says so', async () => {
    const r = findingDiff(await side(BASE, false), await side(ADDS_SQLI, false), { maxDiff: 0 });
    expect(r.partial).toContainEqual({ file: DAO, reason: 'diff-too-large' });
  });
});
