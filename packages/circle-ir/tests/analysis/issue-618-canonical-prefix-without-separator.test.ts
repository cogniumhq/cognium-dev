/**
 * cognium-dev#618 — `getCanonicalPath().startsWith(base)` was credited as a
 * path-traversal guard even when `base` has no trailing separator.
 *
 * A string-prefix check against a bare canonical path is the prefix-confusion
 * bypass (`/srv/data-evil` starts with `/srv/data`); that is the ESAPI
 * CVE-2022-23457 `getValidDirectoryPath` shape. The guard is credited only
 * when the base cannot be proven to lack a trailing separator — a separator
 * at the end of it, resolved through local variables, keeps the credit.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import {
  javaCallArgument,
  javaCanonicalBaseLacksSeparator,
  javaCanonicalStartsWithAllBare,
} from '../../src/analysis/java-canonical-prefix.js';

const traversal = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal' && !f.sanitized);

const servlet = (decl: string[], base: string) =>
  analyze(
    [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class ArchiveReader extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '    File store = new File("/var/archive");',
      '    File entry = new File(store, req.getParameter("entry"));',
      ...decl.map(l => '    ' + l),
      `    if (!entry.getCanonicalPath().startsWith(${base})) {`,
      '      throw new IOException("outside the archive");',
      '    }',
      '    new FileInputStream(entry).close();',
      '  }',
      '}',
    ].join('\n'),
    'ArchiveReader.java',
    'java',
  );

describe('#618 canonical-path prefix guard needs a separator', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('fires for the library shape: parent canonical path, no separator (CVE-2022-23457)', async () => {
    const r = await analyze(
      [
        'import java.io.*;',
        'public class FolderRules {',
        '  public String checkedFolder(String label, String requested, File allowedRoot) throws IOException {',
        '    File folder = new File( requested );',
        '    if ( !folder.exists() ) throw new IOException("missing");',
        '    if ( !folder.getCanonicalPath().startsWith(allowedRoot.getCanonicalPath() ) ) {',
        '      throw new IOException("outside");',
        '    }',
        '    return folder.getCanonicalPath();',
        '  }',
        '}',
      ].join('\n'),
      'FolderRules.java',
      'java',
    );
    expect(traversal(r).some(f => f.sink_line === 4)).toBe(true);
  });

  it('fires when the base is a bare canonical path inline', async () => {
    expect(traversal(await servlet([], 'store.getCanonicalPath()')).length).toBeGreaterThan(0);
  });

  it('fires when the bare base is held in a variable (one and two hops)', async () => {
    expect(traversal(await servlet(['String prefix = store.getCanonicalPath();'], 'prefix')).length).toBeGreaterThan(0);
    expect(
      traversal(await servlet(['String rootText = store.getCanonicalPath();', 'String prefix = rootText;'], 'prefix')).length,
    ).toBeGreaterThan(0);
  });

  it('fires for getCanonicalFile().getPath() with no separator', async () => {
    expect(traversal(await servlet([], 'store.getCanonicalFile().getPath()')).length).toBeGreaterThan(0);
  });

  it('fires when File.separator is joined on the LEFT of the canonical path', async () => {
    expect(traversal(await servlet([], 'File.separator + store.getCanonicalPath()')).length).toBeGreaterThan(0);
  });

  it('fires when a non-separator suffix is appended (+ "X" or + "/foo")', async () => {
    expect(traversal(await servlet(['String prefix = store.getCanonicalPath() + "X";'], 'prefix')).length).toBeGreaterThan(0);
    expect(traversal(await servlet(['String prefix = store.getCanonicalPath() + "/foo";'], 'prefix')).length).toBeGreaterThan(0);
  });

  it('fires when a compound assignment appends a non-separator', async () => {
    expect(
      traversal(await servlet(['String prefix = store.getCanonicalPath();', 'prefix += "X";'], 'prefix')).length,
    ).toBeGreaterThan(0);
  });

  it('stays clean when the separator is appended inline', async () => {
    expect(traversal(await servlet([], 'store.getCanonicalPath() + File.separator')).length).toBe(0);
  });

  it('stays clean when the separator-anchored base is held in a variable', async () => {
    expect(
      traversal(await servlet(['String prefix = store.getCanonicalPath() + File.separator;'], 'prefix')).length,
    ).toBe(0);
    expect(traversal(await servlet(['String prefix = store.getCanonicalPath() + "/";'], 'prefix')).length).toBe(0);
  });

  it('stays clean when the separator is added on a later assignment or a second hop', async () => {
    expect(
      traversal(await servlet(['String prefix = store.getCanonicalPath();', "prefix = prefix + '/';"], 'prefix')).length,
    ).toBe(0);
    expect(
      traversal(await servlet(['String prefix = store.getCanonicalPath();', 'prefix += File.separator;'], 'prefix')).length,
    ).toBe(0);
    expect(
      traversal(
        await servlet(['String rootText = store.getCanonicalPath();', 'String prefix = rootText + File.separatorChar;'], 'prefix'),
      ).length,
    ).toBe(0);
  });

  it('stays clean for a constant base', async () => {
    expect(traversal(await servlet([], '"/var/archive/"')).length).toBe(0);
  });

  it('keeps the credit for a base it cannot resolve (parameter or field)', async () => {
    expect(traversal(await servlet([], 'this.archiveRoot')).length).toBe(0);
  });
});

describe('java-canonical-prefix helpers', () => {
  it('extracts a balanced call argument, skipping string contents', () => {
    const t = 'x.startsWith(a.b(")") + "(")';
    expect(javaCallArgument(t, t.indexOf('('))).toBe('a.b(")") + "("');
    expect(javaCallArgument('f(a', 1)).toBeNull();
  });

  it('classifies bases', () => {
    const lines = ['void m() {', '  String b = r.getCanonicalPath();', '  if (x) {}'];
    expect(javaCanonicalBaseLacksSeparator(lines, 2, 'b')).toBe(true);
    expect(javaCanonicalBaseLacksSeparator(lines, 2, 'r.getPath()')).toBe(false);
    expect(javaCanonicalBaseLacksSeparator(lines, 2, 'unknown')).toBe(false);
    expect(javaCanonicalBaseLacksSeparator(lines, 2, 'r.getCanonicalPath() + "\\\\"')).toBe(false);
  });

  it('does not resolve across a method header', () => {
    const lines = ['  String b = r.getCanonicalPath();', '}', 'void n() {', '  if (x) {}'];
    expect(javaCanonicalBaseLacksSeparator(lines, 3, 'b')).toBe(false);
  });

  it('method-level check requires every canonical startsWith to be bare', () => {
    expect(javaCanonicalStartsWithAllBare('if (!a.getCanonicalPath().startsWith(b.getCanonicalPath())) throw x;')).toBe(true);
    expect(
      javaCanonicalStartsWithAllBare(
        'if (!a.getCanonicalPath().startsWith(b.getCanonicalPath())) throw x;\nif (!a.getCanonicalPath().startsWith(b.getCanonicalPath() + File.separator)) throw x;',
      ),
    ).toBe(false);
    expect(javaCanonicalStartsWithAllBare('no guard here')).toBe(false);
  });
});
