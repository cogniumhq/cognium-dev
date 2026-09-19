/**
 * cognium-dev#387 — `File.getPath` / `File.getAbsolutePath` / `Path.toString`
 * were high-severity `file_input` taint SOURCES.
 *
 * They are pure path PROJECTIONS: they hand back the path the object already
 * holds. They cannot introduce taint that is not already present — if the File
 * was built from untrusted input, propagation carries it — but as blanket
 * sources they turned every program-constructed path into a source, and the
 * enclosing call is usually itself a sink:
 *
 *     File f = new File("/etc/app.conf");
 *     FileInputStream in = new FileInputStream(f.getAbsolutePath());
 *
 * reported `path_traversal` with no untrusted input anywhere in the file,
 * source and sink on the same line. `new FileInputStream(f.getPath())` is an
 * extremely common Java shape, so this fired broadly and seeded cascades: a
 * projection on a `System.out.println` line became a source that then paired
 * with every path sink within range.
 *
 * MEASURED. OWASP Benchmark Java (2740 files) and SecuriBench Micro (254):
 * **zero delta on both** — neither corpus exercises the shape, which is the
 * same blind spot that let it survive (see the category-scoped scoring note in
 * issue-387-java-stdout-not-xss.test.ts). On a real Java project
 * (`alibaba__one-java-agent`, 92 files) it removes 8 detection-level findings
 * and re-attributes 16, with `source_after_sink` falling 21 → 17. All 8 were
 * read individually and all 8 are false positives:
 *
 *   - 3x a source line that sits AFTER its own sinks, on hardcoded test paths;
 *   - 3x `println("… " + dir.getAbsolutePath())` paired with a URL open and a
 *     FileOutputStream 60 lines later, which the printed value never reaches;
 *   - 2x `throw new PluginException("… " + f.getAbsolutePath())` paired with a
 *     `new File(...)` 140 lines away in a different method.
 *
 * The genuine signal in those files — `main(String[] args)` flowing to file
 * operations — survives untouched.
 *
 * NO `listFiles` COVERAGE IS LOST. An earlier revision of this change claimed
 * there was, and used it as a reason to hold the change back. Measured
 * directly, before vs after, for a File taken from `dir.listFiles()`:
 * `getName` 0 flows -> 0 flows, `getAbsolutePath` 0 -> 0, `getPath` 1 -> 1.
 * The first two never fired in that shape at all, because class resolution does
 * not resolve a for-each variable to `File`. Modelling the directory listing as
 * a source is still worth doing, but it is additive and not a regression here.
 *
 * WHY THE CLASSLESS ENTRIES HAD TO GO TOO — and this is the load-bearing
 * lesson. The first revision removed only the class-scoped `File.getPath`, and
 * a *classless* `{ method: 'getPath', type: 'file_input' }` 130 lines further
 * down (in an unrelated "Jenkins/CI pipeline sources" block, with no class and
 * no `languages` scope) kept matching `f.getPath()`. So the change did not do
 * what it claimed: the self-flow FP survived for the more common spelling. The
 * same trap then repeated one level down — dropping class-scoped
 * `Path.getFileName` left the classless `getFileName` firing on
 * `Paths.get("/etc/app.conf").getFileName()`.
 *
 * Hence a test per *spelling*, not per concept. Each `constant …` case below
 * corresponds to an entry that had to be removed, and the `getPath` and
 * `getFileName` ones exist specifically because the first revision's tests
 * covered only `getAbsolutePath` and therefore passed while the fix was
 * incomplete.
 *
 * The classless removals were measured non-load-bearing first: with them gone,
 * `Part.getFileName`, `BodyPart`/`MimeBodyPart.getFileName` and
 * `MultipartFile.getOriginalFilename` all still bind their sources from their
 * own class-scoped entries.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

describe('#387 — File path projections are not taint sources', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not report a constant path read through getAbsolutePath', async () => {
    const code = [
      'import java.io.*;',
      'public class B {',
      '  void load() throws IOException {',
      '    File f = new File("/etc/app.conf");',
      '    FileInputStream in = new FileInputStream(f.getAbsolutePath());',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'B.java', 'java');
    expect(r.taint.sources).toHaveLength(0);
    expect(r.taint.flows.filter(f => f.sink_type === 'path_traversal')).toHaveLength(0);
  });

  it('still reports a genuinely tainted path, via propagation', async () => {
    // The point of the change: the real finding never depended on the
    // projection being a source. It comes from the http_param source and
    // survives, so removing the projection costs no detection here.
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class A extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse r) throws IOException {',
      '    String p = req.getParameter("p");',
      '    File f = new File(p);',
      '    FileInputStream in = new FileInputStream(f.getAbsolutePath());',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'A.java', 'java');
    expect(r.taint.sources.some(s => s.type === 'http_param')).toBe(true);
    expect(r.taint.flows.filter(f => f.sink_type === 'path_traversal').length).toBeGreaterThan(0);
  });

  it('keeps Zip-Slip: archive entry names are still sources', async () => {
    const code = [
      'import java.io.*;',
      'import java.util.zip.*;',
      'public class Z {',
      '  void unzip(ZipInputStream zis, File dir) throws IOException {',
      '    ZipEntry e = zis.getNextEntry();',
      '    File out = new File(dir, e.getName());',
      '    FileOutputStream fos = new FileOutputStream(out);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Z.java', 'java');
    expect(r.taint.sources.some(s => s.type === 'file_input')).toBe(true);
  });

  it('keeps upload filenames: MultipartFile / Part are still sources', async () => {
    const code = [
      'import org.springframework.web.multipart.MultipartFile;',
      'import java.io.*;',
      'public class U {',
      '  void save(MultipartFile mf, File dir) throws IOException {',
      '    String name = mf.getOriginalFilename();',
      '    FileOutputStream fos = new FileOutputStream(new File(dir, name));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'U.java', 'java');
    expect(r.taint.sources.some(s => s.type === 'file_input')).toBe(true);
  });
  it.each([
    ['getPath        (classless entry defeated the first revision)', 'f.getPath()'],
    ['getName        (projection by the same argument)', '"/d/" + f.getName()'],
  ])('does not report a constant path read through %s', async (_label, expr) => {
    const code = [
      'import java.io.*;',
      'public class B {',
      '  void load() throws IOException {',
      '    File f = new File("/etc/app.conf");',
      `    FileInputStream in = new FileInputStream(${expr});`,
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'B.java', 'java');
    expect(r.taint.sources).toHaveLength(0);
    expect(r.taint.flows.filter(f => f.sink_type === 'path_traversal')).toHaveLength(0);
  });

  it('does not report a constant Paths.get(...).getFileName()', async () => {
    // The classless `getFileName` kept this firing after the class-scoped
    // `Path.getFileName` was dropped — the second instance of the same trap.
    const code = [
      'import java.io.*;',
      'import java.nio.file.*;',
      'public class P {',
      '  void go() throws IOException {',
      '    Path pt = Paths.get("/etc/app.conf");',
      '    FileInputStream in = new FileInputStream("/d/" + pt.getFileName());',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'P.java', 'java');
    expect(r.taint.sources).toHaveLength(0);
    expect(r.taint.flows.filter(f => f.sink_type === 'path_traversal')).toHaveLength(0);
  });

  it('still detects a tainted path through getName and getFileName, via propagation', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class A extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse r) throws IOException {',
      '    String p = req.getParameter("p");',
      '    File f = new File(p);',
      '    FileInputStream in = new FileInputStream("/d/" + f.getName());',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'A.java', 'java');
    expect(r.taint.sources.some(s => s.type === 'http_param')).toBe(true);
    expect(r.taint.flows.filter(f => f.sink_type === 'path_traversal').length).toBeGreaterThan(0);
  });

  it('keeps Part.getFileName binding a source without the classless entry', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'import java.io.*;',
      'public class U extends HttpServlet {',
      '  protected void doPost(HttpServletRequest req, HttpServletResponse r) throws IOException {',
      '    Part part = req.getPart("f");',
      '    String name = part.getFileName();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'U.java', 'java');
    expect(r.taint.sources.some(s => s.type === 'file_input')).toBe(true);
  });
});
