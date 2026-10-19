/**
 * cognium-dev #816 — flow-sanitize `log_injection` / `custom_wrapper` safe
 * mirror must stay clean (nightly sast-validation regression).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, analyzeProject, initAnalyzer } from '../../src/analyzer.js';

const logInj = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'log_injection' && !f.sanitized);

const servlet = (helper: string[], logLine: string, extraImports: string[] = []) =>
  analyze(
    [
      'import javax.servlet.http.*;',
      'import java.util.logging.Logger;',
      ...extraImports,
      'public class V06CustomWrapperSafe extends HttpServlet {',
      ...helper.map(l => '    ' + l),
      '    public void wrapped(HttpServletRequest req) {',
      '        ' + logLine,
      '    }',
      '}',
    ].join('\n'),
    'V06CustomWrapperSafe.java',
    'java',
  );

describe('#816 Java custom CRLF log wrapper safe mirror', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('static helper with chained replace strips log_injection', async () => {
    const r = await servlet(
      [
        'private static String stripLogChars(String s) {',
        '    return s.replace("\\r", "_").replace("\\n", "_").replace("\\t", "_");',
        '}',
      ],
      'Logger.getLogger("app").info("user=" + stripLogChars(req.getParameter("user")));',
    );
    expect(logInj(r).length).toBe(0);
  });

  it('instance helper with replaceAll char class strips log_injection', async () => {
    const r = await servlet(
      [
        'private String stripLogChars(String s) {',
        '    return s.replaceAll("[\\r\\n\\t]", "_");',
        '}',
      ],
      'Logger.getLogger("app").info("user=" + stripLogChars(req.getParameter("user")));',
    );
    expect(logInj(r).length).toBe(0);
  });

  it('helper that only replaces spaces still fires log_injection', async () => {
    const r = await servlet(
      [
        'private static String stripLogChars(String s) {',
        '    return s.replace(" ", "-");',
        '}',
      ],
      'Logger.getLogger("app").info("user=" + stripLogChars(req.getParameter("user")));',
    );
    expect(logInj(r).length).toBeGreaterThan(0);
  });

  it('raw parameter without wrapper still fires log_injection', async () => {
    const r = await servlet(
      [],
      'Logger.getLogger("app").info("user=" + req.getParameter("user"));',
    );
    expect(logInj(r).length).toBeGreaterThan(0);
  });

  it('cross-file static CRLF helper keeps the controller log clean', async () => {
    const helper = [
      'public final class StripUtil {',
      '  private StripUtil() {}',
      '  public static String strip(String s) {',
      '    return s.replace("\\r", "_").replace("\\n", "_").replace("\\t", "_");',
      '  }',
      '}',
    ].join('\n');
    const ctrl = [
      'import javax.servlet.http.*;',
      'import java.util.logging.Logger;',
      'public class V06CustomWrapperSafe extends HttpServlet {',
      '  public void wrapped(HttpServletRequest req) {',
      '    Logger.getLogger("app").info("user=" + StripUtil.strip(req.getParameter("user")));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyzeProject([
      { filePath: 'StripUtil.java', code: helper, language: 'java' },
      { filePath: 'V06CustomWrapperSafe.java', code: ctrl, language: 'java' },
    ]);
    const paths = (r.taint_paths ?? []).filter(p => p.sink.type === 'log_injection');
    expect(paths.length).toBe(0);
  });
});
