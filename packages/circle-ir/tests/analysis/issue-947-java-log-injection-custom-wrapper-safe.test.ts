/**
 * cognium-dev #947 — flow-sanitize `log_injection` / `custom_wrapper` / java safe
 * mirror (nightly gates-nightly regression). CRLF-stripping helper must suppress
 * log_injection; partial strip and raw echo still fire.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const logInj = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'log_injection' && !f.sanitized);

const servlet = (helper: string[], logLine: string) =>
  [
    'import javax.servlet.http.*;',
    'import java.util.logging.Logger;',
    'public class V06CustomWrapperSafe extends HttpServlet {',
    ...helper.map((l) => '    ' + l),
    '    public void wrapped(HttpServletRequest req) {',
    '        ' + logLine,
    '    }',
    '}',
  ].join('\n');

describe('#947 Java custom_wrapper log_injection safe mirror', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('custom_wrapper CRLF strip stays clean for log_injection', async () => {
    const code = servlet(
      [
        'private static String stripLogChars(String s) {',
        '    return s.replace("\\r", "_").replace("\\n", "_").replace("\\t", "_");',
        '}',
      ],
      'Logger.getLogger("app").info("user=" + stripLogChars(req.getParameter("user")));',
    );
    const ir = await analyze(code, 'V06CustomWrapperSafe.java', 'java');
    expect(logInj(ir)).toEqual([]);
  });

  it('helper that only strips spaces still fires log_injection', async () => {
    const code = servlet(
      [
        'private static String stripLogChars(String s) {',
        '    return s.replace(" ", "-");',
        '}',
      ],
      'Logger.getLogger("app").info("user=" + stripLogChars(req.getParameter("user")));',
    );
    const ir = await analyze(code, 'V06PartialWrapper.java', 'java');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });

  it('recall: raw parameter in log line still emits log_injection', async () => {
    const code = servlet(
      [],
      'Logger.getLogger("app").info("user=" + req.getParameter("user"));',
    );
    const ir = await analyze(code, 'V01BaselineTp.java', 'java');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });
});
