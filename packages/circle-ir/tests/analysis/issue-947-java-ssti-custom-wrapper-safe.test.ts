/**
 * cognium-dev #947 — flow-sanitize `ssti` / `custom_wrapper` / java safe
 * mirror (nightly gates-nightly regression). Brace-stripping helper must
 * suppress code_injection into Velocity.evaluate; partial strip and raw
 * interpolation still fire.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const codeInjFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'code_injection' && !f.sanitized);

const codeInjSinks = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.sinks ?? []).filter((s) => s.type === 'code_injection');

const safeMirror = [
  'import org.apache.velocity.app.Velocity;',
  'import javax.servlet.http.*;',
  'public class V06CustomWrapperSafe extends HttpServlet {',
  '    static String companySanitize(String x) {',
  '        return x.replace("{", "").replace("}", "");',
  '    }',
  '    public void render(HttpServletRequest req) throws Exception {',
  '        String n = companySanitize(req.getParameter("n"));',
  '        Velocity.evaluate(null, req.getWriter(), "v", "<p>" + n + "</p>");',
  '    }',
  '}',
].join('\n');

const partialStrip = [
  'import org.apache.velocity.app.Velocity;',
  'import javax.servlet.http.*;',
  'public class V06PartialWrapper extends HttpServlet {',
  '    static String companySanitize(String x) {',
  '        return x.replace("{", "");',
  '    }',
  '    public void render(HttpServletRequest req) throws Exception {',
  '        String n = companySanitize(req.getParameter("n"));',
  '        Velocity.evaluate(null, req.getWriter(), "v", "<p>" + n + "</p>");',
  '    }',
  '}',
].join('\n');

const tpMirror = [
  'import org.apache.velocity.app.Velocity;',
  'import javax.servlet.http.*;',
  'public class V01BaselineTp extends HttpServlet {',
  '    public void render(HttpServletRequest req) throws Exception {',
  '        String n = req.getParameter("n");',
  '        Velocity.evaluate(null, req.getWriter(), "v", "<p>" + n + "</p>");',
  '    }',
  '}',
].join('\n');

describe('#947 Java custom_wrapper ssti safe mirror', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('custom_wrapper brace strip stays clean for code_injection', async () => {
    const ir = await analyze(safeMirror, 'V06CustomWrapperSafe.java', 'java');
    expect(codeInjFlows(ir)).toEqual([]);
  });

  it('helper that only strips open brace still fires code_injection', async () => {
    const ir = await analyze(partialStrip, 'V06PartialWrapper.java', 'java');
    expect(codeInjFlows(ir).length).toBeGreaterThan(0);
  });

  it('recall: raw parameter in template still emits code_injection', async () => {
    const ir = await analyze(tpMirror, 'V01BaselineTp.java', 'java');
    expect(codeInjSinks(ir).length).toBeGreaterThan(0);
  });
});
