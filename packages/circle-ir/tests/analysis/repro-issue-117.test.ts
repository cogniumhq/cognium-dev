import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * Regression lock for cognium-dev #117 — CWE-501 Trust Boundary Violation.
 *
 * OWASP Java Benchmark's trustbound category was 0% recall because the
 * inline shape `req.getSession().setAttribute("k", req.getParameter("v"))`
 * left the chained receiver `req.getSession()` with `receiver_type=null`.
 * The class-scoped `HttpSession.setAttribute` trust_boundary sink pattern
 * did not match, so only the classless `xss` setAttribute pattern fired
 * at the same line and the trust_boundary flow was silently dropped.
 *
 * Fix (Sprint 91):
 *  1. `resolveReceiverType` learns servlet chained factory return types
 *     (`req.getSession()` → HttpSession, etc.) so the class-scoped sink
 *     matcher fires on the chained receiver.
 *  2. `canSourceReachSink` gains `trust_boundary` as a valid sink for
 *     http_param/http_body/http_header/http_cookie/http_path/http_query
 *     and `interprocedural_param`, so the inline-colocation flow detector
 *     no longer drops `http_* → trust_boundary` at emit time.
 *
 * Both flow shapes (inline and intermediate) must now emit BOTH the
 * `xss` and `trust_boundary` flows.
 */
describe('#117 CWE-501 trust boundary — inline vs intermediate shape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('inline shape emits both xss and trust_boundary flows', async () => {
    const code = `
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest req, HttpServletResponse res) {
    req.getSession().setAttribute("user", req.getParameter("u"));
  }
}`;
    const ir = await analyze(code, 'inline.java', 'java');
    const flows = ir.taint?.flows ?? [];
    const sinkTypes = new Set(flows.map(f => f.sink_type));
    expect(sinkTypes.has('trust_boundary'), 'inline shape must emit trust_boundary').toBe(true);
    expect(sinkTypes.has('xss'), 'inline shape must still emit xss').toBe(true);
  });

  it('intermediate shape emits both xss and trust_boundary flows', async () => {
    const code = `
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest req, HttpServletResponse res) {
    String user = req.getParameter("u");
    HttpSession s = req.getSession();
    s.setAttribute("user", user);
  }
}`;
    const ir = await analyze(code, 'intermediate.java', 'java');
    const flows = ir.taint?.flows ?? [];
    const sinkTypes = new Set(flows.map(f => f.sink_type));
    expect(sinkTypes.has('trust_boundary'), 'intermediate shape must emit trust_boundary').toBe(true);
    expect(sinkTypes.has('xss'), 'intermediate shape must still emit xss').toBe(true);
  });

  it('servlet context inline shape emits trust_boundary', async () => {
    const code = `
import jakarta.servlet.http.*;
import jakarta.servlet.ServletContext;
public class A {
  public void doGet(HttpServletRequest req, HttpServletResponse res) {
    req.getServletContext().setAttribute("data", req.getParameter("d"));
  }
}`;
    const ir = await analyze(code, 'ctx.java', 'java');
    const flows = ir.taint?.flows ?? [];
    const trustBoundaryFlows = flows.filter(f => f.sink_type === 'trust_boundary');
    expect(trustBoundaryFlows.length).toBeGreaterThan(0);
  });

  it('does not spuriously mark unrelated chained setAttribute as trust_boundary', async () => {
    // Model.setAttribute (Spring MVC) is an xss sink, NOT trust_boundary.
    // Ensure chained factory resolution does not widen trust_boundary matching
    // to arbitrary setAttribute receivers.
    const code = `
import org.springframework.ui.Model;
public class A {
  public String doGet(Model model, String q) {
    model.addAttribute("q", q);
    return "view";
  }
}`;
    const ir = await analyze(code, 'model.java', 'java');
    const flows = ir.taint?.flows ?? [];
    const trustBoundaryFlows = flows.filter(f => f.sink_type === 'trust_boundary');
    expect(trustBoundaryFlows.length, 'Model.addAttribute must not fire trust_boundary').toBe(0);
  });
});
