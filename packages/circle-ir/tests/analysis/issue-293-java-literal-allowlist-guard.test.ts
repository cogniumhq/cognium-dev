/**
 * cognium-dev#293 (Java cell): `if (!Set.of("a", "b").contains(key)) throw`
 * is an allow-list guard; past it `key` is one of the listed constants.
 *
 * Credited only for a set written out as string literals (inline, or a
 * `static final` constant of the same file built from literals), only when
 * the guard rejects, and only for the guarded variable until it is
 * reassigned or the method ends.
 *
 * SAST regression fixture — the handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const code = `import java.util.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class DisplaySettings extends HttpServlet {
    private static final Set<String> OPTIONS = Set.of("density", "palette");
    private final Set<String> learned = new HashSet<>();

    protected void inlineSet(HttpServletRequest req) {
        String opt = req.getParameter("opt");
        if (!Set.of("density", "palette").contains(opt)) {
            throw new IllegalArgumentException("unknown option");
        }
        req.getSession().setAttribute(opt, "1");
    }

    protected void constantSet(HttpServletRequest req) {
        String opt = req.getParameter("opt");
        if (!OPTIONS.contains(opt)) return;
        req.getSession().setAttribute(opt, "1");
    }

    protected void mutableSet(HttpServletRequest req) {
        String opt = req.getParameter("opt");
        if (!learned.contains(opt)) return;
        req.getSession().setAttribute(opt, "1");
    }

    protected void guardFallsThrough(HttpServletRequest req) {
        String opt = req.getParameter("opt");
        if (!OPTIONS.contains(opt)) { System.out.println("odd"); }
        req.getSession().setAttribute(opt, "1");
    }

    protected void otherValueStored(HttpServletRequest req) {
        String opt = req.getParameter("opt");
        String level = req.getParameter("level");
        if (!List.of("density", "palette").contains(opt)) throw new IllegalArgumentException();
        req.getSession().setAttribute("chosen", level);
    }

    protected void reassignedAfterGuard(HttpServletRequest req) {
        String opt = req.getParameter("opt");
        if (!OPTIONS.contains(opt)) return;
        opt = req.getParameter("fallback");
        req.getSession().setAttribute(opt, "1");
    }

    protected void rawValueOnSinkLine(HttpServletRequest req) {
        String opt = req.getParameter("opt");
        String level = req.getParameter("level");
        if (!OPTIONS.contains(opt)) return;
        req.getSession().setAttribute(opt, level);
    }

    protected void unguarded(HttpServletRequest req) {
        String opt = req.getParameter("opt");
        req.getSession().setAttribute(opt, "1");
    }
}
`;

const lines = code.split('\n');
const sinkOf = (method: string) => {
  const start = lines.findIndex(l => l.includes(`void ${method}(`));
  return lines.findIndex((l, i) => i > start && l.includes('setAttribute')) + 1;
};

describe('#293 Java literal allow-list guard', () => {
  let sinks: number[] = [];
  beforeAll(async () => {
    await initAnalyzer();
    const r = await analyze(code, 'DisplaySettings.java', 'java');
    sinks = (r.taint.flows ?? []).filter(f => f.sink_type === 'trust_boundary' && !f.sanitized).map(f => f.sink_line);
  });

  it('clears trust_boundary after an inline or constant literal set guard that rejects', () => {
    expect(sinks).not.toContain(sinkOf('inlineSet'));
    expect(sinks).not.toContain(sinkOf('constantSet'));
  });

  it('still fires for a non-literal set and for a guard that falls through', () => {
    expect(sinks).toContain(sinkOf('mutableSet'));
    expect(sinks).toContain(sinkOf('guardFallsThrough'));
  });

  it('does not credit a different value, a reassigned variable, or another method', () => {
    expect(sinks).toContain(sinkOf('otherValueStored'));
    expect(sinks).toContain(sinkOf('reassignedAfterGuard'));
    expect(sinks).toContain(sinkOf('unguarded'));
  });

  it('does not credit a raw value that shares the sink line with the guarded one', () => {
    expect(sinks).toContain(sinkOf('rawValueOnSinkLine'));
  });
});
