/**
 * cognium-dev#562 / #605 / #517 (minimal slices): Java `String.replace`
 * sanitizer credit is argument-aware. `log_injection` is credited only when
 * the chain strips both CR and LF; `xss` only when it entity-escapes `<` and `>`.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function lines(code: string, file: string, type: string) {
  const r = await analyze(code, file, 'java');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort((a, b) => a - b);
}

const audit = `import java.io.IOException;
import java.util.logging.Logger;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuditTrailServlet extends HttpServlet {
    private static final Logger AUDIT = Logger.getLogger("audit");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String actor = request.getParameter("actor");
        String lfOnly = actor.replace("\\n", "");
        AUDIT.info("login by " + lfOnly);
        String both = actor.replace("\\n", "").replace("\\r", "");
        AUDIT.info("login by " + both);
        String rx = actor.replaceAll("[\\r\\n]", "");
        AUDIT.info("login by " + rx);
        AUDIT.info("login by " + actor);
        String angle = actor.replace("<", "");
        AUDIT.info("login by " + angle);
    }
}
`;

const signup = `import java.io.IOException;
import java.util.logging.Logger;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SignupAuditServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger("signup");

    private String scrub(String value) {
        return value.replace("\\n", "");
    }

    private String scrubBoth(String value) {
        return value.replace("\\n", "").replace("\\r", "");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String email = request.getParameter("email");
        LOG.info("signup " + scrub(email));
        LOG.info("signup " + scrubBoth(email));
    }
}
`;

const echo = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EchoPageServlet extends HttpServlet {
    private String tidy(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private String decorate(String value) {
        return "[" + value.trim() + "]";
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        response.getWriter().write("<p>" + tidy(q) + "</p>");
        response.getWriter().write("<p>" + decorate(q) + "</p>");
        String inline = q.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        response.getWriter().write("<p>" + inline + "</p>");
    }
}
`;

const partial = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EchoPartialServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        String amp = q.replace("&", "&amp;");
        response.getWriter().write(amp);
        String nl = q.replace("\\n", "").replace("\\r", "");
        response.getWriter().write(nl);
        String esc = q.replace("<", "&lt;").replace(">", "&gt;");
        Runtime.getRuntime().exec(esc);
    }
}
`;

describe('Java argument-aware replace sanitizer credit', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('#562: log_injection only at the LF-only (14), control (19) and angle-only (21) lines', async () => {
    expect(await lines(audit, 'AuditTrailServlet.java', 'log_injection')).toEqual([14, 19, 21]);
  });

  it('#605: LF-only helper fires, CR+LF helper stays clean', async () => {
    expect(await lines(signup, 'SignupAuditServlet.java', 'log_injection')).toEqual([21]);
  });

  it('#517: inline < > entity escape clears xss at 21; the unescaped helper (19) still fires', async () => {
    const l = await lines(echo, 'EchoPageServlet.java', 'xss');
    expect(l).toContain(19);
    expect(l).not.toContain(21);
  });

  it('#517: partial escapes keep xss, and the xss credit does not clear command_injection', async () => {
    const l = await lines(partial, 'EchoPartialServlet.java', 'xss');
    expect(l).toContain(11);
    expect(l).toContain(13);
    expect(await lines(partial, 'EchoPartialServlet.java', 'command_injection')).toContain(15);
  });
});
