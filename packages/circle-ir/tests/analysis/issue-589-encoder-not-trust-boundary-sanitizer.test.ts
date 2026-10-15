/**
 * #589 (slice) — an HTML/markup encoder neutralises the XSS context only.
 *
 * A local assigned from any registered sanitizer call entered
 * `constProp.sanitizedVars`, which carries no sink-type information, so
 * `filterCleanVariableSinks` treated the argument as clean for EVERY sink type:
 * `session.setAttribute("n", escapeHtml(x))` lost its `trust_boundary` sink.
 * Variables produced by a context-specific encoder now remember that scope and
 * only drop sinks of the types the encoder covers (xss, and the bare-helper
 * `external_taint_escape` credit that its config row also carries). Other
 * sanitizer families keep their existing behaviour.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { DEFAULT_SANITIZERS } from '../../src/analysis/config-loader.js';
import { HTML_CONTEXT_ENCODER_METHODS, SANITIZER_METHODS } from '../../src/analysis/constant-propagation/patterns.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const sinksAt = (r: IR, line: number) => (r.taint.sinks ?? []).filter(s => s.line === line).map(s => s.type);
const flowTypesFrom = (r: IR, srcLine: number, sinkLine: number) =>
  (r.taint.flows ?? []).filter(f => f.source_line === srcLine && f.sink_line === sinkLine).map(f => f.sink_type);

const save = (encoderImport: string, encode: string) => `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
${encoderImport}

public class ProfileSaveServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String nick = request.getParameter("nickname");
        String shown = ${encode};
        request.getSession().setAttribute("displayName", shown);
        String raw = request.getParameter("theme");
        request.getSession().setAttribute("theme", raw);
    }
}
`;

describe('#589 an HTML encoder does not clear trust_boundary', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const variants: Array<[string, string, string]> = [
    ['Commons escapeHtml', 'import org.apache.commons.lang.StringEscapeUtils;', 'StringEscapeUtils.escapeHtml(nick)'],
    ['ESAPI encodeForHTML', 'import org.owasp.esapi.ESAPI;', 'ESAPI.encoder().encodeForHTML(nick)'],
    ['Spring htmlEscape', 'import org.springframework.web.util.HtmlUtils;', 'HtmlUtils.htmlEscape(nick)'],
  ];

  for (const [name, imp, enc] of variants) {
    it(`${name}: line 12 keeps trust_boundary with a flow from line 10, and no xss`, async () => {
      const r = await analyze(save(imp, enc), 'ProfileSaveServlet.java', 'java');
      expect(sinksAt(r, 12)).toContain('trust_boundary');
      expect(sinksAt(r, 12)).not.toContain('xss');
      expect(flowTypesFrom(r, 10, 12)).toContain('trust_boundary');
      expect(flowTypesFrom(r, 10, 12)).not.toContain('xss');
    });
    it(`${name}: the unencoded control on line 14 still reports trust_boundary`, async () => {
      const r = await analyze(save(imp, enc), 'ProfileSaveServlet.java', 'java');
      expect(sinksAt(r, 14)).toContain('trust_boundary');
    });
  }

  it('ProfileShowServlet: the same encoder written to HTML stays clean of xss', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class ProfileShowServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String shown = StringEscapeUtils.escapeHtml(request.getParameter("nickname"));
        response.getWriter().print("<p>" + shown + "</p>");
    }
}
`, 'ProfileShowServlet.java', 'java');
    expect((r.taint.flows ?? []).filter(f => f.sink_type === 'xss')).toHaveLength(0);
  });

  it('other sanitizer families keep their scope: parseInt still clears an sql sink', async () => {
    const r = await analyze(`import java.io.IOException;
import java.sql.Connection;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IdServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Connection conn = null;
        int id = Integer.parseInt(request.getParameter("id"));
        conn.createStatement().executeQuery("SELECT * FROM t WHERE id=" + id);
    }
}
`, 'IdServlet.java', 'java');
    expect((r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection')).toHaveLength(0);
  });
});

describe('#589 the HTML-encoder list stays in step with the sanitizer config', () => {
  it('every listed method is a registered const-prop sanitizer', () => {
    for (const m of HTML_CONTEXT_ENCODER_METHODS) expect(SANITIZER_METHODS.has(m), m).toBe(true);
  });

  it('no listed method clears a sink type other than xss / external_taint_escape in the config', () => {
    for (const row of DEFAULT_SANITIZERS as Array<{ method?: string; removes?: string[] }>) {
      if (!row.method || !HTML_CONTEXT_ENCODER_METHODS.has(row.method)) continue;
      for (const t of row.removes ?? []) {
        expect(['xss', 'external_taint_escape'], `${row.method} removes ${t}`).toContain(t);
      }
    }
  });
});

describe('#589 sibling / overwrite: encoder must not bleed onto another method or a later constant', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('same-method constant overwrite after escapeHtml stays quiet at setAttribute', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class ProfileSaveServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String nick = request.getParameter("nickname");
        String data = StringEscapeUtils.escapeHtml(nick);
        data = "safe";
        request.getSession().setAttribute("displayName", data);
    }
}
`, 'ProfileSaveServlet.java', 'java');
    expect(sinksAt(r, 13)).not.toContain('trust_boundary');
    expect(flowTypesFrom(r, 10, 13)).not.toContain('trust_boundary');
  });

  it('sibling good() with literal "safe" on the same local stays quiet', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class ProfileSaveServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String nick = request.getParameter("nickname");
        String data = StringEscapeUtils.escapeHtml(nick);
        request.getSession().setAttribute("displayName", data);
    }

    protected void good(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String data = "safe";
        request.getSession().setAttribute("displayName", data);
    }
}
`, 'ProfileSaveServlet.java', 'java');
    // doPost encoder → trust_boundary still fires
    expect(sinksAt(r, 12)).toContain('trust_boundary');
    expect(flowTypesFrom(r, 10, 12)).toContain('trust_boundary');
    // good() literal must stay quiet
    expect(sinksAt(r, 17)).not.toContain('trust_boundary');
    expect((r.taint.flows ?? []).filter(f => f.sink_line === 17 && f.sink_type === 'trust_boundary')).toHaveLength(0);
  });

  it('sibling good() with parseInt on the same local stays quiet', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class ProfileSaveServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String nick = request.getParameter("nickname");
        String data = StringEscapeUtils.escapeHtml(nick);
        request.getSession().setAttribute("displayName", data);
    }

    protected void good(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // parseInt of a literal — clean; must not inherit doPost's encoder uncovered set
        // via the bare name data.
        int id = Integer.parseInt("42");
        String data = Integer.toString(id);
        request.getSession().setAttribute("displayName", data);
    }
}
`, 'ProfileSaveServlet.java', 'java');
    expect(sinksAt(r, 12)).toContain('trust_boundary');
    expect(sinksAt(r, 18)).not.toContain('trust_boundary');
  });

  it('single escapeHtml in doPost must not drop xss in sibling other()', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class SiblingEncoderServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String data = StringEscapeUtils.escapeHtml(request.getParameter("a"));
        response.getWriter().print(data);
    }

    protected void other(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String data = request.getParameter("b");
        response.getWriter().print(data);
    }
}
`, 'SiblingEncoderServlet.java', 'java');
    // doPost: escapeHtml → print stays clean of xss
    expect((r.taint.flows ?? []).filter(f => f.sink_line === 11 && f.sink_type === 'xss')).toHaveLength(0);
    // other(): raw getParameter → print must still report xss
    expect(sinksAt(r, 16)).toContain('xss');
    expect(flowTypesFrom(r, 15, 16)).toContain('xss');
  });

  it('encoder method still fires trust_boundary (positive control)', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class ProfileSaveServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String nick = request.getParameter("nickname");
        String data = StringEscapeUtils.escapeHtml(nick);
        request.getSession().setAttribute("displayName", data);
    }
}
`, 'ProfileSaveServlet.java', 'java');
    expect(sinksAt(r, 12)).toContain('trust_boundary');
    expect(flowTypesFrom(r, 10, 12)).toContain('trust_boundary');
  });
});

describe('#589 encoder-only predecessor must not drop a later unrestricted one', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('mixed = shown + b: xss still fires on print(mixed); setAttribute(shown) keeps trust_boundary', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class MixedEncoderServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String a = request.getParameter("a");
        String shown = StringEscapeUtils.escapeHtml(a);
        String b = a.toUpperCase();
        String mixed = shown + b;
        response.getWriter().print(mixed);
        request.getSession().setAttribute("displayName", shown);
    }
}
`, 'MixedEncoderServlet.java', 'java');
    // Line numbers (1-based, import lines included):
    // 10: a = getParameter, 11: shown = escapeHtml, 12: b = toUpperCase,
    // 13: mixed = shown + b, 14: print(mixed), 15: setAttribute(shown)
    expect(sinksAt(r, 14)).toContain('xss');
    expect(flowTypesFrom(r, 10, 14)).toContain('xss');
    expect(sinksAt(r, 15)).toContain('trust_boundary');
    expect(flowTypesFrom(r, 10, 15)).toContain('trust_boundary');
  });

  it('same-line escapeHtml(a) + b: raw operand keeps xss on print(mixed)', async () => {
    const r = await analyze(`import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class MixedInlineServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String a = request.getParameter("a");
        String b = a.toUpperCase();
        String mixed = StringEscapeUtils.escapeHtml(a) + b;
        response.getWriter().print(mixed);
    }
}
`, 'MixedInlineServlet.java', 'java');
    // 10: a, 11: b, 12: mixed, 13: print
    expect(sinksAt(r, 13)).toContain('xss');
    expect(flowTypesFrom(r, 10, 13)).toContain('xss');
  });
});
