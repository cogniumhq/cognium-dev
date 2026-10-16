/**
 * #589 (slice) — braceless top-level `if` / `else` arms must merge defs like braced twins.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const trustFlows = (r: IR) =>
  (r.taint.flows ?? []).filter((f) => f.sink_type === 'trust_boundary');

const saveServlet = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class NicknameSaveServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] vals = request.getParameterValues("nick");
        String nick;
        if (vals != null && vals.length > 0) nick = vals[0];
        else nick = "";
        String shown = StringEscapeUtils.escapeHtml(nick);
        request.getSession().putValue("userid", shown);
    }
}
`;

const showServlet = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class NicknameShowServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] vals = request.getParameterValues("nick");
        String nick;
        if (vals != null && vals.length > 0) nick = vals[0];
        else nick = "";
        String shown = StringEscapeUtils.escapeHtml(nick);
        response.getWriter().print("<p>" + shown + "</p>");
    }
}
`;

const fixedServlet = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class NicknameFixedServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String nick;
        if (response.isCommitted()) nick = "a";
        else nick = "b";
        String shown = StringEscapeUtils.escapeHtml(nick);
        request.getSession().putValue("userid", shown);
    }
}
`;

const bracedServlet = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class NicknameBracedServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] vals = request.getParameterValues("nick");
        String nick;
        if (vals != null && vals.length > 0) {
            nick = vals[0];
        } else {
            nick = "";
        }
        String shown = StringEscapeUtils.escapeHtml(nick);
        request.getSession().putValue("userid", shown);
    }
}
`;

const allowlistServlet = `import java.io.IOException;
import java.util.Set;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class ChoiceAllowlistServlet extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("a", "b");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String choice = request.getParameter("choice");
        if (!ALLOWED.contains(choice)) choice = "a";
        String shown = StringEscapeUtils.escapeHtml(choice);
        request.getSession().putValue("userid", shown);
    }
}
`;

describe('#589 braceless if/else DFG merge', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('NicknameSaveServlet: trust_boundary flow from parameter read to session write', async () => {
    const r = await analyze(saveServlet, 'NicknameSaveServlet.java', 'java');
    const flows = trustFlows(r).filter((f) => f.sink_line === 15);
    expect(flows).toHaveLength(1);
    expect(flows[0].source_line).toBe(10);
  });

  it('NicknameShowServlet: no trust_boundary flow (HTML encoder clears xss only)', async () => {
    const r = await analyze(showServlet, 'NicknameShowServlet.java', 'java');
    expect(trustFlows(r)).toHaveLength(0);
  });

  it('NicknameFixedServlet: literals only — no trust_boundary flow', async () => {
    const r = await analyze(fixedServlet, 'NicknameFixedServlet.java', 'java');
    expect(trustFlows(r)).toHaveLength(0);
  });

  it('NicknameBracedServlet: regression — flow still present', async () => {
    const r = await analyze(bracedServlet, 'NicknameBracedServlet.java', 'java');
    const flows = trustFlows(r).filter((f) => f.sink_line === 18);
    expect(flows).toHaveLength(1);
    expect(flows[0].source_line).toBe(10);
  });

  it('ChoiceAllowlistServlet: allowlist guard — no trust_boundary flow', async () => {
    const r = await analyze(allowlistServlet, 'ChoiceAllowlistServlet.java', 'java');
    expect(trustFlows(r)).toHaveLength(0);
  });
});
