/**
 * cognium-dev#589 S5 — non-helper OWASP trustbound shapes (renamed fixtures).
 *
 * Direct HTML encoder calls must not clear trust_boundary on session writes.
 * These lock the four P2 IDs that historically missed without a same-file helper.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;
const trustFlows = (r: IR) =>
  (r.taint.flows ?? []).filter((f) => f.sink_type === 'trust_boundary');

/** BenchmarkTest00668 shape: encoded value is the session *key* (putValue first arg). */
const PUT_VALUE_KEY = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.esapi.ESAPI;

public class SessionKeyPutServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("nickname");
        if (param == null) param = "";
        String bar = ESAPI.encoder().encodeForHTML(param);
        request.getSession().putValue(bar, "10340");
    }
}
`;

/** BenchmarkTest00670 shape: string tail replace before session key write. */
const TAIL_REPLACE_KEY = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TailReplaceKeyServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("nickname");
        if (param == null) param = "";
        String bar = param;
        if (param != null && param.length() > 1) {
            StringBuilder sb = new StringBuilder(param);
            bar = sb.replace(param.length() - 1, param.length(), "Z").toString();
        }
        request.getSession().putValue(bar, "10340");
    }
}
`;

/** BenchmarkTest00671 shape: constant-folded if assigns request param to session key. */
const CONST_IF_KEY = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ConstIfKeyServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("nickname");
        if (param == null) param = "";
        String bar;
        int num = 196;
        if ((500 / 42) + num > 200) bar = param;
        else bar = "unused";
        request.getSession().putValue(bar, "10340");
    }
}
`;

/** BenchmarkTest00756 shape: braceless parameterValues arm + direct encodeHtml + putValue value arg. */
const PARAM_VALUES_VALUE = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringEscapeUtils;

public class ParamValuesValueServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] values = request.getParameterValues("nickname");
        String param;
        if (values != null && values.length > 0) param = values[0];
        else param = "";
        String bar = StringEscapeUtils.escapeHtml(param);
        request.getSession().putValue("userid", bar);
    }
}
`;

describe('cognium-dev#589 S5 non-helper OWASP trustbound', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('putValue(encodedKey, literal): trust_boundary on session key', async () => {
    const r = await analyze(PUT_VALUE_KEY, 'SessionKeyPutServlet.java', 'java');
    expect(trustFlows(r).length).toBeGreaterThanOrEqual(1);
  });

  it('putValue(tail-replaced key, literal): trust_boundary', async () => {
    const r = await analyze(TAIL_REPLACE_KEY, 'TailReplaceKeyServlet.java', 'java');
    expect(trustFlows(r).length).toBeGreaterThanOrEqual(1);
  });

  it('putValue(const-if param key, literal): trust_boundary', async () => {
    const r = await analyze(CONST_IF_KEY, 'ConstIfKeyServlet.java', 'java');
    expect(trustFlows(r).length).toBeGreaterThanOrEqual(1);
  });

  it('putValue(fixed key, escapeHtml(values[0])): trust_boundary', async () => {
    const r = await analyze(PARAM_VALUES_VALUE, 'ParamValuesValueServlet.java', 'java');
    expect(trustFlows(r).length).toBeGreaterThanOrEqual(1);
  });
});
