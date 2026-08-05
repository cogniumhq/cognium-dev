/**
 * cognium-ai#247 — two static-detector false-positive classes (Java).
 *
 * FP-1: `sql_injection` on a parameterized `PreparedStatement`. The
 *   named-param → `?` rewrite `conn.prepareStatement(q.replaceAll(PATTERN, "?"))`
 *   is the canonical parameterized-query pattern; the detector flagged it.
 * FP-2: `xss` on a JSON/GraphQL API response body. A response builder's
 *   `.body(x)` is content-negotiated (JSON by default); XSS needs an HTML
 *   context.
 *
 * (FP-3, path_traversal on a URL route resolver, no longer reproduced as of
 * 3.208.0 — `resolve` is not a filesystem sink.)
 *
 * Both fixes preserve recall: a genuine concatenated `prepareStatement` and a
 * genuine text/html response body still fire. Corpus-verified 0 OWASP
 * sqli/xss true-positive loss.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer, generateFindings } from '../../src/index.js';

describe('cognium-ai#247 — static-detector FP classes', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const findingsOf = async (code: string, file: string) => {
    const r = await analyze(code, file, 'java');
    return generateFindings(r.taint.sources, r.taint.sinks, r.dfg, file);
  };

  it('FP-1: prepareStatement(q.replaceAll(PATTERN, "?")) is NOT sql_injection', async () => {
    const code = [
      'import java.sql.*;',
      'public class NamedParamPreparedStatement {',
      '  PreparedStatement f(Connection conn, String namedParamQuery) throws Exception {',
      '    return conn.prepareStatement(namedParamQuery.replaceAll(":\\\\w+", "?"));',
      '  }',
      '}',
    ].join('\n');
    expect((await findingsOf(code, 'NPPS.java')).filter((x) => x.type === 'sql_injection')).toHaveLength(0);
  });

  it('FP-1 recall: prepareStatement with concatenated input STILL fires sql_injection', async () => {
    const code = [
      'import java.sql.*;',
      'import javax.servlet.http.HttpServletRequest;',
      'public class C {',
      '  void f(Connection conn, HttpServletRequest req) throws Exception {',
      '    String id = req.getParameter("id");',
      '    conn.prepareStatement("SELECT * FROM u WHERE id=" + id);',
      '  }',
      '}',
    ].join('\n');
    expect((await findingsOf(code, 'C.java')).some((x) => x.type === 'sql_injection')).toBe(true);
  });

  it('FP-2: ResponseEntity.body() on a JSON API response is NOT xss', async () => {
    const code = [
      'import org.springframework.http.*;',
      'public class JsonApiController {',
      '  ResponseEntity<?> f(String body) {',
      '    return ResponseEntity.status(200).contentType(MediaType.valueOf("application/vnd.api+json")).body(body);',
      '  }',
      '}',
    ].join('\n');
    expect((await findingsOf(code, 'JsonApiController.java')).filter((x) => x.type === 'xss')).toHaveLength(0);
  });

  it('FP-2 recall: body() on a text/html response STILL fires xss', async () => {
    const code = [
      'import org.springframework.http.*;',
      'public class C {',
      '  ResponseEntity<?> f(String userInput) {',
      '    return ResponseEntity.status(200).contentType(MediaType.TEXT_HTML).body("<html>" + userInput + "</html>");',
      '  }',
      '}',
    ].join('\n');
    expect((await findingsOf(code, 'H.java')).some((x) => x.type === 'xss')).toBe(true);
  });
});
