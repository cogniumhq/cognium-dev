/**
 * Repro for Sprint 8 (cognium-dev v3.57.0) — Java FP/FN fixes.
 *
 *   #90 — Fastjson typed-overload heuristic + multi-position
 *   #91 — render() template-receiver substring denylist
 *   #84 — Java for-each loop element-taint
 *   #49 — Java path canonicalization + XXE setFeature sanitizers + dedupe
 *   #62 — Map.put → Map.get + StringBuilder.append → toString() propagation
 *
 * NOTE: SAST regression fixtures — every example is either deliberately
 * vulnerable (must fire) or deliberately safe (must NOT fire). Do not "fix"
 * the fixtures.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('Sprint 8 — cognium-dev v3.57.0 fixes', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ===========================================================================
  // #90 — Fastjson typed-overload heuristic
  // ===========================================================================

  it('#90: JSON.parseObject(json, User.class) is NOT a deserialization sink', async () => {
    const code = `
public class Svc {
  public Object run(String json) {
    return JSON.parseObject(json, User.class);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    const fp = (r.findings ?? []).filter(
      f => f.cwe === 'CWE-502' && f.line >= 4
    );
    expect(fp).toHaveLength(0);
  });

  it('#90: JSON.parseObject(json, charset, User.class) — 3-arg typed — is NOT a sink', async () => {
    const code = `
public class Svc {
  public Object run(String json, java.nio.charset.Charset cs) {
    return JSON.parseObject(json, cs, User.class);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    const fp = (r.findings ?? []).filter(
      f => f.cwe === 'CWE-502' && f.line >= 4
    );
    expect(fp).toHaveLength(0);
  });

  it('#90: JSON.parseObject(json, targetType) — typed-param identifier — is NOT a sink', async () => {
    const code = `
public class Svc {
  public Object run(String json, java.lang.reflect.Type targetType) {
    return JSON.parseObject(json, targetType);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    const fp = (r.findings ?? []).filter(
      f => f.cwe === 'CWE-502' && f.line >= 4
    );
    expect(fp).toHaveLength(0);
  });

  it('#90: JSON.parseObject(json, new TypeReference<List<User>>(){}.getType()) is NOT a sink', async () => {
    const code = `
public class Svc {
  public Object run(String json) {
    return JSON.parseObject(json, new TypeReference<java.util.List<User>>(){}.getType());
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    const fp = (r.findings ?? []).filter(
      f => f.cwe === 'CWE-502' && f.line >= 4
    );
    expect(fp).toHaveLength(0);
  });

  it('#90: JSON.parseObject(json) — 1-arg untyped — IS still a sink', async () => {
    const code = `
public class Svc {
  public Object run(String json) {
    return JSON.parseObject(json);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    const sinks = r.taint.sinks.filter(s => s.method === 'parseObject');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
  });

  // ===========================================================================
  // #91 — render() template-receiver substring denylist
  // ===========================================================================

  it('#91: typeTemplate.render(...) on a template-receiver does NOT fire code_injection', async () => {
    const code = `
public class Forest {
  public String run(MappingTemplate typeTemplate, String body) {
    return typeTemplate.render(body);
  }
}
`;
    const r = await analyze(code, 'Forest.java', 'java');
    const fp = (r.findings ?? []).filter(
      f => f.cwe === 'CWE-94' && f.line === 4
    );
    expect(fp).toHaveLength(0);
  });

  // ===========================================================================
  // #84 — Java for-each loop element-taint
  // ===========================================================================

  it('#84: for-each over tainted List propagates taint to loop variable (fires sql_injection)', async () => {
    const code = `
public class Svc {
  public void run(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
    String input = request.getParameter("ids");
    java.util.List<String> ids = new java.util.ArrayList<>();
    ids.add(input);
    for (String id : ids) {
      stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
    }
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  // ===========================================================================
  // #49 — Java path canonicalization + XXE setFeature
  // ===========================================================================

  it('#49: getCanonicalPath + startsWith guard suppresses path_traversal on File(base, x)', async () => {
    const code = `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
public class SafeService {
  private static final String UPLOAD_ROOT = "/var/uploads";
  public byte[] read(String filename) throws Exception {
    File base = new File(UPLOAD_ROOT);
    File target = new File(base, filename);
    String canonical = target.getCanonicalPath();
    if (!canonical.startsWith(base.getCanonicalPath() + File.separator)) {
      throw new SecurityException("path traversal blocked");
    }
    return Files.readAllBytes(Paths.get(canonical));
  }
}
`;
    const r = await analyze(code, 'SafeService.java', 'java');
    const fp = (r.findings ?? []).filter(f => f.cwe === 'CWE-22' || f.cwe === 'CWE-022');
    expect(fp).toHaveLength(0);
  });

  it('#49: setFeature(disallow-doctype-decl) suppresses xxe on builder.parse(...)', async () => {
    const code = `
import javax.xml.parsers.*;
import org.w3c.dom.Document;
public class SafeXml {
  public Document parse(byte[] body) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new java.io.ByteArrayInputStream(body));
  }
}
`;
    const r = await analyze(code, 'SafeXml.java', 'java');
    const fp = (r.findings ?? []).filter(f => f.cwe === 'CWE-611');
    expect(fp).toHaveLength(0);
  });

  it('#49: dedupe — same sink line, same type, only one finding', async () => {
    const code = `
public class Svc {
  public void run(HttpServletRequest req, java.sql.Statement stmt) throws Exception {
    String a = req.getParameter("a");
    String b = req.getParameter("b");
    stmt.executeQuery("SELECT * FROM users WHERE a='" + a + "' AND b='" + b + "'");
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    // Two sources flow to the same sink line; sink list dedupes by (line, type, method).
    const sinks = r.taint.sinks.filter(
      s => s.type === 'sql_injection' && s.method === 'executeQuery'
    );
    expect(sinks).toHaveLength(1);
  });

  // ===========================================================================
  // #62-partial — Map.put + StringBuilder propagation
  // ===========================================================================

  it('#62: Map.put(k, tainted) → query(m.get(k)) fires sql_injection', async () => {
    const code = `
public class Svc {
  public void run(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
    String input = request.getParameter("q");
    java.util.Map<String,String> m = new java.util.HashMap<>();
    m.put("key", input);
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + m.get("key") + "'");
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('#62: StringBuilder.append(tainted) → query(sb.toString()) fires sql_injection', async () => {
    const code = `
public class Svc {
  public void run(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
    String input = request.getParameter("q");
    StringBuilder sb = new StringBuilder();
    sb.append("SELECT * FROM users WHERE name = '");
    sb.append(input);
    sb.append("'");
    stmt.executeQuery(sb.toString());
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });
});
