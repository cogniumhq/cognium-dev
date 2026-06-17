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

  // ===========================================================================
  // #51 — Go filepath sanitizers
  // ===========================================================================

  it('#51: filepath.Base on tainted input suppresses path_traversal on os.ReadFile', async () => {
    const code = `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name"))
	p := filepath.Join("/var/uploads", name)
	data, _ := os.ReadFile(p)
	_ = data
}
`;
    const r = await analyze(code, 'handler.go', 'go');
    const fp = (r.findings ?? []).filter(f => f.cwe === 'CWE-22' || f.cwe === 'CWE-022');
    expect(fp).toHaveLength(0);
  });

  it('#51: filepath.Clean on tainted input suppresses path_traversal on os.ReadFile', async () => {
    const code = `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	clean := filepath.Clean(filepath.Join("/var/uploads", r.URL.Query().Get("name")))
	data, _ := os.ReadFile(clean)
	_ = data
}
`;
    const r = await analyze(code, 'handler.go', 'go');
    const fp = (r.findings ?? []).filter(f => f.cwe === 'CWE-22' || f.cwe === 'CWE-022');
    expect(fp).toHaveLength(0);
  });

  it('#51: untreated tainted input still fires path_traversal on os.ReadFile', async () => {
    const code = `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	data, _ := os.ReadFile("/var/uploads/" + name)
	_ = data
}
`;
    const r = await analyze(code, 'handler.go', 'go');
    const sinks = r.taint.sinks.filter(s => s.type === 'path_traversal');
    expect(sinks.length).toBeGreaterThanOrEqual(1);
  });

  // ===========================================================================
  // #50 — security-headers global-middleware suppression
  // ===========================================================================

  it('#50: app.use(helmet()) suppresses missing-x-frame-options on handler file', async () => {
    const code = `
const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet());
app.get('/hello', (req, res) => {
  res.send('hi');
});
`;
    const r = await analyze(code, 'safe_routes.js', 'javascript');
    const fp = (r.findings ?? []).filter(
      f => f.rule_id === 'missing-x-frame-options' || f.rule_id === 'missing-csp-frame-ancestors'
    );
    expect(fp).toHaveLength(0);
  });

  it('#50: handler without middleware still fires missing-x-frame-options', async () => {
    const code = `
const express = require('express');
const app = express();
app.get('/hello', (req, res) => {
  res.send('hi');
});
`;
    const r = await analyze(code, 'unsafe_routes.js', 'javascript');
    const findings = (r.findings ?? []).filter(
      f => f.rule_id === 'missing-x-frame-options'
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  // ===========================================================================
  // #73 — Bash function-local $1/$2 not conflated with script CLI args
  // ===========================================================================

  it('#73: $1 inside a function body is NOT a script-CLI positional source', async () => {
    const code = `#!/usr/bin/env bash
format_name() {
  local first="$1" last="$2"
  echo "\${last}, \${first}"
}
main() { format_name "Ada" "Lovelace"; }
main "$@"
`;
    const r = await analyze(code, 'benign.sh', 'bash');
    // $1/$2 inside format_name() must not be reported as positional sources.
    const fnLocalSources = (r.taint.sources ?? []).filter(
      s => (s.variable === '1' || s.variable === '2') && s.line >= 2 && s.line <= 5
    );
    expect(fnLocalSources).toHaveLength(0);
  });

  it('#73: top-level $1 IS still a script-CLI positional source', async () => {
    const code = `#!/usr/bin/env bash
target="/etc/app/\${1}.conf"
cat "$target"
`;
    const r = await analyze(code, 'unsafe.sh', 'bash');
    const topLevelSources = (r.taint.sources ?? []).filter(
      s => s.variable === '1' && s.line === 2
    );
    expect(topLevelSources.length).toBeGreaterThanOrEqual(1);
  });
});
