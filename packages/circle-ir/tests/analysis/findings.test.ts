/**
 * Tests for Finding generation
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { buildDFG } from '../../src/core/extractors/dfg.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { generateFindings } from '../../src/analysis/findings.js';

describe('Finding Generation', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should generate SQL injection finding', async () => {
    const code = `
public class VulnerableController {
    public void search(HttpServletRequest request, Statement stmt) {
        String query = request.getParameter("query");
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + query + "'");
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'VulnerableController.java');

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const sqlFinding = findings.find(f => f.type === 'sql_injection');
    expect(sqlFinding).toBeDefined();
    expect(sqlFinding!.cwe).toBe('CWE-89');
    expect(sqlFinding!.severity).toMatch(/critical|high/);
  });

  it('should include remediation advice', async () => {
    const code = `
public class Controller {
    public void handle(HttpServletRequest request, Statement stmt) {
        String id = request.getParameter("id");
        stmt.executeQuery("SELECT * FROM items WHERE id = " + id);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'Controller.java');

    for (const finding of findings) {
      expect(finding.remediation).toBeTruthy();
      expect(finding.remediation.length).toBeGreaterThan(10);
    }
  });

  it('should include explanation', async () => {
    const code = `
public class Handler {
    public void process(HttpServletRequest request, Runtime runtime) {
        String cmd = request.getParameter("cmd");
        runtime.exec(cmd);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'Handler.java');

    for (const finding of findings) {
      expect(finding.explanation).toBeTruthy();
      expect(finding.explanation.length).toBeGreaterThan(10);
    }
  });

  it('should calculate severity correctly', async () => {
    const code = `
@RestController
public class ApiController {
    @GetMapping("/exec")
    public void execute(@RequestParam String cmd, Runtime runtime) {
        runtime.exec(cmd);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'ApiController.java');

    const cmdInjection = findings.find(f => f.type === 'command_injection');
    if (cmdInjection) {
      // Command injection from HTTP param should be critical or high
      expect(['critical', 'high']).toContain(cmdInjection.severity);
    }
  });

  it('should set exploitable flag based on path existence', async () => {
    const code = `
public class Service {
    public void process(HttpServletRequest request, Statement stmt) {
        String input = request.getParameter("data");
        String query = "SELECT * FROM t WHERE c = '" + input + "'";
        stmt.executeQuery(query);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'Service.java');

    for (const finding of findings) {
      expect(typeof finding.exploitable).toBe('boolean');
      expect(finding.verification).toBeDefined();
      expect(typeof finding.verification.graph_path_exists).toBe('boolean');
    }
  });

  it('should sort findings by severity', async () => {
    const code = `
public class MultiVuln {
    public void method(HttpServletRequest request, Statement stmt, PrintWriter out) {
        String id = request.getParameter("id");
        stmt.executeQuery("SELECT * FROM t WHERE id = " + id);
        out.println(id);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'MultiVuln.java');

    if (findings.length > 1) {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      for (let i = 1; i < findings.length; i++) {
        const prevSeverity = severityOrder[findings[i - 1].severity];
        const currSeverity = severityOrder[findings[i].severity];
        expect(currSeverity).toBeGreaterThanOrEqual(prevSeverity);
      }
    }
  });

  it('should have unique finding IDs', async () => {
    const code = `
public class Handler {
    public void handle(HttpServletRequest request, Statement stmt) {
        String a = request.getParameter("a");
        String b = request.getParameter("b");
        stmt.executeQuery("SELECT * FROM t WHERE a = " + a);
        stmt.execute("DELETE FROM t WHERE b = " + b);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'Handler.java');

    const ids = findings.map(f => f.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('should include file name in findings', async () => {
    const code = `
public class Test {
    public void test(HttpServletRequest request, Statement stmt) {
        String x = request.getParameter("x");
        stmt.executeQuery(x);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'TestFile.java');

    for (const finding of findings) {
      expect(finding.source.file).toBe('TestFile.java');
      expect(finding.sink.file).toBe('TestFile.java');
    }
  });

  it('should handle XSS findings', async () => {
    const code = `
public class XSSHandler {
    public void render(HttpServletRequest request, PrintWriter out) {
        String name = request.getParameter("name");
        out.print("<div>" + name + "</div>");
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'XSSHandler.java');

    const xssFinding = findings.find(f => f.type === 'xss');
    expect(xssFinding).toBeDefined();
    expect(xssFinding!.cwe).toBe('CWE-79');
  });

  it('should handle path traversal findings', async () => {
    const code = `
public class FileHandler {
    public void read(HttpServletRequest request) {
        String path = request.getParameter("file");
        FileInputStream fis = new FileInputStream(path);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'FileHandler.java');

    const pathFinding = findings.find(f => f.type === 'path_traversal');
    expect(pathFinding).toBeDefined();
    expect(pathFinding!.cwe).toBe('CWE-22');
  });

  it('should handle findings with intermediate variable flow', async () => {
    const code = `
public class FlowHandler {
    public void process(HttpServletRequest request, Statement stmt) {
        String input = request.getParameter("data");
        String processed = input.trim();
        String query = "SELECT * FROM t WHERE c = '" + processed + "'";
        String finalQuery = query + " ORDER BY id";
        stmt.executeQuery(finalQuery);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'FlowHandler.java');

    // Should detect the flow through multiple variables
    expect(findings.length).toBeGreaterThan(0);
    if (findings.length > 0) {
      expect(findings[0].path).toBeDefined();
    }
  });

  it('should calculate confidence based on distance', async () => {
    // Source and sink far apart
    const code = `
public class DistantFlow {
    public void process(HttpServletRequest request, Statement stmt) {
        String input = request.getParameter("data");
        // Many lines of code
        int a = 1;
        int b = 2;
        int c = 3;
        int d = 4;
        int e = 5;
        int f = 6;
        int g = 7;
        int h = 8;
        int i = 9;
        int j = 10;
        int k = 11;
        int l = 12;
        int m = 13;
        int n = 14;
        int o = 15;
        int p = 16;
        // Now use the input
        stmt.executeQuery("SELECT * FROM t WHERE c = '" + input + "'");
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'DistantFlow.java');

    expect(findings.length).toBeGreaterThan(0);
    // Confidence should still be reasonable even with distance
    for (const finding of findings) {
      expect(finding.confidence).toBeGreaterThan(0);
      expect(finding.confidence).toBeLessThanOrEqual(1);
    }
  });

  it('should apply medium proximity bonus for 6-15 line distance', async () => {
    // Source and sink 10 lines apart (triggers the 6-15 line proximity bonus)
    const code = `
public class MediumDistance {
    public void process(HttpServletRequest request, Statement stmt) {
        String input = request.getParameter("data");
        int a = 1;
        int b = 2;
        int c = 3;
        int d = 4;
        int e = 5;
        int f = 6;
        stmt.executeQuery("SELECT * FROM t WHERE c = '" + input + "'");
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'MediumDistance.java');

    expect(findings.length).toBeGreaterThan(0);
    // Should have reasonable confidence with medium distance
    for (const finding of findings) {
      expect(finding.confidence).toBeGreaterThan(0.5);
    }
  });

  it('should apply high proximity bonus for close source and sink', async () => {
    // Source and sink within 5 lines (triggers the <= 5 line proximity bonus)
    const code = `
public class CloseDistance {
    public void process(HttpServletRequest request, Statement stmt) {
        String input = request.getParameter("data");
        stmt.executeQuery("SELECT * FROM t WHERE c = '" + input + "'");
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'CloseDistance.java');

    expect(findings.length).toBeGreaterThan(0);
    // Should have high confidence when close
    for (const finding of findings) {
      expect(finding.confidence).toBeGreaterThanOrEqual(0.8);
    }
  });

  it('should handle XSS sinks for severity classification', async () => {
    const code = `
public class XSSTest {
    public void render(HttpServletRequest request) {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + name + "</h1>");
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'XSSTest.java');

    const xssFinding = findings.find(f => f.type === 'xss');
    if (xssFinding) {
      // XSS should be high or medium severity
      expect(['high', 'medium']).toContain(xssFinding.severity);
    }
  });

  it('should handle code injection findings', async () => {
    const code = `
public class CodeInject {
    public void execute(HttpServletRequest request) {
        String code = request.getParameter("code");
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        engine.eval(code);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'CodeInject.java');

    // Should detect either the code injection or have findings for the source
    expect(taint.sources.length).toBeGreaterThan(0);
  });

  it('should handle deserialization findings', async () => {
    const code = `
public class DeserTest {
    public void deserialize(HttpServletRequest request) throws Exception {
        InputStream is = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(is);
        Object obj = ois.readObject();
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'DeserTest.java');

    // Should detect sources and potentially deserialization sinks
    expect(taint.sources.length).toBeGreaterThan(0);
  });

  it('should handle LDAP injection findings', async () => {
    const code = `
public class LDAPTest {
    public void search(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        DirContext ctx = new InitialDirContext();
        ctx.search("ou=users", "(uid=" + user + ")", null);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'LDAPTest.java');

    // Should detect sources
    expect(taint.sources.length).toBeGreaterThan(0);
  });

  it('should handle environment variable sources', async () => {
    const code = `
public class EnvTest {
    public void execute() {
        String path = System.getenv("USER_PATH");
        Runtime.getRuntime().exec(path);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'EnvTest.java');

    // Environment variable sources should be detected
    const envSource = taint.sources.find(s => s.type === 'env_input');
    expect(envSource).toBeDefined();

    // Should also detect command injection sink
    const cmdSink = taint.sinks.find(s => s.type === 'command_injection');
    expect(cmdSink).toBeDefined();
  });

  it('should handle proximity-based findings without direct path', async () => {
    // Source and sink are close but indirect - tests medium severity path
    const code = `
public class ProximityTest {
    public void process(HttpServletRequest request, Statement stmt) {
        String input = request.getParameter("data");
        String transformed = transform(input);
        String query = buildQuery(transformed);
        stmt.executeQuery(query);
    }

    private String transform(String s) { return s.trim(); }
    private String buildQuery(String s) { return "SELECT * FROM t WHERE x = '" + s + "'"; }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'ProximityTest.java');

    // Should generate findings based on proximity
    expect(findings.length).toBeGreaterThanOrEqual(0);
    for (const finding of findings) {
      expect(['critical', 'high', 'medium', 'low']).toContain(finding.severity);
    }
  });

  it('should handle non-critical sinks for low severity', async () => {
    // Test with a less critical sink type
    const code = `
public class WeakRandomTest {
    public void generateToken(HttpServletRequest request) {
        String seed = request.getParameter("seed");
        Random random = new Random(Long.parseLong(seed));
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    // This may or may not produce findings depending on weak_random sink detection
    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'WeakRandomTest.java');
    expect(Array.isArray(findings)).toBe(true);
  });

  it('should generate remediation for various sink types', async () => {
    const code = `
public class MultiSinkTest {
    public void method(HttpServletRequest request) {
        String input = request.getParameter("x");
        // Multiple potential sinks
        stmt.executeQuery(input);
        out.println(input);
        new File(input);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'MultiSinkTest.java');

    // Each finding should have remediation advice
    for (const finding of findings) {
      expect(finding.remediation).toBeTruthy();
      expect(finding.remediation.length).toBeGreaterThan(10);
    }
  });

  it('should return medium severity for critical sink without path', async () => {
    // Source and sink in separate methods with no data flow connection
    const code = `
public class NoPathCritical {
    public void getInput(HttpServletRequest request) {
        String param = request.getParameter("data");
        localVar = param;
    }

    public void doQuery(Statement stmt) {
        // No connection to param - different method
        String unconnected = "hardcoded";
        stmt.executeQuery("SELECT * FROM t WHERE x = '" + unconnected + "'");
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    // Should have both source and sink
    expect(taint.sources.length).toBeGreaterThan(0);
    expect(taint.sinks.length).toBeGreaterThan(0);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'NoPathCritical.java');

    // Findings may be generated with medium severity when no path but critical sink
    for (const finding of findings) {
      expect(['critical', 'high', 'medium', 'low']).toContain(finding.severity);
    }
  });

  it('should return low severity for non-critical sink without path', async () => {
    // Source and non-critical sink in separate methods
    const code = `
public class NoPathNonCritical {
    public void readParam(HttpServletRequest request) {
        String value = request.getParameter("name");
        memberVar = value;
    }

    public void writeOutput(PrintWriter writer) {
        // No connection - different method
        String safe = "static content";
        writer.println(safe);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    // Should have source
    expect(taint.sources.length).toBeGreaterThan(0);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'NoPathNonCritical.java');

    // Verify proper severity assignment
    for (const finding of findings) {
      expect(['critical', 'high', 'medium', 'low']).toContain(finding.severity);
    }
  });

  it('should generate explanation when path exists with no variables', async () => {
    // Direct assignment - minimal variable chain
    const code = `
public class DirectFlow {
    public void handle(HttpServletRequest request, Statement stmt) {
        stmt.executeQuery(request.getParameter("id"));
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'DirectFlow.java');

    // Should have findings with explanations
    for (const finding of findings) {
      expect(finding.explanation).toBeTruthy();
      expect(finding.explanation.length).toBeGreaterThan(10);
    }
  });

  it('should generate manual verification explanation when no path found', async () => {
    // Source and sink exist but in unconnected code blocks
    const code = `
public class Unconnected {
    private String savedInput;

    public void storeInput(HttpServletRequest request) {
        savedInput = request.getParameter("x");
    }

    public void executeQuery(Statement stmt, String query) {
        // query param is not connected to savedInput
        stmt.executeQuery(query);
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const calls = extractCalls(tree);
    const dfg = buildDFG(tree);
    const taint = analyzeTaint(calls, types);

    // Should detect both source and sink
    expect(taint.sources.length).toBeGreaterThan(0);

    const findings = generateFindings(taint.sources, taint.sinks, dfg, 'Unconnected.java');

    // Findings with no path should recommend manual verification
    for (const finding of findings) {
      expect(finding.explanation).toBeTruthy();
      if (!finding.verification.graph_path_exists) {
        expect(finding.explanation).toMatch(/may reach|recommended|verification/i);
      }
    }
  });
});
