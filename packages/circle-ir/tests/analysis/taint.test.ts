/**
 * Tests for Taint analysis
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';

describe('Taint Analysis', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should detect HTTP parameter source', async () => {
    const code = `
public class Controller {
    public void handleRequest(HttpServletRequest request) {
        String id = request.getParameter("id");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    expect(taint.sources.length).toBeGreaterThanOrEqual(1);

    const httpSource = taint.sources.find(s => s.type === 'http_param');
    expect(httpSource).toBeDefined();
    expect(httpSource!.severity).toBe('high');
  });

  it('should detect SQL injection sink', async () => {
    const code = `
public class Repository {
    public void query(Statement stmt, String sql) {
        stmt.executeQuery(sql);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    expect(taint.sinks.length).toBeGreaterThanOrEqual(1);

    const sqlSink = taint.sinks.find(s => s.type === 'sql_injection');
    expect(sqlSink).toBeDefined();
    expect(sqlSink!.cwe).toBe('CWE-89');
  });

  it('should detect annotated parameter sources', async () => {
    const code = `
@RestController
public class UserController {
    @GetMapping("/user")
    public User getUser(@RequestParam String id, @RequestBody User user) {
        return null;
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    // Should detect @RequestParam and @RequestBody as sources
    const paramSource = taint.sources.find(
      s => s.type === 'http_param' && s.location.includes('RequestParam')
    );
    const bodySource = taint.sources.find(
      s => s.type === 'http_body' && s.location.includes('RequestBody')
    );

    expect(paramSource).toBeDefined();
    expect(bodySource).toBeDefined();
  });

  it('should detect command injection sink', async () => {
    const code = `
public class Service {
    public void execute(String cmd) {
        Runtime.getRuntime().exec(cmd);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const cmdSink = taint.sinks.find(s => s.type === 'command_injection');
    expect(cmdSink).toBeDefined();
    expect(cmdSink!.cwe).toBe('CWE-78');
  });

  it('should detect command injection sink for Runtime.exec() via local variable receiver', async () => {
    // Regression: r.exec(cmd) where r is a local Runtime variable was not detected
    // as a sink when analysed without the WASM filter pipeline.
    const code = `
public class Service {
    public void execute(String cmd) {
        Runtime r = Runtime.getRuntime();
        r.exec(cmd);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const cmdSink = taint.sinks.find(s => s.type === 'command_injection');
    expect(cmdSink).toBeDefined();
    expect(cmdSink!.cwe).toBe('CWE-78');
  });

  it('should detect command injection sink for Runtime.exec(args, env, dir) via local variable receiver', async () => {
    // Regression: the 3-arg exec overload with System.getProperty("user.dir") as an
    // inner call at the same line caused filterCleanVariableSinks to remove the sink.
    const code = `
public class Service {
    public void execute(String[] args, String[] env) {
        Runtime r = Runtime.getRuntime();
        r.exec(args, env, new java.io.File(System.getProperty("user.dir")));
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const cmdSink = taint.sinks.find(s => s.type === 'command_injection');
    expect(cmdSink).toBeDefined();
    expect(cmdSink!.cwe).toBe('CWE-78');
  });

  it('should detect path traversal sink', async () => {
    const code = `
public class FileService {
    public void readFile(String path) {
        File file = new File(path);
        FileInputStream fis = new FileInputStream(path);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const pathSinks = taint.sinks.filter(s => s.type === 'path_traversal');
    expect(pathSinks.length).toBeGreaterThanOrEqual(1);
    expect(pathSinks[0].cwe).toBe('CWE-22');
  });

  it('should detect environment variable source', async () => {
    const code = `
public class Config {
    public void loadConfig() {
        String path = System.getenv("CONFIG_PATH");
        String prop = System.getProperty("app.config");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const envSources = taint.sources.filter(s => s.type === 'env_input');
    expect(envSources.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect deserialization sink', async () => {
    const code = `
public class Deserializer {
    public Object deserialize(ObjectInputStream ois) throws Exception {
        return ois.readObject();
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const deserSink = taint.sinks.find(s => s.type === 'deserialization');
    expect(deserSink).toBeDefined();
    expect(deserSink!.cwe).toBe('CWE-502');
  });

  it('should capture source location', async () => {
    const code = `
public class Test {
    public void method(HttpServletRequest request) {
        String value = request.getParameter("key");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const source = taint.sources[0];
    expect(source.line).toBeGreaterThan(0);
    expect(source.location).toContain('getParameter');
  });

  it('should work with custom config', async () => {
    const code = `
public class Test {
    public void method() {
        customSource();
        customSink(data);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);

    const customConfig = {
      sources: [
        { method: 'customSource', type: 'http_param' as const, severity: 'high' as const, return_tainted: true }
      ],
      sinks: [
        { method: 'customSink', type: 'sql_injection' as const, cwe: 'CWE-89', severity: 'critical' as const, arg_positions: [0] }
      ],
      sanitizers: []
    };

    const taint = analyzeTaint(calls, types, customConfig);

    expect(taint.sources.length).toBeGreaterThanOrEqual(1);
    expect(taint.sinks.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect setString as SQL injection sanitizer', async () => {
    // Note: prepareStatement is a SINK (SQL string can be vulnerable)
    // setString/setInt are SANITIZERS (they safely bind parameters)
    const code = `
public class Repository {
    public void safeQuery(Connection conn, String sql) {
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, userInput);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    expect(taint.sanitizers).toBeDefined();
    expect(taint.sanitizers!.length).toBeGreaterThanOrEqual(1);

    const sqlSanitizer = taint.sanitizers!.find(
      s => s.sanitizes.includes('sql_injection')
    );
    expect(sqlSanitizer).toBeDefined();
    // setString is the sanitizer, not prepareStatement
    expect(sqlSanitizer!.method).toContain('setString');
  });

  it('should detect XSS sanitizer methods', async () => {
    const code = `
public class HtmlUtil {
    public String sanitize(String input) {
        return StringEscapeUtils.escapeHtml(input);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    expect(taint.sanitizers).toBeDefined();

    const xssSanitizer = taint.sanitizers!.find(
      s => s.sanitizes.includes('xss')
    );
    expect(xssSanitizer).toBeDefined();
    expect(xssSanitizer!.method).toContain('escapeHtml');
  });

  it('should detect annotation-based sanitizers', async () => {
    const code = `
public class Repository {
    public User findUser(@Param("id") Long id) {
        return null;
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    expect(taint.sanitizers).toBeDefined();

    const annotationSanitizer = taint.sanitizers!.find(
      s => s.type === 'annotation' && s.sanitizes.includes('sql_injection')
    );
    expect(annotationSanitizer).toBeDefined();
    expect(annotationSanitizer!.method).toContain('@Param');
  });

  it('should return sanitizers array in taint result', async () => {
    const code = `
public class Service {
    public void process() {}
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    // Sanitizers should always be defined (possibly empty array)
    expect(taint.sanitizers).toBeDefined();
    expect(Array.isArray(taint.sanitizers)).toBe(true);
  });
});
