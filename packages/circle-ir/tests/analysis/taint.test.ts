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

  it('should detect Camel mail Content-Disposition path traversal (CVE-2018-8041)', async () => {
    // Apache Camel mail consumer wrote attachments to disk using the
    // user-controlled MIME `Content-Disposition: filename=` header, reached via
    // BodyPart.getFileName(). The vulnerable pattern is `new File(parentDir,
    // fileName)` — the tainted argument is at position 1, not 0. Prior to the
    // sink-position widening this flow was missed entirely.
    const code = `
import javax.mail.BodyPart;
import java.io.File;

public class MailConsumer {
    public void saveAttachment(BodyPart part, File parentDir) throws Exception {
        String fileName = part.getFileName();
        File file = new File(parentDir, fileName);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const fileNameSource = taint.sources.find(
      s => s.location.includes('getFileName')
    );
    expect(fileNameSource).toBeDefined();

    const fileSink = taint.sinks.find(
      s => s.type === 'path_traversal' && s.method === 'File'
    );
    expect(fileSink).toBeDefined();
    expect(fileSink!.cwe).toBe('CWE-22');
    // The critical assertion: the 2-arg File(parent, child) overload must
    // mark argument index 1 as a dangerous position.
    expect(fileSink!.argPositions).toContain(1);
  });

  it('should detect Jenkins SCMFileSystem.child path traversal sink (CVE-2022-25175)', async () => {
    // Receiver name matches the class name so the static receiver-heuristic
    // matches. Real Jenkins code uses `fs` and relies on TypeHierarchyResolver
    // (project-level analysis) to resolve the type.
    const code = `
import jenkins.scm.api.SCMFileSystem;

public class ReadTrustedExecution {
    public String run(SCMFileSystem scmFileSystem, String path) throws Exception {
        return scmFileSystem.child(path).contentAsString();
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const scmChild = taint.sinks.find(
      s => s.type === 'path_traversal' && s.method === 'child'
    );
    expect(scmChild).toBeDefined();
    expect(scmChild!.cwe).toBe('CWE-22');
  });

  it('should detect Jenkins @DataBoundConstructor params as taint sources', async () => {
    // Jenkins wires every parameter of a @DataBoundConstructor from user input
    // (form/JSON binding), so ALL constructor params must be tainted.
    // Params on separate lines (real Jenkins style) so they aren't collapsed
    // by findSources' (line, type) dedup.
    const code = `
public class MyStep {
    private final String path;
    private final int timeout;

    @DataBoundConstructor
    public MyStep(
        String path,
        int timeout
    ) {
        this.path = path;
        this.timeout = timeout;
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types);

    const dataBoundSources = taint.sources.filter(
      s => s.location.includes('DataBoundConstructor')
    );
    // Both params of the constructor must be tainted.
    expect(dataBoundSources.length).toBe(2);
    expect(dataBoundSources.every(s => s.type === 'http_param')).toBe(true);
    expect(dataBoundSources.every(s => s.severity === 'high')).toBe(true);
    expect(dataBoundSources.every(s => s.confidence === 1.0)).toBe(true);
    const names = dataBoundSources.map(s => s.location).sort();
    expect(names.some(n => n.includes('path'))).toBe(true);
    expect(names.some(n => n.includes('timeout'))).toBe(true);
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

describe('Java enterprise FP suppression (issue #14)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should NOT flag j.u.c.Executor.execute(Runnable) as command_injection', async () => {
    // Reproducer for the 298/298 FP corpus from DBeaver/Dubbo/Ruoyi/JeecgBoot/XXL-JOB:
    // java.util.concurrent.Executor.execute(Runnable) collides with the
    // Apache Commons Exec `DefaultExecutor.execute(CommandLine)` sink via the
    // substring heuristic ('defaultexecutor'.includes('executor') === true).
    const code = `
import java.util.concurrent.Executor;
public class TaskRunner {
    private Executor executor;
    private Object cachedThreadPool;
    public void runTask(Runnable task) {
        executor.execute(task);
        cachedThreadPool.execute(() -> System.out.println("hi"));
    }
}`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const config = getDefaultConfig();
    const taint = analyzeTaint(calls, types, config, undefined, 'java');

    const cmdi = taint.sinks.find(s => s.type === 'command_injection');
    expect(cmdi).toBeUndefined();
    const sqli = taint.sinks.find(s => s.type === 'sql_injection');
    expect(sqli).toBeUndefined();
  });

  it('should NOT flag cachedThreadPool.execute as sql_injection (cross-language Pool leak)', async () => {
    // Rust/Node `Pool.execute` patterns must not match Java identifiers that
    // happen to end with "pool" via substring containment.
    const code = `
public class ThreadPoolWrapper {
    private Object cachedThreadPool;
    public void schedule(Runnable r) {
        cachedThreadPool.execute(r);
    }
}`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const config = getDefaultConfig();
    const taint = analyzeTaint(calls, types, config, undefined, 'java');

    expect(taint.sinks.find(s => s.type === 'sql_injection')).toBeUndefined();
    expect(taint.sinks.find(s => s.type === 'command_injection')).toBeUndefined();
  });

  it('should still detect Apache Commons DefaultExecutor.execute() command injection', async () => {
    // Negative-control: the legitimate cmdi sink must still fire when the
    // receiver is actually a DefaultExecutor instance.
    const code = `
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.CommandLine;
public class Runner {
    public void run(String userCmd) throws Exception {
        DefaultExecutor defaultExecutor = new DefaultExecutor();
        CommandLine cmd = CommandLine.parse(userCmd);
        defaultExecutor.execute(cmd);
    }
}`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const config = getDefaultConfig();
    const taint = analyzeTaint(calls, types, config, undefined, 'java');

    const cmdi = taint.sinks.find(s => s.type === 'command_injection');
    expect(cmdi).toBeDefined();
  });

  it('should still detect Runtime.exec via short identifier `r`', async () => {
    // Negative-control: classless `exec` pattern must still catch Java's
    // Runtime.exec(...) when the variable is too short to resolve via heuristic.
    const code = `
public class Service {
    public void run(String cmd) throws Exception {
        Runtime r = Runtime.getRuntime();
        r.exec(cmd);
    }
}`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const config = getDefaultConfig();
    const taint = analyzeTaint(calls, types, config, undefined, 'java');

    const cmdi = taint.sinks.find(s => s.type === 'command_injection');
    expect(cmdi).toBeDefined();
  });
});

describe('Shiro URI normalization bypass (issue #8, CVE-2023-34478/46749)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should detect WebUtils.getPathWithinApplication → new File path traversal', async () => {
    // CVE-2023-34478 / CVE-2023-46749 shape: Shiro's WebUtils internally URL-decodes
    // the request URI, so the returned string can contain ../ that bypassed any
    // upstream auth-time normalization. Feeding it into a File sink must fire.
    const code = `
import org.apache.shiro.web.util.WebUtils;
import javax.servlet.http.HttpServletRequest;
import java.io.File;

public class ShiroSink {
    public File resolve(HttpServletRequest request, String baseDir) {
        String path = WebUtils.getPathWithinApplication(request);
        return new File(baseDir, path);
    }
}`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const config = getDefaultConfig();
    const taint = analyzeTaint(calls, types, config, undefined, 'java');

    expect(taint.sources.find(s => s.location.includes('getPathWithinApplication'))).toBeDefined();
    expect(taint.sinks.find(s => s.type === 'path_traversal')).toBeDefined();
  });

  it('should re-taint a sanitized path passed through WebUtils.decodeRequestString', async () => {
    // Even if upstream code normalized the path string, Shiro's decodeRequestString
    // wraps URLDecoder.decode and re-introduces ../ from %2e%2e — sanitization is
    // invalidated, so the downstream File sink must still fire.
    const code = `
import org.apache.shiro.web.util.WebUtils;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.nio.file.Paths;

public class ShiroDecodeSink {
    public File resolve(HttpServletRequest request) {
        String raw = request.getRequestURI();
        String normalized = Paths.get(raw).normalize().toString();
        String decoded = WebUtils.decodeRequestString(request, normalized);
        return new File(decoded);
    }
}`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const config = getDefaultConfig();
    const taint = analyzeTaint(calls, types, config, undefined, 'java');

    expect(taint.sinks.find(s => s.type === 'path_traversal')).toBeDefined();
  });

  it('should recognise WebUtils.getPathWithinApplication as a Shiro http_path source', async () => {
    // Positive control: confirm the Shiro source pattern is wired through the
    // matcher with the expected severity/type. Pinning this guards against
    // accidentally narrowing or dropping the pattern in future config edits.
    const code = `
import org.apache.shiro.web.util.WebUtils;
import javax.servlet.http.HttpServletRequest;

public class ShiroSourceProbe {
    public String probe(HttpServletRequest request) {
        return WebUtils.getPathWithinApplication(request);
    }
}`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const config = getDefaultConfig();
    const taint = analyzeTaint(calls, types, config, undefined, 'java');

    const src = taint.sources.find(s => s.location.includes('getPathWithinApplication'));
    expect(src).toBeDefined();
    expect(src?.type).toBe('http_path');
    expect(src?.severity).toBe('high');
  });
});
