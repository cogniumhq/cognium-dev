/**
 * Tests for ProjectGraph, CrossFilePass, and analyzeProject().
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { ProjectGraph } from '../../src/graph/index.js';
import { CrossFilePass } from '../../src/analysis/passes/cross-file-pass.js';
import { CodeGraph } from '../../src/graph/index.js';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';
import type { CircleIR } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await initAnalyzer();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Test.java', language: 'java', loc: 10, hash: 'abc' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// ProjectGraph — unit tests
// ---------------------------------------------------------------------------

describe('ProjectGraph', () => {
  it('starts empty', () => {
    const pg = new ProjectGraph();
    expect(pg.filePaths).toEqual([]);
    expect(pg.fileCount).toBe(0);
  });

  it('registers files and reports filePaths in insertion order', () => {
    const pg = new ProjectGraph();
    const graphA = new CodeGraph(makeIR({ meta: { circle_ir: '3.0', file: 'A.java', language: 'java', loc: 5, hash: 'a' } }));
    const graphB = new CodeGraph(makeIR({ meta: { circle_ir: '3.0', file: 'B.java', language: 'java', loc: 5, hash: 'b' } }));

    pg.addFile('/src/A.java', graphA);
    pg.addFile('/src/B.java', graphB);

    expect(pg.filePaths).toEqual(['/src/A.java', '/src/B.java']);
    expect(pg.fileCount).toBe(2);
  });

  it('getGraph returns registered graph', () => {
    const pg = new ProjectGraph();
    const graph = new CodeGraph(makeIR());
    pg.addFile('/src/A.java', graph);

    expect(pg.getGraph('/src/A.java')).toBe(graph);
    expect(pg.getGraph('/src/Unknown.java')).toBeUndefined();
  });

  it('getIR returns the underlying CircleIR', () => {
    const pg = new ProjectGraph();
    const ir = makeIR();
    pg.addFile('/src/A.java', new CodeGraph(ir));

    expect(pg.getIR('/src/A.java')).toBe(ir);
    expect(pg.getIR('/nope.java')).toBeUndefined();
  });

  it('resolver is built lazily on first access', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));
    // Access resolver — should not throw
    const r = pg.resolver;
    expect(r).toBeDefined();
    // Second access returns same instance (cached)
    expect(pg.resolver).toBe(r);
  });

  it('addFile invalidates the lazy resolver cache', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));
    const r1 = pg.resolver;

    // Adding another file invalidates the cache
    pg.addFile('/src/B.java', new CodeGraph(makeIR()));
    const r2 = pg.resolver;

    // A new resolver instance must have been created
    expect(r2).not.toBe(r1);
  });

  it('symbolTable is built lazily', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));
    const st = pg.symbolTable;
    expect(st).toBeDefined();
    expect(pg.symbolTable).toBe(st); // same instance on second access
  });

  it('typeHierarchy is built lazily', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));
    const th = pg.typeHierarchy;
    expect(th).toBeDefined();
    expect(pg.typeHierarchy).toBe(th); // same instance on second access
  });
});

// ---------------------------------------------------------------------------
// CrossFilePass — unit tests with minimal fixtures
// ---------------------------------------------------------------------------

describe('CrossFilePass', () => {
  it('returns empty results for a single file with no sources', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));

    const result = new CrossFilePass().run(pg, new Map([['/src/A.java', ['line1']]]));

    expect(result.crossFileCalls).toEqual([]);
    expect(result.taintPaths).toEqual([]);
    expect(result.typeHierarchy).toBeDefined();
    expect(result.typeHierarchy.classes).toBeDefined();
    expect(result.typeHierarchy.interfaces).toBeDefined();
  });

  it('returns well-formed TypeHierarchy even with no types', () => {
    const pg = new ProjectGraph();
    pg.addFile('/src/A.java', new CodeGraph(makeIR()));

    const { typeHierarchy } = new CrossFilePass().run(pg, new Map());
    expect(typeof typeHierarchy.classes).toBe('object');
    expect(typeof typeHierarchy.interfaces).toBe('object');
  });
});

// ---------------------------------------------------------------------------
// analyzeProject() — structural tests
// ---------------------------------------------------------------------------

const JAVA_FILE_A = `
package com.example.controller;

import javax.servlet.http.HttpServletRequest;

public class UserController {
    public void handleRequest(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + userId;
        java.sql.Connection conn = null;
        try {
            java.sql.Statement stmt = conn.createStatement();
            stmt.executeQuery(query);
        } catch (Exception e) {}
    }
}
`.trim();

const JAVA_FILE_B = `
package com.example.service;

import javax.servlet.http.HttpServletRequest;

public class UserService {
    public String getInput(HttpServletRequest request) {
        return request.getParameter("name");
    }
}
`.trim();

describe('analyzeProject()', () => {
  it('returns correct meta for empty file list', async () => {
    const result = await analyzeProject([]);
    expect(result.meta.total_files).toBe(0);
    expect(result.meta.total_loc).toBe(0);
    expect(result.files).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  it('returns correct meta for single file', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/UserController.java', language: 'java' },
    ]);

    expect(result.meta.total_files).toBe(1);
    expect(result.meta.language).toBe('java');
    expect(result.files).toHaveLength(1);
    expect(result.files[0].file).toBe('/src/UserController.java');
    expect(result.cross_file_calls).toHaveLength(0); // no cross-file calls with one file
    expect(result.findings).toEqual([]);
    expect(new Date(result.meta.analyzed_at).toISOString()).toBe(result.meta.analyzed_at);
  });

  it('returns a CircleIR for each file', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);

    expect(result.files).toHaveLength(2);
    expect(result.files[0].file).toBe('/src/A.java');
    expect(result.files[1].file).toBe('/src/B.java');

    for (const fa of result.files) {
      const ir = fa.analysis;
      expect(ir.meta.circle_ir).toBe('3.0');
      expect(ir.types).toBeDefined();
      expect(ir.calls).toBeDefined();
      expect(ir.taint).toBeDefined();
    }
  });

  it('total_files and total_loc are correct', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);

    expect(result.meta.total_files).toBe(2);
    const expectedLoc = result.files.reduce((sum, f) => sum + (f.analysis.meta.loc ?? 0), 0);
    expect(result.meta.total_loc).toBe(expectedLoc);
  });

  it('analyzed_at is a valid ISO timestamp', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
    ]);
    const d = new Date(result.meta.analyzed_at);
    expect(isNaN(d.getTime())).toBe(false);
  });

  it('type_hierarchy has classes and interfaces objects', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);
    expect(typeof result.type_hierarchy.classes).toBe('object');
    expect(typeof result.type_hierarchy.interfaces).toBe('object');
  });

  it('findings is always empty (LLM enrichment out of scope)', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
    ]);
    expect(result.findings).toEqual([]);
  });

  it('taint_paths entries have required fields when present', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);

    for (const path of result.taint_paths) {
      expect(typeof path.id).toBe('string');
      expect(typeof path.source.file).toBe('string');
      expect(typeof path.source.line).toBe('number');
      expect(typeof path.sink.file).toBe('string');
      expect(typeof path.sink.line).toBe('number');
      expect(typeof path.confidence).toBe('number');
      expect(typeof path.path_exists).toBe('boolean');
      expect(Array.isArray(path.hops)).toBe(true);
    }
  });

  it('cross_file_calls entries have required fields when present', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/src/B.java', language: 'java' },
    ]);

    for (const call of result.cross_file_calls) {
      expect(typeof call.id).toBe('string');
      expect(typeof call.from.file).toBe('string');
      expect(typeof call.from.line).toBe('number');
      expect(typeof call.to.file).toBe('string');
      expect(typeof call.resolved).toBe('boolean');
      expect(Array.isArray(call.args_mapping)).toBe(true);
      // Cross-file calls must reference different files
      expect(call.from.file).not.toBe(call.to.file);
    }
  });

  it('deriveProjectRoot produces a common prefix', async () => {
    const result = await analyzeProject([
      { code: JAVA_FILE_A, filePath: '/project/src/A.java', language: 'java' },
      { code: JAVA_FILE_B, filePath: '/project/src/B.java', language: 'java' },
    ]);
    expect(result.meta.root).toBe('/project/src');
    expect(result.meta.name).toBe('src');
  });
});

// ---------------------------------------------------------------------------
// Inter-procedural multi-hop chains — issue #19 regression
// ---------------------------------------------------------------------------

describe('Cross-file multi-hop taint chains (issue #19)', () => {
  it('CVE-2011-2732 shape: open redirect via wrapper + sink strategy', async () => {
    // LoginController.handle calls UrlHandler.determineTargetUrl(request) which
    // returns request.getParameter(...) — a real http_param source.  The returned
    // URL is then passed to RedirectStrategy.sendRedirect which calls
    // res.sendRedirect(url) — the CWE-601 sink.  Neither caller alone has a
    // co-located source-and-sink; the chain only resolves cross-file.
    const controller = `
package app;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class LoginController {
    private final UrlHandler handler = new UrlHandler();
    private final RedirectStrategy strategy = new RedirectStrategy();
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String url = handler.determineTargetUrl(request);
        strategy.sendRedirect(request, response, url);
    }
}
`;
    const handler = `
package app;
import javax.servlet.http.HttpServletRequest;
public class UrlHandler {
    public String determineTargetUrl(HttpServletRequest request) {
        return request.getParameter("spring-security-redirect");
    }
}
`;
    const strategy = `
package app;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class RedirectStrategy {
    public void sendRedirect(HttpServletRequest req, HttpServletResponse res, String url) throws Exception {
        res.sendRedirect(url);
    }
}
`;
    const result = await analyzeProject([
      { code: controller, filePath: 'LoginController.java',  language: 'java' },
      { code: handler,    filePath: 'UrlHandler.java',       language: 'java' },
      { code: strategy,   filePath: 'RedirectStrategy.java', language: 'java' },
    ]);

    expect(result.taint_paths.length).toBeGreaterThanOrEqual(1);
    const ssrf = result.taint_paths.find(p => p.sink.type === 'ssrf');
    expect(ssrf).toBeDefined();
    expect(ssrf!.source.file).toBe('UrlHandler.java');
    expect(ssrf!.source.type).toBe('http_param');
    expect(ssrf!.sink.file).toBe('RedirectStrategy.java');
    expect(ssrf!.sink.cwe).toBe('CWE-601');
    // Multi-hop chain: source -> wrapper return -> sink call -> sink.
    expect(ssrf!.hops.length).toBeGreaterThanOrEqual(3);

    // The cross-file call carrying `url` to sendRedirect should mark
    // taint_propagates=true on param 2.
    const sendRedirectCall = result.cross_file_calls.find(c =>
      c.to.method.endsWith('.sendRedirect'),
    );
    expect(sendRedirectCall).toBeDefined();
    const urlArg = sendRedirectCall!.args_mapping.find(a => a.callee_param === 2);
    expect(urlArg?.taint_propagates).toBe(true);
  });

  it('Sanitized wrapper negative control: no flow when wrapper sanitizes', async () => {
    // Same shape as CVE-2011-2732, but the wrapper class name + method name
    // suggest a sanitizer (UrlSanitizer.sanitizeUrl).  The cross-file resolver
    // must treat the wrapper as sanitizing and skip the multi-hop chain.
    const controller = `
package app;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class LoginController {
    private final UrlSanitizer sanitizer = new UrlSanitizer();
    private final RedirectStrategy strategy = new RedirectStrategy();
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String raw = request.getParameter("redirect");
        String safe = sanitizer.sanitizeUrl(raw);
        strategy.sendRedirect(request, response, safe);
    }
}
`;
    const sanitizer = `
package app;
public class UrlSanitizer {
    public String sanitizeUrl(String input) {
        if (input == null) return "/";
        if (!input.startsWith("/")) return "/";
        return input;
    }
}
`;
    const strategy = `
package app;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class RedirectStrategy {
    public void sendRedirect(HttpServletRequest req, HttpServletResponse res, String url) throws Exception {
        res.sendRedirect(url);
    }
}
`;
    const result = await analyzeProject([
      { code: controller, filePath: 'LoginController.java',  language: 'java' },
      { code: sanitizer,  filePath: 'UrlSanitizer.java',     language: 'java' },
      { code: strategy,   filePath: 'RedirectStrategy.java', language: 'java' },
    ]);

    // No cross-file taint path should be emitted from the sanitized variable
    // (`safe`) to sendRedirect.  Any path emitted from `raw` -> sendRedirect
    // must not exist either because `safe` is what gets passed, not `raw`.
    const passes = result.taint_paths.filter(p =>
      p.source.type === 'http_param' &&
      p.sink.file === 'RedirectStrategy.java',
    );
    expect(passes).toHaveLength(0);
  });

  it('CVE-2018-1260 shape: SpEL injection via parser + getValue', async () => {
    // Spring SpEL injection.  Real-world flow:
    //   1. Controller reads request.getParameter("expr") — http_param.
    //   2. Calls helper.parseAndEval(req) which wraps both the parser and
    //      the evaluation.  The helper internally calls
    //      SpelExpressionParser.parseExpression(expr).getValue().
    //   3. SpelExpressionParser.parseExpression + Expression.getValue are
    //      sinks for CWE-94 (code injection).
    const controller = `
package app;
import javax.servlet.http.HttpServletRequest;
public class SpelController {
    private final SpelHelper helper = new SpelHelper();
    public Object handle(HttpServletRequest request) {
        return helper.evaluate(request);
    }
}
`;
    const helper = `
package app;
import javax.servlet.http.HttpServletRequest;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
public class SpelHelper {
    public Object evaluate(HttpServletRequest req) {
        String expr = req.getParameter("expr");
        Expression e = new SpelExpressionParser().parseExpression(expr);
        return e.getValue();
    }
}
`;
    const result = await analyzeProject([
      { code: controller, filePath: 'SpelController.java', language: 'java' },
      { code: helper,     filePath: 'SpelHelper.java',     language: 'java' },
    ]);

    // The sink must exist in SpelHelper.java (intra-file flow that the
    // single-file InterproceduralPass already handles) — even if the
    // cross-file resolver doesn't add a path, the engine must still surface
    // SpEL parseExpression as a known sink so the helper's intra-file
    // analysis flags it.
    const spelHelperIR = result.files.find(f => f.file === 'SpelHelper.java')?.analysis;
    expect(spelHelperIR).toBeDefined();
    const hasSpelSink = (spelHelperIR!.taint.sinks ?? []).some(s =>
      s.cwe?.startsWith('CWE-9') || s.type === 'spel_injection' || s.type === 'code_injection',
    );
    // We accept *either* a recognized SpEL sink OR a recognized intra-file
    // flow from http_param to a known sink.  This is the minimum signal needed.
    const hasIntraFlow = (spelHelperIR!.taint.flows ?? []).some(f =>
      f.source_type === 'http_param',
    );
    expect(hasSpelSink || hasIntraFlow).toBe(true);
  });

  it('Jenkins #1 shape: @DataBoundConstructor field bound to user input', async () => {
    // Jenkins DataBoundConstructor pattern: the constructor argument is a
    // user-controlled web binding.  A getter exposes it as a field, and a
    // subsequent call from another class uses the field at a dangerous sink.
    //
    // Minimum signal expected: the BuildStep.execute() cross-file call into
    // CommandRunner.run resolves, and CommandRunner.run's `cmd` param is
    // flagged as taint-propagating (it reaches Runtime.exec / ProcessBuilder).
    const action = `
package app;
import org.kohsuke.stapler.DataBoundConstructor;
public class MyBuilder {
    private final String command;
    @DataBoundConstructor
    public MyBuilder(String command) {
        this.command = command;
    }
    public String getCommand() {
        return command;
    }
}
`;
    const buildStep = `
package app;
public class BuildStep {
    private final MyBuilder builder;
    private final CommandRunner runner = new CommandRunner();
    public BuildStep(MyBuilder builder) {
        this.builder = builder;
    }
    public void execute() throws Exception {
        String cmd = builder.getCommand();
        runner.run(cmd);
    }
}
`;
    const runner = `
package app;
public class CommandRunner {
    public void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
`;
    const result = await analyzeProject([
      { code: action,     filePath: 'MyBuilder.java',     language: 'java' },
      { code: buildStep,  filePath: 'BuildStep.java',     language: 'java' },
      { code: runner,     filePath: 'CommandRunner.java', language: 'java' },
    ]);

    // CommandRunner.run's `cmd` param must be flagged as taint-propagating
    // (it reaches Runtime.exec).  This is the new sink-arg-matching
    // taintedParams summary needed by cross-file chaining.
    const runnerCall = result.cross_file_calls.find(c =>
      c.to.method.endsWith('.run') && c.to.file === 'CommandRunner.java',
    );
    expect(runnerCall).toBeDefined();
    const cmdArg = runnerCall!.args_mapping.find(a => a.callee_param === 0);
    expect(cmdArg?.taint_propagates).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Cross-instance field-binding taint paths (3.39.0)
// ---------------------------------------------------------------------------
//
// Closes the canonical CWE-Bench-Java Jenkins shape and adjacent
// framework-DI patterns where the source is bound onto a field by one class
// and consumed by another class reading that field on an aliased instance.
describe('Cross-instance field-binding taint paths (3.39.0)', () => {
  it('Jenkins ReadTrustedStep: ctor field bound + direct field-read sink', async () => {
    // File A binds `path` (DataBoundConstructor param) into `this.path`.
    // File B holds a ReadTrustedStep field, reads `step.path` directly, and
    // forwards the value to a path-traversal sink in its own body.
    const stepFile = `
package com.example;
public class ReadTrustedStep {
    private String path;
    @DataBoundConstructor
    public ReadTrustedStep(String path) {
        this.path = path;
    }
    public String getPath() {
        return path;
    }
}
`;
    const execFile = `
package com.example;
import java.nio.file.Files;
import java.nio.file.Paths;
public class ExecutionImpl {
    private final ReadTrustedStep step;
    public ExecutionImpl(ReadTrustedStep step) {
        this.step = step;
    }
    public boolean start() throws Exception {
        String p = step.path;
        Files.newInputStream(Paths.get(p));
        return true;
    }
}
`;
    const result = await analyzeProject([
      { filePath: 'src/com/example/ReadTrustedStep.java', code: stepFile, language: 'java' },
      { filePath: 'src/com/example/ExecutionImpl.java',   code: execFile, language: 'java' },
    ]);

    const path = result.taint_paths.find(p =>
      p.sink.file.includes('ExecutionImpl') &&
      (p.sink.type === 'path_traversal' || p.sink.cwe === 'CWE-22'),
    );
    expect(path).toBeDefined();
    expect(path!.source.file).toContain('ReadTrustedStep');
    expect(path!.source.type).toBe('constructor_field');
  });

  it('Jenkins ReadTrustedStep: ctor field bound + getter-mediated sink', async () => {
    // Same shape as above but ExecutionImpl reads via `step.getPath()`.
    // Closed by Change 1 (caller-body-sink emission) in 3.39.0.
    const stepFile = `
package com.example;
public class ReadTrustedStep {
    private String path;
    @DataBoundConstructor
    public ReadTrustedStep(String path) {
        this.path = path;
    }
    public String getPath() {
        return path;
    }
}
`;
    const execFile = `
package com.example;
import java.nio.file.Files;
import java.nio.file.Paths;
public class ExecutionImpl {
    private final ReadTrustedStep step;
    public ExecutionImpl(ReadTrustedStep step) {
        this.step = step;
    }
    public boolean start() throws Exception {
        String p = step.getPath();
        Files.newInputStream(Paths.get(p));
        return true;
    }
}
`;
    const result = await analyzeProject([
      { filePath: 'src/com/example/ReadTrustedStep.java', code: stepFile, language: 'java' },
      { filePath: 'src/com/example/ExecutionImpl.java',   code: execFile, language: 'java' },
    ]);

    const path = result.taint_paths.find(p =>
      p.sink.file.includes('ExecutionImpl') &&
      (p.sink.type === 'path_traversal' || p.sink.cwe === 'CWE-22'),
    );
    expect(path).toBeDefined();
  });

  it('@Autowired field: framework-injected field reaches sink via aliased read', async () => {
    // Spring `@Autowired` field is an injection point; another class reads
    // that field on an aliased instance and forwards to a sink.
    const repoFile = `
package app;
public class UserRepository {
    @Autowired
    private String userInput;
}
`;
    const sinkFile = `
package app;
import java.nio.file.Files;
import java.nio.file.Paths;
public class FileService {
    private final UserRepository repo;
    public FileService(UserRepository repo) {
        this.repo = repo;
    }
    public void open() throws Exception {
        String x = repo.userInput;
        Files.newInputStream(Paths.get(x));
    }
}
`;
    const result = await analyzeProject([
      { filePath: 'src/app/UserRepository.java', code: repoFile, language: 'java' },
      { filePath: 'src/app/FileService.java',    code: sinkFile, language: 'java' },
    ]);

    const path = result.taint_paths.find(p =>
      p.sink.file.includes('FileService') &&
      (p.sink.type === 'path_traversal' || p.sink.cwe === 'CWE-22'),
    );
    expect(path).toBeDefined();
    expect(path!.source.type).toBe('autowired_field');
  });

  it('Ctor + setter mix: ctor-bound field still surfaces when class also has setter', async () => {
    // Confirms ctor-bound field-binding analysis still fires when the same
    // class also exposes a setter for the field (no regression).
    const configFile = `
package app;
public class Config {
    private String target;
    @DataBoundConstructor
    public Config(String target) {
        this.target = target;
    }
    public void setTarget(String target) {
        this.target = target;
    }
    public String getTarget() {
        return target;
    }
}
`;
    const userFile = `
package app;
import java.nio.file.Files;
import java.nio.file.Paths;
public class Loader {
    private final Config config;
    public Loader(Config config) {
        this.config = config;
    }
    public void load() throws Exception {
        String t = config.target;
        Files.newInputStream(Paths.get(t));
    }
}
`;
    const result = await analyzeProject([
      { filePath: 'src/app/Config.java', code: configFile, language: 'java' },
      { filePath: 'src/app/Loader.java', code: userFile,   language: 'java' },
    ]);

    const path = result.taint_paths.find(p =>
      p.sink.file.includes('Loader') &&
      (p.sink.type === 'path_traversal' || p.sink.cwe === 'CWE-22'),
    );
    expect(path).toBeDefined();
    expect(path!.source.type).toBe('constructor_field');
  });
});
