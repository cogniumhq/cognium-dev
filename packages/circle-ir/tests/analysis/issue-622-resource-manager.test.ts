/**
 * cognium-dev#622 — Undertow ResourceManager.getResource(String) resolves a
 * request path to a file (WildFly CVE-2018-1047). Class-qualified; a
 * constant path is not a flow. ClassLoader.getResource stays out (#233).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const pathFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal' && !f.sanitized);

describe('#622 Undertow ResourceManager.getResource', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const java = (body: string) => analyze(
    [
      'import javax.servlet.http.*;',
      'import io.undertow.server.handlers.resource.ResourceManager;',
      'public class S extends HttpServlet {',
      '  void read(ResourceManager manager, HttpServletRequest req) throws Exception {',
      body,
      '  }',
      '}',
    ].join('\n'),
    'S.java',
    'java',
  );

  it('manager.getResource(request path) is a path_traversal flow', async () => {
    const r = await java('    String path = req.getParameter("path");\n    manager.getResource(path);');
    expect(pathFlows(r).length).toBeGreaterThan(0);
  });

  it('manager.getResource("index.html") stays clean', async () => {
    const r = await java('    manager.getResource("index.html");');
    expect(pathFlows(r)).toHaveLength(0);
  });

  for (const typeName of ['PathResourceManager', 'FileResourceManager', 'ClassPathResourceManager']) {
    it(`${typeName}.getResource(request path) is a path_traversal flow`, async () => {
      const r = await analyze(
        [
          'import javax.servlet.http.*;',
          `import io.undertow.server.handlers.resource.${typeName};`,
          'public class S extends HttpServlet {',
          `  void read(${typeName} manager, HttpServletRequest req) throws Exception {`,
          '    manager.getResource(req.getParameter("path"));',
          '  }',
          '}',
        ].join('\n'),
        'S.java',
        'java',
      );
      expect(pathFlows(r).length).toBeGreaterThan(0);
    });
  }
});
