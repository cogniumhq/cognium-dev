/**
 * Dogfood 2026-10-31 (cognium-ai secret-scan/scanner.ts, #989): a TypeScript
 * `scanner.scan(directory)` matched the Java AntiSamy `scan` XSS sinks through
 * the receiver-name heuristic (`scanner` ~ `AntiSamyDOMScanner`). The AntiSamy
 * sinks are Java-only.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('AntiSamy sinks apply to Java only', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a TS scanner.scan(directory) is not an XSS sink', async () => {
    const code = `export async function scanForSecrets(directory: string) {\n  const scanner = new SecretScanner({});\n  return scanner.scan(directory);\n}`;
    const r = await analyze(code, 'scanner.ts', 'typescript');
    expect(r.taint.sinks.filter(s => s.type === 'xss')).toHaveLength(0);
  });

  it('Java AntiSamy.scan is still a sink', async () => {
    const code = `import org.owasp.validator.html.*;\npublic class C {\n  void f(String in) throws Exception {\n    AntiSamy as = new AntiSamy();\n    as.scan(in, Policy.getInstance("p.xml"));\n  }\n}`;
    const r = await analyze(code, 'C.java', 'java');
    expect(r.taint.sinks.filter(s => s.type === 'xss' && s.line === 5).length).toBeGreaterThan(0);
  });
});
