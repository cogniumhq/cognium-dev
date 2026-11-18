/**
 * cognium-dev#1290 — attacker-controlled Class.forName is a CWE-502 deserialization sink.
 * Mirrors yamlbeans YamlReader.findTagClass: Class.forName(tag, true, classLoader).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';
import { analyze } from '../../src/analyzer.js';

describe('#1290 Class.forName deserialization sink', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('Class.forName(tag) registers as a deserialization sink', async () => {
    const code = `
public class Loader {
    public Class<?> findTagClass(String tag, ClassLoader loader) throws Exception {
        return Class.forName(tag, true, loader);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java');
    const sink = taint.sinks.find(
      s => s.method === 'forName' && s.type === 'deserialization',
    );
    expect(sink).toBeDefined();
    expect(sink!.cwe).toBe('CWE-502');
  });

  it('tainted tag yields a flow-backed CWE-502 finding', async () => {
    const code = `
import javax.servlet.http.HttpServletRequest;

public class YamlReaderShim {
    public Object load(HttpServletRequest req) throws Exception {
        String tag = req.getParameter("type");
        Class<?> c = Class.forName(tag, true, getClass().getClassLoader());
        return c.getDeclaredConstructor().newInstance();
    }
}
`;
    const result = await analyze(code, 'YamlReaderShim.java', 'java');
    const deser = result.taint?.flows?.filter(f => f.sink_type === 'deserialization');
    expect(deser?.length).toBeGreaterThan(0);
    expect(deser?.[0]?.source_type).toBe('http_param');
  });
});