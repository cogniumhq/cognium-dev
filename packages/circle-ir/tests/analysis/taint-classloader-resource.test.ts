/**
 * Tests for classpath-resource lookups as `path_traversal` sinks.
 * `Class.getResource(name)` and Spring `ResourceLoader.getResource(name)`
 * are not sinks (#233). `ClassLoader.getResource(name)` /
 * `getResourceAsStream(name)` are CWE-22 sinks again for a non-constant name
 * (#621, Spark CVE-2018-9159); a string-literal name is dropped by the
 * constant-argument filter and covered in issue-621-classloader-resource-sink.
 * Filesystem sinks (`FileInputStream(name)`, `Files.readAllBytes(Paths.get(name))`,
 * `File(name)`) remain sinks.
 *
 * Originally cognium-dev#233 (path_traversal family).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';

async function pathSinksFor(code: string) {
  const tree = await parse(code, 'java');
  const calls = extractCalls(tree);
  const types = extractTypes(tree);
  const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java');
  return taint.sinks.filter((s) => s.type === 'path_traversal');
}

describe('Classpath-resource lookups as path_traversal (#233, #621)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('ClassLoader.getResource(name) with a non-constant name IS a path_traversal sink (#621)', async () => {
    const code = `
public class Svc {
  public java.net.URL run(ClassLoader cl, String name) {
    return cl.getResource(name);
  }
}
`;
    const sinks = await pathSinksFor(code);
    expect(sinks.find((s) => s.method === 'getResource')).toBeDefined();
  });

  it('ClassLoader.getResourceAsStream(name) with a non-constant name IS a path_traversal sink (#621)', async () => {
    const code = `
public class Svc {
  public java.io.InputStream run(ClassLoader cl, String name) {
    return cl.getResourceAsStream(name);
  }
}
`;
    const sinks = await pathSinksFor(code);
    expect(sinks.find((s) => s.method === 'getResourceAsStream')).toBeDefined();
  });

  it('Class.getResource(name) is NOT a path_traversal sink', async () => {
    const code = `
public class Svc {
  public java.net.URL run(String name) {
    return Svc.class.getResource(name);
  }
}
`;
    const sinks = await pathSinksFor(code);
    expect(sinks.find((s) => s.method === 'getResource')).toBeUndefined();
  });

  it('ResourceLoader.getResource(name) is NOT a path_traversal sink', async () => {
    const code = `
public class Svc {
  public Object run(org.springframework.core.io.ResourceLoader loader, String name) {
    return loader.getResource(name);
  }
}
`;
    const sinks = await pathSinksFor(code);
    expect(sinks.find((s) => s.method === 'getResource')).toBeUndefined();
  });

  it('FileInputStream(userPath) IS still a path_traversal sink', async () => {
    const code = `
public class Svc {
  public java.io.FileInputStream run(String userPath) throws Exception {
    return new java.io.FileInputStream(userPath);
  }
}
`;
    const sinks = await pathSinksFor(code);
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('URL.openStream() is NOT a path_traversal sink (SSRF, deduped)', async () => {
    // openStream was removed from path.yaml as a duplicate of the SSRF entry.
    // It may still appear as an `ssrf` sink — but MUST NOT appear as
    // path_traversal.
    const code = `
public class Svc {
  public java.io.InputStream run(java.net.URL u) throws Exception {
    return u.openStream();
  }
}
`;
    const sinks = await pathSinksFor(code);
    expect(sinks.find((s) => s.method === 'openStream')).toBeUndefined();
  });
});
