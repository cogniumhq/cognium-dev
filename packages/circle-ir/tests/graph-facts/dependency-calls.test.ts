/**
 * dependency-calls@0.1: calls from a Java subject into one library, and the
 * tests that reach each call (E02, patch a vulnerable dependency).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import { dependencyCalls } from '../../src/graph-facts/index.js';
import * as publicApi from '../../src/index.js';

const APP: Record<string, string> = {
  'src/main/java/app/Codec.java': `package app;
import com.fasterxml.jackson.databind.ObjectMapper;
import static org.apache.commons.text.StringEscapeUtils.escapeHtml4;
public class Codec {
  private final ObjectMapper mapper = new ObjectMapper();
  public String write(Object o) throws Exception { return mapper.writeValueAsString(o); }
  public String html(String s) { return escapeHtml4(s); }
  public int size(String s) { return s.length(); }
}`,
  'src/main/java/app/Service.java': `package app;
public class Service {
  private final Codec codec = new Codec();
  public String render(Object o) throws Exception { return codec.write(o); }
}`,
  'src/test/java/app/ServiceTest.java': `package app;
import org.junit.jupiter.api.Test;
public class ServiceTest {
  @Test
  void renders() throws Exception { new Service().render("x"); }
}`,
};

let g: JavaGraph;

beforeAll(async () => {
  g = await buildJavaGraph(Object.entries(APP).map(([path, code]) => ({ path, code })));
}, 60_000);

describe('dependencyCalls', () => {
  it('lists the calls into the library with the tests that reach them', () => {
    const r = dependencyCalls(g, { packages: ['com.fasterxml.jackson'] });
    expect(r.scheme).toBe('dependency-calls@0.1');
    const rows = r.calls.map(c => `${c.site.line} ${c.receiver}.${c.methodName} ${c.tests.map(t => `${t.class}:${t.file}`).join(',')}`);
    expect(rows).toContain('6 com.fasterxml.jackson.databind.ObjectMapper.writeValueAsString strong:src/test/java/app/ServiceTest.java');
    expect(r.calls.every(c => c.receiver.startsWith('com.fasterxml.jackson.'))).toBe(true);
  });

  it('is not covered when a call has no test path', () => {
    const r = dependencyCalls(g, { packages: ['org.apache.commons.text'] });
    expect(r.calls.map(c => `${c.receiver}.${c.methodName}`)).toEqual(['org.apache.commons.text.StringEscapeUtils.escapeHtml4']);
    expect(r.calls[0].tests).toEqual([]);
    expect(r.uncovered).toBe(1);
    expect(r.covered).toBe(false);
  });

  it('finds nothing for a library the subject does not call', () => {
    const r = dependencyCalls(g, { packages: ['org.yaml.snakeyaml'] });
    expect(r.calls).toEqual([]);
    expect(r.covered).toBe(true);
  });

  it('is exported from the package root', () => {
    expect(publicApi.dependencyCalls).toBe(dependencyCalls);
    expect(publicApi.DEPENDENCY_CALLS_SCHEME).toBe('dependency-calls@0.1');
  });
});
