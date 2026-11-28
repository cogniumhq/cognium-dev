/**
 * cognium-dev#1455 — a project `Base64` class shadows commons on bare
 * `decodeBase64`, keeping static-state xss across files.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const OTHER = `package org.example.testcode;
public class Other {
  private static String last;
  public static void remember(String value) { last = value; }
  public static String last() { return last; }
}
`;

const BASE64 = `package org.example.testcode;
public class Base64 {
  public static String decodeBase64(String data) {
    Other.remember(data);
    return data;
  }
  public static String last() {
    return Other.last();
  }
}
`;

const HELPER = `package org.example.testcode;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Helper {
  public void doSomething(HttpServletRequest request, HttpServletResponse response) {
    String c = request.getHeader("X");
    String k = Base64.decodeBase64(c);
    String bar = Base64.last();
    response.getWriter().println(bar);
  }
}
`;

const lineOf = (code: string, needle: string) =>
  code.split('\n').findIndex(l => l.includes(needle)) + 1;

describe('issue-1455 Java Base64 bare-name shadow', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('keeps xss when project Base64 shadows commons decodeBase64', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'Other.java', code: OTHER, language: 'java' },
        { filePath: 'Base64.java', code: BASE64, language: 'java' },
        { filePath: 'Helper.java', code: HELPER, language: 'java' },
      ],
      {},
    );
    const helper = pa.files.find(f => f.file.endsWith('Helper.java'));
    expect(helper).toBeDefined();
    const sinkLine = lineOf(HELPER, 'getWriter()');
    const flows = helper!.analysis.taint.flows ?? [];
    expect(helper!.analysis.taint.sources?.some(s => s.type === 'http_header')).toBe(true);
    expect(flows.some(f => f.sink_type === 'xss' && f.sink_line === sinkLine)).toBe(true);
  });
});