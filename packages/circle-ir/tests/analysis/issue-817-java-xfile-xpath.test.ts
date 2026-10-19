/**
 * cognium-dev #817 — flow-combo c04 Java xpath_injection FN (cross-file xfile shape).
 * Controller reads HTTP parameter; helper evaluates XPath on the param.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

describe('cognium-dev #817 — Java cross-file xpath_injection (c04)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const controller = `package com.example.web;
import javax.servlet.http.HttpServletRequest;
import com.example.xml.XpathHelper;
public class Controller {
  public void handle(HttpServletRequest req) throws Exception {
    String query = req.getParameter("q");
    XpathHelper helper = new XpathHelper();
    helper.runQuery(query);
  }
}
`;

  const helper = `package com.example.xml;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
public class XpathHelper {
  public void runQuery(String expr) throws Exception {
    XPath xpath = XPathFactory.newInstance().newXPath();
    xpath.evaluate(expr, (Object) null);
  }
}
`;

  it('cross-file http_param → helper xpath_injection sink', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'com/example/xml/XpathHelper.java', language: 'java' },
      { code: controller, filePath: 'com/example/web/Controller.java', language: 'java' },
    ]);
    const paths = (r.taint_paths ?? []).filter((p) => p.sink.type === 'xpath_injection');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    const xfile = paths.find(
      (p) =>
        p.source.file.endsWith('Controller.java') && p.sink.file.endsWith('XpathHelper.java'),
    );
    expect(xfile, 'expected Controller.java → XpathHelper.java xpath_injection').toBeTruthy();
  });

  it('helper alone — no spurious xpath_injection without tainted param', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'com/example/xml/XpathHelper.java', language: 'java' },
    ]);
    const flows = (r.files[0]?.taint?.flows ?? []).filter((f) => f.sink_type === 'xpath_injection');
    expect(flows).toHaveLength(0);
  });
});
