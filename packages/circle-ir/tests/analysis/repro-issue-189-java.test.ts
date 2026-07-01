import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * #189 Sprint 92 — Java chained-factory FN regression lock
 *
 * Prior to Sprint 92, sink patterns keyed on JAXP factory-produced classes
 * (`DocumentBuilder.parse`, `SAXParser.parse`, `XPath.evaluate`) missed
 * inline call chains like
 * `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(...)`
 * because `resolveReceiverType` could not walk multi-level chains — the
 * receiver's class was reported as `null` and the class-scoped sink pattern
 * never matched.
 *
 * The fix (`packages/circle-ir/src/core/extractors/calls.ts`) makes
 * `resolveReceiverType` recursive via `splitChainedReceiver` and extends
 * `JAVA_CHAINED_FACTORY_RETURN_TYPES` with the JAXP factory entries.
 *
 * This test locks the three shapes that flipped from `[FN]` → `[OK]` in the
 * sub-batch probe (`tests/repro-189-java.test.ts`).
 */
describe('#189 Java chained-factory receiver resolution', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('xxe: DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(taint)', async () => {
    const code = `
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.StringReader;
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String xml = req.getParameter("x");
    DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
  }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.source_type === 'http_param' && f.sink_type === 'xxe')).toBe(true);
  });

  it('xxe: SAXParserFactory.newInstance().newSAXParser().parse(taint, handler)', async () => {
    const code = `
import javax.xml.parsers.*;
import org.xml.sax.helpers.DefaultHandler;
import java.io.*;
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String xml = req.getParameter("x");
    SAXParserFactory.newInstance().newSAXParser().parse(new java.io.ByteArrayInputStream(xml.getBytes()), new DefaultHandler());
  }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.source_type === 'http_param' && f.sink_type === 'xxe')).toBe(true);
  });

  it('xpath: XPathFactory.newInstance().newXPath().evaluate(taintedExpr, doc)', async () => {
    const code = `
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String q = req.getParameter("q");
    Document doc = null;
    XPathFactory.newInstance().newXPath().evaluate("//user[name='" + q + "']", doc);
  }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.source_type === 'http_param' && f.sink_type === 'xpath_injection')).toBe(true);
  });

  it('preserves single-level chained resolution from Sprint 91 (#117)', async () => {
    // Regression guard: the recursive rewrite must not regress the
    // servlet-API single-level chain (`req.getSession().setAttribute(...)`)
    // shipped in 3.140.0.
    const code = `
import jakarta.servlet.http.*;
public class A {
  public void doGet(HttpServletRequest req, HttpServletResponse res) {
    String v = req.getParameter("v");
    req.getSession().setAttribute("k", v);
  }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.sink_type === 'trust_boundary')).toBe(true);
  });
});
