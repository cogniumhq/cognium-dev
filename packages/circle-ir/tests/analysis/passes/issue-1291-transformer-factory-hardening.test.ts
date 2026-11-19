/**
 * cognium-dev#1291 — hardened TransformerFactory (angus-mail text_xml shape)
 * must clear taint xxe at transform(StreamSource, …), like DocumentBuilderFactory.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const xxeFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.flows ?? []).filter((f) => f.sink_type === 'xxe');

const xxeFindings = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'xxe' || f.cwe === 'CWE-611');

describe('cognium-dev#1291 — hardened TransformerFactory', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP — FEATURE_SECURE_PROCESSING + ACCESS_EXTERNAL_* on tainted StreamSource transform', async () => {
    const code = `
import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;

public class TextXml {
  private void setAttribute(TransformerFactory tf, String name, String value) {
    try {
      tf.setAttribute(name, value);
    } catch (Exception e) { }
  }

  public void writeTo(Object obj, HttpServletRequest req, StreamResult result) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
    try {
      tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    } catch (Exception e) { }
    setAttribute(tf, XMLConstants.ACCESS_EXTERNAL_DTD, "");
    setAttribute(tf, XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
  Transformer transformer = tf.newTransformer();
  InputStream in = req.getInputStream();
  transformer.transform(new StreamSource(in), result);
  }
}
`;
    const r = await analyze(code, 'TextXml.java', 'java');
    expect(xxeFlows(r)).toHaveLength(0);
    expect(xxeFindings(r).filter((f) => (f.line ?? 0) > 20)).toHaveLength(0);
  });

  it('TP recall — unhardened TransformerFactory with StreamSource still reports xxe', async () => {
    const code = `
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;

public class BareTf {
  public void writeTo(HttpServletRequest req, StreamResult result) throws Exception {
    Transformer t = TransformerFactory.newInstance().newTransformer();
    InputStream in = req.getInputStream();
    t.transform(new StreamSource(in), result);
  }
}
`;
    const r = await analyze(code, 'BareTf.java', 'java');
    expect(xxeFlows(r).length + xxeFindings(r).length).toBeGreaterThan(0);
  });
});