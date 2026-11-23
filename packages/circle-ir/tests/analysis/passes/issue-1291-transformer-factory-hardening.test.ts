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

  // #1293 follow-up — value-checked external-access hardening.

  // A TransformerFactory whose writeTo body applies `hardening` to a tainted
  // StreamSource transform. Shares angus-mail's `setAttribute(tf, name, value)`
  // wrapper so the value sits at the call site, not behind an indirection.
  const tfWriteTo = (hardening: string) => `
import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;

public class TextXml {
  private void setAttribute(TransformerFactory tf, String name, String value) {
    try { tf.setAttribute(name, value); } catch (Exception e) { }
  }
  public void writeTo(HttpServletRequest req, StreamResult result) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
${hardening}
    Transformer transformer = tf.newTransformer();
    InputStream in = req.getInputStream();
    transformer.transform(new StreamSource(in), result);
  }
}
`;
  const clears = async (name: string, hardening: string) => {
    const r = await analyze(tfWriteTo(hardening), name, 'java');
    expect(xxeFlows(r), name).toHaveLength(0);
    expect(xxeFindings(r).filter((f) => (f.line ?? 0) > 20), name).toHaveLength(0);
  };
  const stays = async (name: string, hardening: string) => {
    const r = await analyze(tfWriteTo(hardening), name, 'java');
    expect(xxeFlows(r).length + xxeFindings(r).length, name).toBeGreaterThan(0);
  };

  it('TP (d) — ACCESS_EXTERNAL_DTD="all" is permissive, not hardening: xxe stays', async () => {
    await stays('AllDtd.java',
      '    setAttribute(tf, XMLConstants.ACCESS_EXTERNAL_DTD, "all");\n' +
      '    setAttribute(tf, XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");');
  });

  it('TP (b) — FEATURE_SECURE_PROCESSING alone is not hardening: xxe stays', async () => {
    await stays('FspOnly.java',
      '    try { tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); } catch (Exception e) { }');
  });

  it('FP (c) — ACCESS_EXTERNAL_DTD="" alone clears xxe', async () => {
    await clears('DtdEmptyOnly.java',
      '    setAttribute(tf, XMLConstants.ACCESS_EXTERNAL_DTD, "");');
  });

  it('FP — literal accessExternalDTD property URI set to "" clears xxe', async () => {
    await clears('UriEmpty.java',
      '    setAttribute(tf, "http://javax.xml.XMLConstants/property/accessExternalDTD", "");');
  });

  it('FP (g) — DocumentBuilderFactory setFeature(disallow-doctype-decl) still clears xxe', async () => {
    const code = `
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class Dbf {
  Document parse(InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    return dbf.newDocumentBuilder().parse(in);
  }
}
`;
    const r = await analyze(code, 'Dbf.java', 'java');
    expect(xxeFlows(r)).toHaveLength(0);
    expect(xxeFindings(r).filter((f) => (f.line ?? 0) > 6)).toHaveLength(0);
  });
});