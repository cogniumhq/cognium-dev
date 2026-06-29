/**
 * Sprint 62 — cognium-dev #171 recall lock.
 *
 * Companion / inverse of #166 (Sprint 44, v3.102.0). Verifies that the
 * Java XXE pass STILL FIRES on the plantuml `XmlFactories` shape — a
 * factory-holder class that calls `DocumentBuilderFactory.newInstance()`
 * and `TransformerFactory.newInstance()` with zero hardening flags set
 * anywhere in the file. Parsing happens elsewhere in the project
 * (`SvgSaxParser`), so the file contains no `.parse(...)` and no
 * `DOMSource` / `StreamResult` output-only indicators that would
 * trigger the Sprint 43 #173 suppression.
 *
 * Behavioral contract verified here:
 *   - Plantuml XmlFactories shape → high-severity finding fires
 *     (legitimate TP — flagged as security risk, upstream-reportable).
 *   - Hardened shape with `FEATURE_SECURE_PROCESSING` or any
 *     `JAVA_SAFE_EVIDENCE_RE` token in the same file → fully suppressed
 *     (matches Sprint 44 #166 binary-suppression contract; the ticket's
 *     "low-confidence emit" enhancement is intentionally out of scope —
 *     would reverse the explicit Sprint 44 design decision to fully
 *     suppress rather than downgrade).
 *
 * Recall-lock-only — no source change in this sprint.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countXxe = (
  findings: Array<{ rule_id?: string }> | undefined,
) =>
  (findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion').length;

describe('cognium-dev #171 — Java XXE no-hardening recall lock (plantuml shape)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // Plantuml shape — must fire (high-confidence TP)
  // -------------------------------------------------------------------------

  it('#171 TP-1 — plantuml XmlFactories: DocumentBuilderFactory.newInstance() with no hardening fires', async () => {
    // Reproduces the exact factory-holder shape from
    // plantuml__plantuml/src/main/java/net/sourceforge/plantuml/xml/XmlFactories.java
    const code = `
package net.sourceforge.plantuml.xml;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;

public class XmlFactories {
    private static class DocumentBuilderFactoryHolder {
        static final DocumentBuilderFactory INSTANCE = DocumentBuilderFactory.newInstance();
    }
    private static class TransformerFactoryHolder {
        static final TransformerFactory INSTANCE = TransformerFactory.newInstance();
    }
    public static DocumentBuilder newDocumentBuilder() throws ParserConfigurationException {
        return DocumentBuilderFactoryHolder.INSTANCE.newDocumentBuilder();
    }
    public static Transformer newTransformer() throws TransformerConfigurationException {
        return TransformerFactoryHolder.INSTANCE.newTransformer();
    }
}
`;
    const r = await analyze(code, 'XmlFactories.java', 'java');
    expect(countXxe(r.findings)).toBeGreaterThanOrEqual(1);
  });

  it('#171 TP-2 — bare DocumentBuilderFactory.newInstance() without hardening fires', async () => {
    const code = `
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

public class BareDbf {
    public void parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xml);
    }
}
`;
    const r = await analyze(code, 'BareDbf.java', 'java');
    expect(countXxe(r.findings)).toBeGreaterThanOrEqual(1);
  });

  it('#171 TP-3 — bare SAXParserFactory.newInstance() without hardening fires', async () => {
    const code = `
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;

public class BareSax {
    public void parse(java.io.InputStream xml) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser sp = spf.newSAXParser();
        sp.parse(xml, null);
    }
}
`;
    const r = await analyze(code, 'BareSax.java', 'java');
    expect(countXxe(r.findings)).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Sprint 44 #166 contract — hardened shape still suppressed
  // -------------------------------------------------------------------------

  it('#171 TN-1 — hardened DocumentBuilderFactory (FEATURE_SECURE_PROCESSING) suppressed', async () => {
    const code = `
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

public class HardenedDbf {
    public void parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xml);
    }
}
`;
    const r = await analyze(code, 'HardenedDbf.java', 'java');
    expect(countXxe(r.findings)).toBe(0);
  });

  it('#171 TN-2 — hardened TransformerFactory (ACCESS_EXTERNAL_DTD) suppressed', async () => {
    const code = `
import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;

public class HardenedTf {
    public TransformerFactory build() {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return tf;
    }
}
`;
    const r = await analyze(code, 'HardenedTf.java', 'java');
    expect(countXxe(r.findings)).toBe(0);
  });
});
