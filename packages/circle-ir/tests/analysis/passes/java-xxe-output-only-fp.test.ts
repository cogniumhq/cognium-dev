/**
 * Tests for cognium-dev #173 — output-only TransformerFactory +
 * empty DocumentBuilder FP suppression (xml-entity-expansion pass).
 *
 * Sprint 43 adds file-level output-direction analysis to
 * `xml-entity-expansion-pass.ts`. The Java path now suppresses two FP
 * shapes (conservative bias — both safe shape present AND unsafe shape
 * absent):
 *
 *   #173a — TransformerFactory used ONLY to SERIALIZE an in-process
 *           Document tree via `DOMSource → StreamResult`. No
 *           `StreamSource` / `SAXSource` / `InputSource` in the file
 *           means no attacker-controllable bytes ever reach the
 *           factory. No XML parsing occurs; no entity resolution
 *           attack surface.
 *
 *   #173b — DocumentBuilderFactory whose builder only calls
 *           `.newDocument()` (creates an empty in-memory tree) and
 *           never `.parse(...)` (never reads bytes). Empty document
 *           construction cannot be exploited.
 *
 * Recall lock: `StreamSource` / `SAXSource` / `InputSource` (real XML
 * parsing entry points), `.parse(...)` on a `DocumentBuilder`, and
 * SAXParserFactory continue to fire. Files that mix the safe shape
 * with an unsafe parse path continue to fire (the unsafe path wins).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countXxeFindings = (
  findings: Array<{ rule_id?: string }> | undefined,
) => (findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion').length;

describe('cognium-dev #173 — Java xml-entity-expansion output-only FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP — output-only TransformerFactory / empty DocumentBuilder
  // -------------------------------------------------------------------------

  it('FP #173 — TransformerFactory serialize DOM→StreamResult: no xxe finding', async () => {
    const code = `import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import java.io.File;

public class XmlSerializer {
  public void write(Document doc, File out) throws Exception {
    Transformer t = TransformerFactory.newInstance().newTransformer();
    t.transform(new DOMSource(doc), new StreamResult(out));
  }
}
`;
    const r = await analyze(code, 'XmlSerializer.java', 'java');
    expect(countXxeFindings(r.findings)).toBe(0);
  });

  it('FP #173 — DocumentBuilder.newDocument() empty-tree only: no xxe finding', async () => {
    const code = `import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class EmptyDocBuilder {
  public Document build() throws Exception {
    DocumentBuilder b = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    Document d = b.newDocument();
    return d;
  }
}
`;
    const r = await analyze(code, 'EmptyDocBuilder.java', 'java');
    expect(countXxeFindings(r.findings)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall locks — XXE patterns that MUST continue to fire
  // -------------------------------------------------------------------------

  it('Recall — TransformerFactory with StreamSource input: xxe finding fires', async () => {
    const code = `import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.transform.stream.StreamResult;
import java.io.InputStream;
import java.io.OutputStream;

public class XmlTransform {
  public void run(InputStream in, OutputStream out) throws Exception {
    Transformer t = TransformerFactory.newInstance().newTransformer();
    t.transform(new StreamSource(in), new StreamResult(out));
  }
}
`;
    const r = await analyze(code, 'XmlTransform.java', 'java');
    expect(countXxeFindings(r.findings)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — DocumentBuilder.parse(input): xxe finding fires', async () => {
    const code = `import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class XmlParse {
  public Document run(InputStream in) throws Exception {
    DocumentBuilder b = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    Document d = b.parse(in);
    return d;
  }
}
`;
    const r = await analyze(code, 'XmlParse.java', 'java');
    expect(countXxeFindings(r.findings)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — SAXParserFactory.newInstance() without safe features: xxe finding fires', async () => {
    const code = `import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;
import java.io.InputStream;

public class SaxParse {
  public void run(InputStream in, DefaultHandler h) throws Exception {
    SAXParser p = SAXParserFactory.newInstance().newSAXParser();
    p.parse(in, h);
  }
}
`;
    const r = await analyze(code, 'SaxParse.java', 'java');
    expect(countXxeFindings(r.findings)).toBeGreaterThanOrEqual(1);
  });

  it('Regression — TransformerFactory in file with a separate .parse(): xxe finding fires (no over-suppression)', async () => {
    const code = `import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import java.io.File;
import java.io.InputStream;

public class MixedXml {
  public Document read(InputStream in) throws Exception {
    DocumentBuilder b = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    return b.parse(in);
  }
  public void write(Document doc, File out) throws Exception {
    Transformer t = TransformerFactory.newInstance().newTransformer();
    t.transform(new DOMSource(doc), new StreamResult(out));
  }
}
`;
    const r = await analyze(code, 'MixedXml.java', 'java');
    expect(countXxeFindings(r.findings)).toBeGreaterThanOrEqual(1);
  });
});
