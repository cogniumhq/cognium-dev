/**
 * cognium-dev #1035 — #173 empty-DocumentBuilder suppression must not drop a
 * real CWE-611 when `.parse(...)` is live and `newDocument()` appears only in
 * a comment (jettison AbstractDOMDocumentParser shape).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countXxeFindings = (
  findings: Array<{ rule_id?: string }> | undefined,
) => (findings ?? []).filter((f) => f.rule_id === 'xml-entity-expansion').length;

describe('cognium-dev #1035 — Java XXE #173 jettison-shaped recall', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP — unhardened DocumentBuilderFactory with live parse; newDocument only in comment', async () => {
    const code = `
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class AbstractDOMDocumentParser {
  private DocumentBuilderFactory factory;

  protected DocumentBuilderFactory getDocumentBuilderFactory() {
    if (factory == null) {
      factory = DocumentBuilderFactory.newInstance();
    }
    return factory;
  }

  public Document parse(InputStream in) throws Exception {
    // builder.newDocument(); — empty tree helper only, not used here
    return getDocumentBuilderFactory().newDocumentBuilder().parse(in);
  }
}
`;
    const r = await analyze(code, 'AbstractDOMDocumentParser.java', 'java');
    expect(countXxeFindings(r.findings)).toBeGreaterThanOrEqual(1);
  });

  it('FP control — empty DocumentBuilder only (no parse): still suppressed', async () => {
    const code = `
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class EmptyDocBuilder {
  public Document build() throws Exception {
    DocumentBuilder b = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    return b.newDocument();
  }
}
`;
    const r = await analyze(code, 'EmptyDocBuilder.java', 'java');
    expect(countXxeFindings(r.findings)).toBe(0);
  });
});
