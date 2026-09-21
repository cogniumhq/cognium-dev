/**
 * xml-entity-expansion — hardening is scoped to the factory, not the file.
 *
 * Any hardening token anywhere in a file used to silence the whole file, so one
 * hardened factory masked every unhardened factory beside it. Reduced from
 * production code in the vuln-localization corpus (keycloak `StaxParserUtil`,
 * activemq `RuntimeConfigurationBroker`, log4j2 `XmlConfiguration`, camel
 * `SpringBootStarterMojo`): a hardened DocumentBuilderFactory in one method, an
 * untouched SchemaFactory in the next.
 *
 * The new check is one-sided on purpose. It fires only for a factory that
 * PROVABLY never receives hardening — chained, or a local that builds a parser,
 * with no hand-off, no return, and no hardening-capable setter ANYWHERE in the
 * method (hardening may land on the factory's product, not the factory).
 * Every ambiguous shape keeps the old file-level silence, and the negative
 * fixtures below pin each of those.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const HARDENED_SIBLING = [
  '  Document parse(InputStream in) throws Exception {',
  '    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();',
  '    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
  '    return dbf.newDocumentBuilder().parse(in);',
  '  }',
];

const wrap = (...methods: string[][]) =>
  [
    'import javax.xml.XMLConstants;',
    'import javax.xml.parsers.*;',
    'import javax.xml.transform.*;',
    'import javax.xml.transform.dom.*;',
    'import javax.xml.transform.stream.*;',
    'import javax.xml.validation.*;',
    'import org.w3c.dom.Document;',
    'import java.io.*;',
    'public class X {',
    ...methods.flat(),
    '}',
  ].join('\n');

const xee = async (code: string) =>
  ((await analyze(code, 'X.java', 'java')).findings ?? [])
    .filter((f) => f.rule_id === 'xml-entity-expansion')
    .map((f) => ({ api: (f.evidence as { api?: string })?.api, line: f.line }));

describe('xml-entity-expansion — per-factory hardening scope', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('fires on an unhardened factory that a hardened sibling used to mask', async () => {
    const found = await xee(wrap(HARDENED_SIBLING, [
      '  void validate(Source doc, InputStream xsd) throws Exception {',
      '    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);',
      '    Schema schema = factory.newSchema(new StreamSource(xsd));',
      '    schema.newValidator().validate(doc);',
      '  }',
    ]));
    expect(found.map((f) => f.api)).toEqual(['SchemaFactory']);
  });

  it('fires on a chained factory, which can never be configured', async () => {
    const found = await xee(wrap(HARDENED_SIBLING, [
      '  Document pom(File f) throws Exception {',
      '    DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();',
      '    return builder.parse(f);',
      '  }',
    ]));
    expect(found.map((f) => f.api)).toEqual(['DocumentBuilderFactory']);
  });

  it('fires when newInstance( is broken across lines', async () => {
    const found = await xee(wrap(HARDENED_SIBLING, [
      '  Schema load(InputStream xsd) throws Exception {',
      '    SchemaFactory schemaFactory = SchemaFactory.newInstance(',
      '        XMLConstants.W3C_XML_SCHEMA_NS_URI);',
      '    return schemaFactory.newSchema(new StreamSource(xsd));',
      '  }',
    ]));
    expect(found.map((f) => f.api)).toEqual(['SchemaFactory']);
  });

  it('fires on a TransformerFactory only when its method reads a StreamSource', async () => {
    const reads = await xee(wrap(HARDENED_SIBLING, [
      '  void xslt(InputStream in, Writer out) throws Exception {',
      '    TransformerFactory tf = TransformerFactory.newInstance();',
      '    tf.newTransformer().transform(new StreamSource(in), new StreamResult(out));',
      '  }',
    ]));
    expect(reads.map((f) => f.api)).toEqual(['TransformerFactory']);

    const writes = await xee(wrap(HARDENED_SIBLING, [
      '  void dump(Document d, Writer out) throws Exception {',
      '    TransformerFactory tf = TransformerFactory.newInstance();',
      '    tf.newTransformer().transform(new DOMSource(d), new StreamResult(out));',
      '  }',
    ]));
    expect(writes).toEqual([]);
  });

  // ---- every ambiguous shape keeps the old file-level silence ----

  it.each([
    ['hardened through a constant declared elsewhere', [
      '  static final String NO_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";',
      '  Document p(InputStream in) throws Exception {',
      '    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();',
      '    f.setFeature(NO_DOCTYPE, true);',
      '    return f.newDocumentBuilder().parse(in);',
      '  }',
    ]],
    ['chained, with the hardening applied to its PRODUCT', [
      '  void load() throws Exception {',
      '    SAXParser sp = SAXParserFactory.newInstance().newSAXParser();',
      '    sp.getXMLReader().setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);',
      '    sp.parse("rules.xml", null);',
      '  }',
    ]],
    ['chained, with its product handed to a helper', [
      '  void load() throws Exception {',
      '    SAXParser sp = SAXParserFactory.newInstance().newSAXParser();',
      '    lockDown(sp);',
      '    sp.parse("rules.xml", null);',
      '  }',
    ]],
    ['handed to a helper that may harden it', [
      '  Document p(InputStream in) throws Exception {',
      '    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();',
      '    secure(f);',
      '    return f.newDocumentBuilder().parse(in);',
      '  }',
      '  void secure(DocumentBuilderFactory x) throws Exception {',
      '    x.setFeature("http://xml.org/sax/features/external-general-entities", false);',
      '  }',
    ]],
    ['returned to a caller that may harden it', [
      '  SAXParserFactory make() {',
      '    SAXParserFactory f = SAXParserFactory.newInstance();',
      '    f.setNamespaceAware(true);',
      '    return f;',
      '  }',
    ]],
    ['held in a field', [
      '  private SchemaFactory sf;',
      '  void init() { sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI); }',
      '  Schema s(InputStream xsd) throws Exception { return sf.newSchema(new StreamSource(xsd)); }',
    ]],
    ['created to inspect, never used to build a parser', [
      '  boolean xerces() {',
      '    SAXParserFactory f = SAXParserFactory.newInstance();',
      '    return f.getClass().getName().contains("xerces");',
      '  }',
    ]],
  ])('stays silent when the factory is %s', async (_name, method) => {
    expect(await xee(wrap(HARDENED_SIBLING, method as string[]))).toEqual([]);
  });

  it('stays silent when hardening is process-wide (jdk.xml.* limits)', async () => {
    expect(await xee(wrap([
      '  static { System.setProperty("jdk.xml.entityExpansionLimit", "1"); }',
      '  Schema s(InputStream xsd) throws Exception {',
      '    SchemaFactory f = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);',
      '    return f.newSchema(new StreamSource(xsd));',
      '  }',
    ]))).toEqual([]);
  });

  it('leaves a file with no hardening evidence exactly as before', async () => {
    const found = await xee(wrap([
      '  private SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);',
      '  SAXParserFactory make() { SAXParserFactory f = SAXParserFactory.newInstance(); return f; }',
    ]));
    expect(found.map((f) => f.api).sort()).toEqual(['SAXParserFactory', 'SchemaFactory']);
  });
});
