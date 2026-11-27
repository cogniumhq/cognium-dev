/**
 * XXE (CWE-611) remediation per parser kind.
 *
 * The generic `xxe` remediation ("disable external entity processing") tells
 * a reader what to do but not where or how. Each XML parser family has its own
 * one-line hardening, set on the object that builds the parser, so a finding
 * that names the parser kind can name the exact line to add.
 *
 * The parser kind is read from the sink: its resolved receiver class when the
 * taint matcher has one (Java, most C#), else the receiver written in the sink
 * location (`etree.fromstring() in x`), else the method name alone for sinks
 * that have no receiver (`new XmlTextReader(...)`). A sink this table does not
 * know keeps the generic text.
 */

import type { TaintSink } from '../types/index.js';

export interface XxeParserFix {
  /** The parser kind the hardening goes on, e.g. `DocumentBuilderFactory`. */
  parser: string;
  /** The hardening line to add, as code. */
  line: string;
  /** Where the line goes. */
  where: string;
}

const DISALLOW_DOCTYPE = '"http://apache.org/xml/features/disallow-doctype-decl"';

const DOCUMENT_BUILDER: XxeParserFix = {
  parser: 'DocumentBuilderFactory',
  line: `factory.setFeature(${DISALLOW_DOCTYPE}, true);`,
  where: 'on the factory before newDocumentBuilder()',
};
const SAX_PARSER: XxeParserFix = {
  parser: 'SAXParserFactory',
  line: `factory.setFeature(${DISALLOW_DOCTYPE}, true);`,
  where: 'on the factory before newSAXParser()',
};
const XML_READER: XxeParserFix = {
  parser: 'XMLReader',
  line: `reader.setFeature(${DISALLOW_DOCTYPE}, true);`,
  where: 'on the reader before parse()',
};
const XML_INPUT: XxeParserFix = {
  parser: 'XMLInputFactory',
  line: 'factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);',
  where: 'on the factory before createXMLStreamReader()',
};
const TRANSFORMER: XxeParserFix = {
  parser: 'TransformerFactory',
  line: 'factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");',
  where: 'on the factory before newTransformer(), with ACCESS_EXTERNAL_STYLESHEET set to "" the same way',
};
const SCHEMA: XxeParserFix = {
  parser: 'SchemaFactory',
  line: 'factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");',
  where: 'on the factory before newSchema(), with ACCESS_EXTERNAL_SCHEMA set to "" the same way',
};
const UNMARSHALLER: XxeParserFix = {
  parser: 'Unmarshaller (JAXB)',
  line: 'xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);',
  where: 'on an XMLInputFactory, then unmarshal(xif.createXMLStreamReader(source)) instead of the raw input',
};

const CS_XML_DOCUMENT: XxeParserFix = {
  parser: 'XmlDocument',
  line: 'doc.XmlResolver = null;',
  where: 'before Load / LoadXml',
};
const CS_XDOCUMENT: XxeParserFix = {
  parser: 'XDocument',
  line: 'XDocument.Load(XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }));',
  where: 'in place of XDocument.Load(input)',
};
const CS_XML_TEXT_READER: XxeParserFix = {
  parser: 'XmlTextReader',
  line: 'reader.DtdProcessing = DtdProcessing.Prohibit;',
  where: 'before the first Read()',
};

const PY_LXML: XxeParserFix = {
  parser: 'lxml.etree',
  line: 'parser = etree.XMLParser(resolve_entities=False, no_network=True)',
  where: 'and pass parser=parser to the parse call (or use defusedxml.lxml)',
};
const PY_MINIDOM: XxeParserFix = {
  parser: 'xml.dom.minidom',
  line: 'from defusedxml.minidom import parseString',
  where: 'in place of the xml.dom.minidom import',
};
const PY_SAX: XxeParserFix = {
  parser: 'xml.sax',
  line: 'from defusedxml.sax import parse',
  where: 'in place of the xml.sax import',
};

const JS_LIBXMLJS: XxeParserFix = {
  parser: 'libxmljs',
  line: 'libxmljs.parseXml(text, { noent: false })',
  where: 'never pass noent: true',
};

/** Receiver class or receiver name -> parser fix. */
const BY_RECEIVER: Record<string, XxeParserFix> = {
  DocumentBuilder: DOCUMENT_BUILDER,
  DocumentBuilderFactory: DOCUMENT_BUILDER,
  SAXParser: SAX_PARSER,
  SAXParserFactory: SAX_PARSER,
  XMLReader: XML_READER,
  XMLInputFactory: XML_INPUT,
  XMLStreamReader: XML_INPUT,
  XMLEventReader: XML_INPUT,
  TransformerFactory: TRANSFORMER,
  Transformer: TRANSFORMER,
  SchemaFactory: SCHEMA,
  Validator: SCHEMA,
  Unmarshaller: UNMARSHALLER,
  XmlDocument: CS_XML_DOCUMENT,
  XDocument: CS_XDOCUMENT,
  XmlTextReader: CS_XML_TEXT_READER,
  etree: PY_LXML,
  lxml: PY_LXML,
  minidom: PY_MINIDOM,
  sax: PY_SAX,
  libxml: JS_LIBXMLJS,
  libxmljs: JS_LIBXMLJS,
};

/** Sinks with no receiver at all: the method names the parser. */
const BY_METHOD: Record<string, XxeParserFix> = {
  XmlTextReader: CS_XML_TEXT_READER,
  LoadXml: CS_XML_DOCUMENT,
};

/** Receiver tail written in a sink location, e.g. `lxml.etree.parse() in f` -> `etree`. */
function receiverFromLocation(location: string): string | undefined {
  const m = /^([\w$.]+)\.[\w$]+\s*\(/.exec(location);
  if (!m) return undefined;
  const parts = m[1].split('.');
  return parts[parts.length - 1];
}

/** Map the Java/C# class tail (`javax.xml.parsers.DocumentBuilder` -> `DocumentBuilder`). */
function tail(name: string): string {
  const parts = name.split('.');
  return parts[parts.length - 1];
}

/**
 * The parser kind and hardening line for an XXE sink, or `undefined` when the
 * sink's parser is not one this table knows.
 */
export function xxeParserFix(
  sink: Pick<TaintSink, 'class' | 'method' | 'location'>,
): XxeParserFix | undefined {
  if (sink.class) {
    const hit = BY_RECEIVER[tail(sink.class)];
    if (hit) return hit;
  }
  const recv = sink.location ? receiverFromLocation(sink.location) : undefined;
  if (recv) {
    const hit = BY_RECEIVER[recv];
    if (hit) return hit;
  }
  if (sink.method) return BY_METHOD[sink.method];
  return undefined;
}

/** One sentence naming the parser kind and the line to add. */
export function formatXxeFix(fix: XxeParserFix): string {
  return `Parser: ${fix.parser}. Add \`${fix.line}\` ${fix.where}.`;
}

/**
 * The remediation text for an XXE sink: parser kind and hardening line when
 * known, else `fallback` (the generic rule remediation).
 */
export function xxeRemediation(
  sink: Pick<TaintSink, 'class' | 'method' | 'location'>,
  fallback: string,
): string {
  const fix = xxeParserFix(sink);
  return fix ? `${formatXxeFix(fix)} ${fallback}` : fallback;
}
