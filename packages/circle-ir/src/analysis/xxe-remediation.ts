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
 *
 * Python `etree` (and `ET`) is lxml or the stdlib ElementTree depending on the
 * import, and lxml's hardening raises TypeError on the stdlib module. Those
 * receivers are resolved through the file's imports when given, and keep the
 * generic text when the module cannot be told.
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
const VALIDATOR: XxeParserFix = {
  parser: 'Validator',
  line: 'validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");',
  where: 'on the validator before validate(), with ACCESS_EXTERNAL_SCHEMA set to "" the same way',
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
/** Stdlib ElementTree: swap the import for defusedxml's drop-in of the same call. */
const PY_ELEMENTTREE_CALLS = new Set(['parse', 'fromstring', 'XML', 'iterparse']);
function pyElementTree(method: string | undefined): XxeParserFix {
  const call = method && PY_ELEMENTTREE_CALLS.has(method) ? method : 'fromstring';
  return {
    parser: 'xml.etree.ElementTree',
    line: `from defusedxml.ElementTree import ${call}`,
    where: 'in place of the xml.etree.ElementTree import',
  };
}
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

/** libxmljs / libxmljs2: the receiver and call the code already uses, without noent. */
const LIBXML_CALLS = new Set(['parseXml', 'parseXmlString']);
function jsLibxmljs(recv: string, method: string | undefined): XxeParserFix {
  const call = method && LIBXML_CALLS.has(method) ? method : 'parseXmlString';
  return {
    parser: 'libxmljs',
    line: `${recv}.${call}(text, { noent: false })`,
    where: 'in place of the call; never pass noent: true',
  };
}

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
  Validator: VALIDATOR,
  Unmarshaller: UNMARSHALLER,
  XmlDocument: CS_XML_DOCUMENT,
  XDocument: CS_XDOCUMENT,
  XmlTextReader: CS_XML_TEXT_READER,
  lxml: PY_LXML,
  minidom: PY_MINIDOM,
  sax: PY_SAX,
};

/** Sinks with no receiver at all: the method names the parser. */
const BY_METHOD: Record<string, XxeParserFix> = {
  XmlTextReader: CS_XML_TEXT_READER,
  LoadXml: CS_XML_DOCUMENT,
};

/** Receivers that name the parser by their own text, whatever the method. */
const LIBXML_RECEIVERS = new Set(['libxml', 'libxmljs']);

/** Python names that are an ElementTree-style module: lxml's or the stdlib's. */
const ETREE_NAMES = new Set(['etree', 'ET', 'ElementTree', 'cElementTree']);

/** Receiver written in a sink location, e.g. `lxml.etree.parse() in f` -> `lxml.etree`. */
function receiverPathFromLocation(location: string): string | undefined {
  const m = /^([\w$.]+)\.[\w$]+\s*\(/.exec(location);
  return m ? m[1] : undefined;
}

/**
 * Local Python name -> the module or member it binds, from `import a.b as x`
 * and `from a import b [as x], ...` lines. Plain `import a.b` binds nothing
 * new: calls through it are already qualified.
 */
export function pythonImportAliases(code: string): Map<string, string> {
  const aliases = new Map<string, string>();
  for (const raw of code.split('\n')) {
    const line = raw.trim();
    const imp = /^import\s+([\w.]+)\s+as\s+(\w+)/.exec(line);
    if (imp) {
      aliases.set(imp[2], imp[1]);
      continue;
    }
    const from = /^from\s+([\w.]+)\s+import\s+([^#]+)/.exec(line);
    if (!from) continue;
    for (const item of from[2].replace(/[()\\]/g, '').split(',')) {
      const words = item.trim().split(/\s+/);
      const name = words[0];
      if (!name || name === '*') continue;
      const local = words.length === 3 && words[1] === 'as' ? words[2] : name;
      aliases.set(local, `${from[1]}.${name}`);
    }
  }
  return aliases;
}

/**
 * For an ElementTree-style receiver: `lxml`, `stdlib`, or `unknown` when the
 * module cannot be told. `undefined` when the receiver is not one at all.
 */
function etreeModule(
  receiver: string,
  aliases: ReadonlyMap<string, string> | undefined,
): 'lxml' | 'stdlib' | 'unknown' | undefined {
  const first = receiver.split('.')[0];
  const bound = aliases?.get(first);
  const resolved = bound ? bound + receiver.slice(first.length) : receiver;
  const parts = resolved.split('.');
  if (!ETREE_NAMES.has(parts[parts.length - 1])) return undefined;
  if (parts[0] === 'lxml') return 'lxml';
  if (parts[0] === 'xml') return 'stdlib';
  return 'unknown';
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
  pyAliases?: ReadonlyMap<string, string>,
): XxeParserFix | undefined {
  const recvPath = sink.location ? receiverPathFromLocation(sink.location) : undefined;
  for (const name of [recvPath, sink.class]) {
    if (!name) continue;
    const etree = etreeModule(name, pyAliases);
    if (etree === 'lxml') return PY_LXML;
    if (etree === 'stdlib') return pyElementTree(sink.method);
    if (etree === 'unknown') return undefined;
  }
  if (sink.class) {
    const hit = BY_RECEIVER[tail(sink.class)];
    if (hit) return hit;
  }
  const recv = recvPath ? tail(recvPath) : undefined;
  if (recv) {
    if (LIBXML_RECEIVERS.has(recv)) return jsLibxmljs(recv, sink.method);
    const hit = BY_RECEIVER[recv];
    if (hit) return hit;
  }
  if (sink.class && LIBXML_RECEIVERS.has(tail(sink.class))) {
    return jsLibxmljs(tail(sink.class), sink.method);
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
 * known, else `fallback` (the generic rule remediation). `pyAliases` (from
 * `pythonImportAliases`) tells lxml's `etree` from the stdlib's.
 */
export function xxeRemediation(
  sink: Pick<TaintSink, 'class' | 'method' | 'location'>,
  fallback: string,
  pyAliases?: ReadonlyMap<string, string>,
): string {
  const fix = xxeParserFix(sink, pyAliases);
  return fix ? `${formatXxeFix(fix)} ${fallback}` : fallback;
}
