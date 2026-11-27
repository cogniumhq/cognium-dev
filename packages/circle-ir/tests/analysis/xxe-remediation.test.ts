/**
 * XXE (CWE-611) findings name the parser kind and the one-line hardening in
 * `remediation`, so a reader sees a concrete next step instead of the generic
 * "disable external entity processing".
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { getRemediation } from '../../src/analysis/rules.js';
import { pythonImportAliases, xxeParserFix, xxeRemediation } from '../../src/analysis/xxe-remediation.js';

type Lang = 'java' | 'csharp' | 'python' | 'javascript';

async function xxeRemediations(code: string, file: string, lang: Lang): Promise<string[]> {
  const r = await analyze(code, file, lang);
  const findings = generateFindings(
    r.taint.sources, r.taint.sinks, r.dfg, file, code, lang,
    r.taint.sanitizers, r.types, r.taint.flows,
  );
  return findings.filter(f => f.type === 'xxe').map(f => f.remediation);
}

const servlet = (body: string) => `import javax.servlet.http.*;
import java.io.*;

public class T {
  public void h(HttpServletRequest req) throws Exception {
${body}
  }
}
`;

describe('XXE remediation names the parser and the hardening line', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('DocumentBuilderFactory', async () => {
    const rem = await xxeRemediations(servlet(`    javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
    javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
    db.parse(req.getInputStream());`), 'T.java', 'java');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: DocumentBuilderFactory.');
      expect(r).toContain('factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);');
    }
  });

  it('SAXParserFactory', async () => {
    const rem = await xxeRemediations(servlet(`    javax.xml.parsers.SAXParserFactory spf = javax.xml.parsers.SAXParserFactory.newInstance();
    javax.xml.parsers.SAXParser sp = spf.newSAXParser();
    sp.parse(req.getInputStream(), new org.xml.sax.helpers.DefaultHandler());`), 'T.java', 'java');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: SAXParserFactory.');
      expect(r).toContain('disallow-doctype-decl", true);');
      expect(r).toContain('newSAXParser()');
    }
  });

  it('XMLReader', async () => {
    const rem = await xxeRemediations(servlet(`    org.xml.sax.XMLReader r = org.xml.sax.helpers.XMLReaderFactory.createXMLReader();
    r.parse(new org.xml.sax.InputSource(req.getInputStream()));`), 'T.java', 'java');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: XMLReader.');
      expect(r).toContain('reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);');
    }
  });

  it('TransformerFactory', async () => {
    const rem = await xxeRemediations(servlet(`    javax.xml.transform.TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();
    javax.xml.transform.Transformer t = tf.newTransformer();
    t.transform(new javax.xml.transform.stream.StreamSource(req.getInputStream()), new javax.xml.transform.stream.StreamResult(System.out));`), 'T.java', 'java');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: TransformerFactory.');
      expect(r).toContain('factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");');
    }
  });

  it('JAXB Unmarshaller', async () => {
    const rem = await xxeRemediations(servlet(`    javax.xml.bind.JAXBContext ctx = javax.xml.bind.JAXBContext.newInstance(T.class);
    javax.xml.bind.Unmarshaller u = ctx.createUnmarshaller();
    u.unmarshal(req.getInputStream());`), 'T.java', 'java');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: Unmarshaller (JAXB).');
      expect(r).toContain('xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);');
    }
  });

  it('C# XmlDocument', async () => {
    const rem = await xxeRemediations(`using System.Xml;
using Microsoft.AspNetCore.Mvc;
public class C : Controller {
  public IActionResult P(string xml) {
    var doc = new XmlDocument();
    doc.LoadXml(xml);
    return Ok();
  }
}
`, 'C.cs', 'csharp');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: XmlDocument.');
      expect(r).toContain('doc.XmlResolver = null;');
    }
  });

  it('C# XmlTextReader (constructor sink, no receiver)', async () => {
    const rem = await xxeRemediations(`using System.Xml;
using Microsoft.AspNetCore.Mvc;
public class C : Controller {
  public IActionResult P(string path) {
    var r = new XmlTextReader(path);
    return Ok();
  }
}
`, 'C.cs', 'csharp');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: XmlTextReader.');
      expect(r).toContain('reader.DtdProcessing = DtdProcessing.Prohibit;');
    }
  });

  it('Python lxml.etree', async () => {
    const rem = await xxeRemediations(`from flask import request
from lxml import etree

@app.route('/x')
def x():
    data = request.args.get('d')
    return etree.fromstring(data)
`, 'x.py', 'python');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: lxml.etree.');
      expect(r).toContain('etree.XMLParser(resolve_entities=False, no_network=True)');
    }
  });

  const flaskFromstring = (imp: string, recv: string) => `from flask import request
${imp}

@app.route('/x')
def x():
    data = request.args.get('d')
    return ${recv}.fromstring(data)
`;

  it.each([
    ['import lxml.etree', 'lxml.etree'],
    ['from lxml import etree as ET', 'ET'],
    ['import lxml.etree as et', 'et'],
  ])('Python lxml via %s', async (imp, recv) => {
    const rem = await xxeRemediations(flaskFromstring(imp, recv), 'x.py', 'python');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: lxml.etree.');
      expect(r).toContain('etree.XMLParser(resolve_entities=False, no_network=True)');
    }
  });

  // The stdlib ElementTree has no XMLParser(resolve_entities=...): lxml's
  // advice would raise TypeError there, so an `etree` alias of the stdlib
  // module must get the defusedxml line instead.
  it.each([
    ['import xml.etree.ElementTree as etree', 'etree'],
    ['import xml.etree.ElementTree as ET', 'ET'],
    ['from xml.etree import ElementTree as etree', 'etree'],
  ])('Python stdlib ElementTree via %s', async (imp, recv) => {
    const rem = await xxeRemediations(flaskFromstring(imp, recv), 'x.py', 'python');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: xml.etree.ElementTree.');
      expect(r).toContain('from defusedxml.ElementTree import fromstring');
      expect(r).not.toContain('resolve_entities');
      expect(r).not.toContain('XMLParser(');
    }
  });

  it('Python xml.dom.minidom', async () => {
    const rem = await xxeRemediations(`from flask import request
from xml.dom import minidom

@app.route('/x')
def x():
    data = request.args.get('d')
    return minidom.parseString(data)
`, 'x.py', 'python');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: xml.dom.minidom.');
      expect(r).toContain('from defusedxml.minidom import parseString');
    }
  });

  it('libxmljs', async () => {
    const rem = await xxeRemediations(`const libxmljs = require('libxmljs');
module.exports.bulk = function (req, res) {
  var p = libxmljs.parseXmlString(req.body.x, {noent:true})
  res.send('ok')
}
`, 'h.js', 'javascript');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('Parser: libxmljs.');
      expect(r).toContain('Add `libxmljs.parseXmlString(text, { noent: false })` in place of the call; never pass noent: true.');
    }
  });

  it('libxml alias names the method it calls', async () => {
    const rem = await xxeRemediations(`const libxml = require('libxmljs2');
module.exports.bulk = function (req, res) {
  var p = libxml.parseXmlString(req.body.x, {noent:true})
  res.send('ok')
}
`, 'h.js', 'javascript');
    expect(rem.length).toBeGreaterThan(0);
    for (const r of rem) {
      expect(r).toContain('`libxml.parseXmlString(text, { noent: false })`');
      expect(r).not.toContain('parseXml(');
    }
  });
});

describe('xxeParserFix', () => {
  it.each([
    [{ class: 'DocumentBuilder', method: 'parse', location: 'db.parse() in h' }, 'DocumentBuilderFactory'],
    [{ class: 'javax.xml.parsers.SAXParser', method: 'parse', location: 'sp.parse() in h' }, 'SAXParserFactory'],
    [{ class: 'XMLStreamReader', method: 'next', location: 'xr.next() in h' }, 'XMLInputFactory'],
    [{ class: 'XMLInputFactory', method: 'createXMLStreamReader', location: 'xif.createXMLStreamReader() in h' }, 'XMLInputFactory'],
    [{ class: 'Transformer', method: 'transform', location: 't.transform() in h' }, 'TransformerFactory'],
    [{ class: 'SchemaFactory', method: 'newSchema', location: 'sf.newSchema() in h' }, 'SchemaFactory'],
    [{ class: 'XDocument', method: 'Load', location: 'XDocument.Load() in P' }, 'XDocument'],
    [{ method: 'LoadXml', location: 'LoadXml() in P' }, 'XmlDocument'],
    [{ method: 'parse', location: 'sax.parse() in f' }, 'xml.sax'],
  ])('%o -> %s', (sink, parser) => {
    expect(xxeParserFix(sink)?.parser).toBe(parser);
  });

  it('Validator is hardened on the validator itself', () => {
    const fix = xxeParserFix({ class: 'javax.xml.validation.Validator', method: 'validate', location: 'v.validate() in h' });
    expect(fix?.parser).toBe('Validator');
    expect(fix?.line).toBe('validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");');
    expect(fix?.where).toContain('ACCESS_EXTERNAL_SCHEMA');
    expect(fix?.where).toContain('validator');
  });

  it('a bare etree receiver with no import to resolve it keeps the generic text', () => {
    // `etree` is lxml or the stdlib by import; without one, neither line is safe.
    expect(xxeParserFix({ method: 'fromstring', location: 'etree.fromstring() in x' })).toBeUndefined();
    expect(xxeParserFix({ class: 'etree', method: 'parse', location: '' })).toBeUndefined();
  });

  it('an etree receiver resolves through the file imports', () => {
    const lxml = pythonImportAliases('from lxml import etree\n');
    const std = pythonImportAliases('import xml.etree.ElementTree as etree\n');
    const sink = { method: 'parse', location: 'etree.parse() in x' };
    expect(xxeParserFix(sink, lxml)?.parser).toBe('lxml.etree');
    expect(xxeParserFix(sink, std)?.parser).toBe('xml.etree.ElementTree');
    expect(xxeParserFix(sink, std)?.line).toBe('from defusedxml.ElementTree import parse');
  });

  it('a qualified receiver names its module without imports', () => {
    expect(xxeParserFix({ method: 'fromstring', location: 'lxml.etree.fromstring() in x' })?.parser).toBe('lxml.etree');
    const std = xxeParserFix({ method: 'XML', location: 'xml.etree.ElementTree.XML() in x' });
    expect(std?.parser).toBe('xml.etree.ElementTree');
    expect(std?.line).toBe('from defusedxml.ElementTree import XML');
  });

  it('pythonImportAliases reads import and from-import bindings', () => {
    const m = pythonImportAliases([
      'import xml.etree.ElementTree as ET',
      'from lxml import etree as LE, objectify',
      'import os',
      '    from xml.etree import cElementTree',
    ].join('\n'));
    expect(m.get('ET')).toBe('xml.etree.ElementTree');
    expect(m.get('LE')).toBe('lxml.etree');
    expect(m.get('objectify')).toBe('lxml.objectify');
    expect(m.get('cElementTree')).toBe('xml.etree.cElementTree');
    expect(m.has('os')).toBe(false);
  });

  it('XMLInputFactory line disables DTD support', () => {
    expect(xxeParserFix({ class: 'XMLInputFactory', location: '' })?.line)
      .toBe('factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);');
  });

  it('an unknown parser keeps the generic remediation', () => {
    const generic = getRemediation('xxe');
    const sink = { class: 'SomethingElse', method: 'parse', location: 'p.parse() in f' };
    expect(xxeParserFix(sink)).toBeUndefined();
    expect(xxeRemediation(sink, generic)).toBe(generic);
  });

  it('a known parser keeps the generic text after the specific line', () => {
    const generic = getRemediation('xxe');
    const r = xxeRemediation({ class: 'DocumentBuilder', location: 'db.parse() in h' }, generic);
    expect(r.startsWith('Parser: DocumentBuilderFactory. Add `')).toBe(true);
    expect(r.endsWith(generic)).toBe(true);
  });
});

describe('xml-entity-expansion fix names the factory hardening', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const factoryFix = async (body: string) => {
    const r = await analyze(servlet(body), 'T.java', 'java');
    return (r.findings ?? []).filter(f => f.rule_id === 'xml-entity-expansion').map(f => f.fix);
  };

  it('TransformerFactory', async () => {
    const fixes = await factoryFix(`    javax.xml.transform.TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();
    javax.xml.transform.Transformer t = tf.newTransformer();
    t.transform(new javax.xml.transform.stream.StreamSource(req.getInputStream()), new javax.xml.transform.stream.StreamResult(System.out));`);
    expect(fixes).toHaveLength(1);
    expect(fixes[0]).toContain('Parser: TransformerFactory.');
    expect(fixes[0]).toContain('factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");');
  });

  it('SchemaFactory', async () => {
    const fixes = await factoryFix(`    javax.xml.validation.SchemaFactory sf = javax.xml.validation.SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
    javax.xml.validation.Schema s = sf.newSchema(new javax.xml.transform.stream.StreamSource(req.getInputStream()));`);
    expect(fixes).toHaveLength(1);
    expect(fixes[0]).toContain('Parser: SchemaFactory.');
    expect(fixes[0]).toContain('factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");');
  });

  it('XMLInputFactory keeps its own fix', async () => {
    const fixes = await factoryFix(`    javax.xml.stream.XMLInputFactory xif = javax.xml.stream.XMLInputFactory.newInstance();
    javax.xml.stream.XMLStreamReader xr = xif.createXMLStreamReader(req.getInputStream());`);
    expect(fixes).toHaveLength(1);
    expect(fixes[0]).toContain('XMLInputFactory.SUPPORT_DTD, false');
  });
});
