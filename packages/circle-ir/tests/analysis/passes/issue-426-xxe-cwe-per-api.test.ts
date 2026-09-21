/**
 * #426 — xml-entity-expansion assigns its CWE per API.
 *
 * Every finding used to carry CWE-776 (entity expansion). For the APIs whose
 * unhardened default resolves EXTERNAL entities, the accurate primary weakness
 * is CWE-611, and the rule's own JS variant already said so — the rule disagreed
 * with itself across languages.
 *
 *   Java JAXP factories     CWE-611   external entities on by default; JAXP
 *                                     ships a default expansion limit
 *   lxml.etree              CWE-611   resolve_entities defaults on
 *   xml.etree.ElementTree   CWE-776   never resolves external entities
 *   libxmljs { noent: true } CWE-611  unchanged
 *
 * Label only: no finding is added or removed, and rule_id is unchanged.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

type Lang = 'java' | 'python' | 'javascript';
const cwes = async (code: string, file: string, lang: Lang) =>
  ((await analyze(code, file, lang)).findings ?? [])
    .filter((f) => f.rule_id === 'xml-entity-expansion')
    .map((f) => f.cwe);

const java = (factory: string, make = `${factory}.newInstance()`) => [
  'import javax.xml.parsers.*;',
  'import javax.xml.stream.*;',
  'import javax.xml.transform.*;',
  'import javax.xml.validation.*;',
  'public class T {',
  `  Object make() throws Exception { ${factory} f = ${make}; return f; }`,
  '}',
].join('\n');

describe('#426 — xml-entity-expansion CWE per API', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['SAXParserFactory', undefined],
    ['DocumentBuilderFactory', undefined],
    ['XMLInputFactory', undefined],
    ['TransformerFactory', undefined],
    ['SchemaFactory', 'SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema")'],
  ])('Java %s is CWE-611', async (factory, make) => {
    expect(await cwes(java(factory, make as string | undefined), 'T.java', 'java')).toEqual(['CWE-611']);
  });

  it('lxml.etree is CWE-611', async () => {
    const code = 'from lxml import etree\n\ndef load(data):\n    return etree.fromstring(data)\n';
    expect(await cwes(code, 't.py', 'python')).toEqual(['CWE-611']);
  });

  it('xml.etree.ElementTree stays CWE-776 — it never resolves external entities', async () => {
    const code = 'import xml.etree.ElementTree as ET\n\ndef load(data):\n    return ET.fromstring(data)\n';
    expect(await cwes(code, 't.py', 'python')).toEqual(['CWE-776']);
  });

  it('agrees with the JS variant of the same rule, which was already CWE-611', async () => {
    const code = "const libxml = require('libxmljs');\nfunction load(buf) { return libxml.parseXml(buf, { noent: true }); }\n";
    expect(await cwes(code, 't.js', 'javascript')).toEqual(['CWE-611']);
  });

  it('names only the weakness that applies in the message', async () => {
    const msg = async (code: string) =>
      ((await analyze(code, 't.py', 'python')).findings ?? [])
        .filter((f) => f.rule_id === 'xml-entity-expansion')
        .map((f) => f.message)
        .join(' ');
    const et = await msg('import xml.etree.ElementTree as ET\n\ndef load(d):\n    return ET.fromstring(d)\n');
    expect(et).toContain('CWE-776');
    expect(et).not.toContain('CWE-611');
    const lx = await msg('from lxml import etree\n\ndef load(d):\n    return etree.fromstring(d)\n');
    expect(lx).toContain('CWE-611');
  });
});
