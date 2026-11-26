/**
 * Java xxe — a hardened factory also silences the inter-procedural flow.
 *
 * TaintPropagationPass drops an xxe flow whose sink sits in a method that
 * hardens its DocumentBuilderFactory (`isInJavaSanitizedMethod`, #101). The
 * inter-procedural pass adds flows after that filter ran: in a report reader
 * whose own method is named `parse`, `docBuilder.parse(is)` resolves to that
 * method by name, and the flow comes back as "call to parse()". The textbook
 * fix (`disallow-doctype-decl` set to true) therefore never cleared the
 * finding, and a re-check of that fix said "still present". Reduced from the
 * result-file readers in OWASP BenchmarkUtils (`score/parsers/*Reader.java`).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const reader = (hardening: string[]) =>
  [
    'import java.io.StringReader;',
    'import javax.xml.parsers.DocumentBuilder;',
    'import javax.xml.parsers.DocumentBuilderFactory;',
    'import org.w3c.dom.Document;',
    'import org.xml.sax.InputSource;',
    'public class ToolReader extends Reader {',
    '    @Override',
    '    public Results parse(ResultFile resultFile) throws Exception {',
    '        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();',
    ...hardening,
    '        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();',
    '        InputSource is = new InputSource(new StringReader(resultFile.content()));',
    '        Document doc = docBuilder.parse(is);',
    '        return new Results(doc);',
    '    }',
    '}',
  ].join('\n');

const xxeFlows = async (code: string) =>
  ((await analyze(code, 'ToolReader.java', 'java')).taint?.flows ?? []).filter(
    (f) => f.sink_type === 'xxe',
  );

describe('java xxe — hardened factory and inter-procedural flows', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('keeps the flow when the factory is not hardened', async () => {
    const flows = await xxeFlows(reader([]));
    expect(flows.length).toBeGreaterThan(0);
  });

  it('drops the flow once disallow-doctype-decl is set on the factory', async () => {
    const flows = await xxeFlows(
      reader([
        '        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
      ]),
    );
    expect(flows).toEqual([]);
  });

  it('drops the flow when the external-entity features are turned off', async () => {
    const flows = await xxeFlows(
      reader([
        '        docBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);',
        '        docBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);',
      ]),
    );
    expect(flows).toEqual([]);
  });
});
