/**
 * Tests for cognium-dev #181 — Java `xxe` (CWE-611) FP suppression on
 * non-XML parsers (Stage 9f in `sink-filter-pass.ts`).
 *
 * Follow-up to #155 (which closed the `code_injection` over-match on
 * `parser.parse()`). On v3.104.0 the same minimal fixture began firing
 * `xxe` instead — the receiver-fuzzy lookup in `taint-matcher.ts` maps
 * any name ending in `parser` to `SAXParser` / `XMLReader` /
 * `DocumentBuilder`, and the xxe sink rule accepts the call.
 *
 * Stage 9f drops the xxe sink when the resolvable receiver type is in
 * `DATA_PARSER_TYPES` (commonmark `Parser`, CLI arg parsers, date /
 * number parsers, …). Recall on real XML parsers (DocumentBuilder,
 * SAXParser, XMLReader, …) is unchanged because those classes are NOT
 * in DATA_PARSER_TYPES — the gate never trips on them.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countXxeSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'xxe').length;
const countXxeFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'xxe').length;

describe('cognium-dev #181 — Java xxe non-XML-parser FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP-suppression: receiver type ∈ DATA_PARSER_TYPES → no xxe sink
  // -------------------------------------------------------------------------

  it('issue #181 repro — commonmark PARSER.parse(markdown): no xxe sink/flow', async () => {
    const code = `import org.commonmark.parser.Parser;
import org.commonmark.node.Node;

public class SafeMarkdownParse {
    private static final Parser PARSER = Parser.builder().build();
    public Node render(String markdown) {
        return PARSER.parse(markdown);
    }
}
`;
    const r = await analyze(code, 'SafeMarkdownParse.java', 'java');
    expect(countXxeSinks(r.taint?.sinks)).toBe(0);
    expect(countXxeFlows(r.taint?.flows)).toBe(0);
  });

  it('FP — commonmark `parser.parse(md)` local-variable form: no xxe sink', async () => {
    const code = `import org.commonmark.parser.Parser;
import org.commonmark.node.Node;

public class MarkdownService {
    public Node render(String md) {
        Parser parser = Parser.builder().build();
        Node node = parser.parse(md);
        return node;
    }
}
`;
    const r = await analyze(code, 'MarkdownService.java', 'java');
    expect(countXxeSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP — JCommander CommandLine.parse(args): no xxe sink', async () => {
    const code = `import com.beust.jcommander.JCommander;

public class CliApp {
    public void run(String[] args) {
        JCommander cmd = JCommander.newBuilder().build();
        cmd.parse(args);
    }
}
`;
    const r = await analyze(code, 'CliApp.java', 'java');
    expect(countXxeSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall locks: real XML parsers continue to fire xxe sinks
  // -------------------------------------------------------------------------

  it('Recall — DocumentBuilder.parse(stream): xxe sink fires', async () => {
    const code = `import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class XmlLoader {
    public Document load(InputStream xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = f.newDocumentBuilder();
        return builder.parse(xml);
    }
}
`;
    const r = await analyze(code, 'XmlLoader.java', 'java');
    expect(countXxeSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — SAXParser.parse(stream, handler): xxe sink fires', async () => {
    const code = `import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;
import java.io.InputStream;

public class SaxLoader {
    public void load(InputStream xml) throws Exception {
        SAXParser sax = SAXParserFactory.newInstance().newSAXParser();
        sax.parse(xml, new DefaultHandler());
    }
}
`;
    const r = await analyze(code, 'SaxLoader.java', 'java');
    expect(countXxeSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — XMLReader.parse(input): xxe sink fires', async () => {
    const code = `import org.xml.sax.XMLReader;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.XMLReaderFactory;

public class XmlReaderLoader {
    public void load(InputSource src) throws Exception {
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.parse(src);
    }
}
`;
    const r = await analyze(code, 'XmlReaderLoader.java', 'java');
    expect(countXxeSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });
});
