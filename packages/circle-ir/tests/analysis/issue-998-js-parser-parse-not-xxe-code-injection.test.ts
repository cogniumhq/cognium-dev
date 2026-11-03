/**
 * cognium-dev#998 — `parser.parse(...)` in JS/TS is a tree-sitter / lockfile /
 * text parser, not a JAXP XML parser (XXE) or cron-utils `CronParser`
 * (code_injection). The Java entries matched by receiver name (`parser` →
 * SAXParser, `…parser` → CronParser) in every language; they are now Java-only.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sinkTypes = async (code: string, file: string, lang: 'typescript' | 'java') => {
  const r = await analyze(code, file, lang);
  return r.taint.sinks.filter(s => s.method === 'parse').map(s => s.type);
};

describe('#998 — JS/TS parser.parse is not an XXE or code_injection sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('tree-sitter / lockfile parser.parse in TS has no xxe or code_injection sink', async () => {
    const code = `
import * as fs from 'fs';
export function load(parser: any, abs: string) {
  return parser.parse(fs.readFileSync(abs, 'utf-8'));
}
export function local(abs: string) {
  const parser = new Parser();
  return parser.parse(fs.readFileSync(abs, 'utf-8'));
}
`;
    const types = await sinkTypes(code, 'bom.ts', 'typescript');
    expect(types).not.toContain('xxe');
    expect(types).not.toContain('code_injection');
  });

  it('Java SAXParser.parse and DocumentBuilder.parse are still XXE sinks', async () => {
    const code = `
import javax.xml.parsers.*;
import java.io.InputStream;
public class X {
  void a(SAXParser parser, InputStream in) throws Exception { parser.parse(in, null); }
  void b(DocumentBuilder builder, InputStream in) throws Exception { builder.parse(in); }
}
`;
    const types = await sinkTypes(code, 'X.java', 'java');
    expect(types).toContain('xxe');
  });
});
