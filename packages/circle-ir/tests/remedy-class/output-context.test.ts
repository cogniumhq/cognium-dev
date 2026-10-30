import { describe, it, expect } from 'vitest';
import {
  htmlContextAt, markupBefore, javaStringLiterals,
  analyzeProject, pathSetDiff, remedyClassOf, loadSafeConstructTable,
} from '../../src/index.js';

describe('htmlContextAt', () => {
  it('element content, attributes, URLs, scripts', () => {
    expect(htmlContextAt('')).toBe('html-content');
    expect(htmlContextAt('<p>Results for ')).toBe('html-content');
    expect(htmlContextAt('<input name="q" value="')).toBe('html-attribute-quoted');
    expect(htmlContextAt("<input value='")).toBe('html-attribute-quoted');
    expect(htmlContextAt('<input value=')).toBe('html-attribute-unquoted');
    expect(htmlContextAt('<a href="')).toBe('url');
    expect(htmlContextAt('<img class="x" src=')).toBe('url');
    expect(htmlContextAt('<script>var q = "')).toBe('js-string');
    expect(htmlContextAt("<script>var q = 'a\\'b")).toBe('js-string');
    expect(htmlContextAt('<script>var q = 1 + ')).toBe('js');
    expect(htmlContextAt('<script>var a="x";</script><p>')).toBe('html-content');
    expect(htmlContextAt('<div class="a" id=b>')).toBe('html-content');
    expect(htmlContextAt('</p><b>')).toBe('html-content');
  });

  it('event handlers, style and tag internals are unknown', () => {
    expect(htmlContextAt('<div onclick="go(\'')).toBe('unknown');
    expect(htmlContextAt('<div style="color:')).toBe('unknown');
    expect(htmlContextAt('<div onclick=')).toBe('unknown');
    expect(htmlContextAt('<div ')).toBe('unknown');
  });
});

describe('markupBefore and javaStringLiterals', () => {
  it('reads the literals written before the first tainted name', () => {
    const q = new Set(['q']);
    expect(markupBefore('"<p>" + Encode.forHtml(q) + "</p>"', q)).toBe('<p>');
    expect(markupBefore('"<a href=\\"" + base + "/" + q', q)).toBe('<a href="/');
    expect(markupBefore('"q is here" + other', q)).toBeNull();
    expect(markupBefore('"x" + obj.q', q)).toBeNull();
  });

  it('unescapes Java string literals', () => {
    expect(javaStringLiterals('"a\\"b" + "\\n\\t\\u0041\\\\"')).toEqual(['a"b', '\n\tA\\']);
  });
});

/* Synthetic servlet and table written for these tests. */
const TABLE = `format: safe-construct-table@0.1
check-set: example/java
cwe: 79
cwe-list-version: '4.20'
language: java
version: 1.0.0
settles: signal
sources:
  doc:
    kind: vendor-docs
    publisher: Example
    title: Example encoder notes
    url: https://example.org/encoder
    fetched: '2026-10-29'
    quote: Example.
sinks:
  - id: writer
    call: { type: java.io.PrintWriter, methods: [print, println, write], arg: 0 }
constructs:
  - id: S79-1
    class: safe
    remedy-class: contextual-encoding
    applies-to: [writer]
    context: html-content
    match: { call: { type: org.owasp.encoder.Encode, static: true, methods: [forHtml], arg: 0 }, arg-is: tainted, role: sanitizer }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: W79-1
    class: weak
    remedy-class: contextual-encoding
    applies-to: [writer]
    context: js-string
    match: { call: { type: org.owasp.encoder.Encode, static: true, methods: [forHtml], arg: 0 }, role: sanitizer }
    level: SHOULD
    basis: own
    sources: [doc]
  - id: S79-9
    class: safe
    remedy-class: contextual-encoding
    applies-to: [writer]
    match: { call: { type: org.owasp.encoder.Encode, static: true, methods: [forHtml], arg: 0 }, role: sanitizer }
    level: SHOULD
    basis: cited
    sources: [doc]
`;
const FILE = 'src/main/java/demo/Page.java';
const page = (body: string): string => `package demo;
import java.io.*;
import javax.servlet.http.*;
public class Page extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String q = req.getParameter("q");
    PrintWriter out = resp.getWriter();
${body}
  }
}`;
const BASE = page(`    out.print("<p>" + q + "</p>");`);

async function observe(after: string, outputContext?: boolean) {
  const b = await analyzeProject([{ code: BASE, filePath: FILE, language: 'java' }]);
  const a = await analyzeProject([{ code: after, filePath: FILE, language: 'java' }]);
  const d = pathSetDiff(b, a, { cwe: 79 });
  return remedyClassOf(d, b, a, loadSafeConstructTable(TABLE), outputContext === undefined ? {} : { outputContext });
}

describe('remedyClassOf — outputContext', () => {
  it('is off by default: no context fields, every row that holds is listed', async () => {
    const r = await observe(page(`    out.print("<p>" + org.owasp.encoder.Encode.forHtml(q) + "</p>");`));
    expect(r.sinks.length).toBeGreaterThan(0);
    const s = r.sinks[0];
    expect(s.sink.outputContext).toBeUndefined();
    expect(s.contextExcludedRows).toBeUndefined();
    expect(s.rows.map(x => x.id)).toEqual(['S79-1', 'W79-1', 'S79-9']);
    expect(JSON.stringify(await observe(page(`    out.print("<p>" + org.owasp.encoder.Encode.forHtml(q) + "</p>");`), false))).toBe(JSON.stringify(r));
  });

  it('element content: the content row and the row without a context', async () => {
    const r = await observe(page(`    out.print("<p>" + org.owasp.encoder.Encode.forHtml(q) + "</p>");`), true);
    const s = r.sinks[0];
    expect(s.sink.outputContext).toBe('html-content');
    expect(s.rows.map(x => x.id)).toEqual(['S79-1', 'S79-9']);
    expect(s.contextExcludedRows).toEqual([{ id: 'W79-1', context: 'js-string' }]);
    expect(s.match).toBe('multiple');
  });

  it('a script string, written across two calls: the JS row', async () => {
    const r = await observe(page(`    out.print("<script>var q = \\"");
    out.print(org.owasp.encoder.Encode.forHtml(q));
    out.print("\\";</script>");`), true);
    const s = r.sinks[0];
    expect(s.sink.outputContext).toBe('js-string');
    expect(s.rows.map(x => x.id)).toEqual(['W79-1', 'S79-9']);
    expect(s.contextExcludedRows).toEqual([{ id: 'S79-1', context: 'html-content' }]);
  });

  it('two writes in different contexts: unknown, nothing excluded', async () => {
    const r = await observe(page(`    out.print("<p>" + org.owasp.encoder.Encode.forHtml(q) + "</p>");
    out.print("<script>var q = \\"" + org.owasp.encoder.Encode.forHtml(q) + "\\";</script>");`), true);
    const s = r.sinks[0];
    expect(s.sink.outputContext).toBe('unknown');
    expect(s.contextExcludedRows).toEqual([]);
    expect(s.rows.map(x => x.id)).toEqual(['S79-1', 'W79-1', 'S79-9']);
  });
});
