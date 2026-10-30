import { describe, it, expect } from 'vitest';
import {
  analyzeProject, deriveTemplateFacts, templateEngineOf, expressionNames, handedNames,
  pathSetDiff, remedyClassOf, loadSafeConstructTable,
} from '../../src/index.js';
import type { TemplateFact } from '../../src/index.js';

/* Synthetic controller, views and table written for these tests. */

describe('expressionNames', () => {
  it('reads root names, skipping members, functions, prefixes and keywords', () => {
    expect(expressionNames('${q}')).toEqual(['q']);
    expect(expressionNames('${user.name} and ${fn:escapeXml(raw)}')).toEqual(['raw', 'user']);
    expect(expressionNames('@{/x(id=${id})}')).toEqual(['id']);
    expect(expressionNames("${empty list or x eq 'a'}")).toEqual(['list', 'x']);
    expect(expressionNames('*{field}')).toEqual(['field']);
    expect(expressionNames('no expression')).toEqual([]);
  });
});

describe('templateEngineOf', () => {
  it('JSP by extension, Thymeleaf by th: attributes, nothing for plain HTML', () => {
    expect(templateEngineOf('a/b.jsp', '')).toBe('jsp');
    expect(templateEngineOf('a/b.tagx', '')).toBe('jsp');
    expect(templateEngineOf('t/x.html', '<p th:text="${a}">')).toBe('thymeleaf');
    expect(templateEngineOf('t/x.html', '<p data-th-text="${a}">')).toBe('thymeleaf');
    expect(templateEngineOf('t/x.html', '<p>${a}</p>')).toBeNull();
    expect(templateEngineOf('t/x.txt', 'th:text')).toBeNull();
  });
});

describe('deriveTemplateFacts', () => {
  it('JSP: custom tags with their attributes, EL in text and in plain attributes', async () => {
    const jsp = `<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<p>Results for <c:out value="\${q}" escapeXml="false"/></p>
<p>raw \${q.name}</p>
<a href="\${link}">x</a>`;
    const facts = await deriveTemplateFacts(jsp, 'v/search.jsp');
    expect(facts).toEqual([
      { file: 'v/search.jsp', engine: 'jsp', names: ['q'], line: 2, construct: 'c:out', element: 'c:out', attributes: { value: '${q}', escapeXml: 'false' }, expression: '${q}' },
      { file: 'v/search.jsp', engine: 'jsp', names: ['q'], line: 3, construct: '${}', attributes: {}, expression: '${q.name}' },
      { file: 'v/search.jsp', engine: 'jsp', names: ['link'], line: 4, construct: '${}', element: 'a', inAttribute: 'href', attributes: {}, expression: '${link}' },
    ]);
  });

  it('Thymeleaf: th: and data-th- attributes and inline expressions', async () => {
    const html = `<html xmlns:th="http://www.thymeleaf.org">
<body><p th:utext="\${q}" class="r">query</p><span data-th-text="\${n}">n</span>
<div>[[\${a}]] and [(\${b})]</div></body></html>`;
    const facts = await deriveTemplateFacts(html, 't/search.html');
    expect(facts.map(f => [f.line, f.construct, f.names.join(), f.element ?? null])).toEqual([
      [2, 'th:text', 'n', 'span'],
      [2, 'th:utext', 'q', 'p'],
      [3, '[(…)]', 'b', null],
      [3, '[[…]]', 'a', null],
    ]);
    expect(facts.find(f => f.construct === 'th:utext')?.attributes).toEqual({ class: 'r' });
  });

  it('nothing for a file no supported engine reads', async () => {
    expect(await deriveTemplateFacts('<p>${a}</p>', 'x.html')).toEqual([]);
  });
});

const CTRL = 'src/main/java/demo/SearchController.java';
const CONTROLLER = `package demo;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
@org.springframework.stereotype.Controller
public class SearchController {
  @GetMapping("/search")
  public String search(@RequestParam String q, Model model) {
    model.addAttribute("q", q);
    return "search";
  }
}`;
const VIEW = 'src/main/resources/templates/search.html';
const view = (attr: string): string => `<html xmlns:th="http://www.thymeleaf.org"><body><p ${attr}="\${q}">q</p></body></html>`;

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
    title: Example template notes
    url: https://example.org/templates
    fetched: '2026-10-29'
    quote: Example.
sinks:
  - id: utext
    template: { engine: thymeleaf, construct: "th:utext" }
constructs:
  - id: S79-1
    class: safe
    remedy-class: auto-escaping-template
    applies-to: [utext]
    match: { template: { engine: thymeleaf, construct: "th:text" }, role: sink-replacement }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: W79-1
    class: weak
    remedy-class: auto-escaping-template
    applies-to: [utext]
    match: { template: { engine: thymeleaf, construct: "th:utext" }, role: sink-replacement }
    level: SHOULD
    basis: own
    sources: [doc]
`;

async function pin(viewHtml: string) {
  const project = await analyzeProject([{ code: CONTROLLER, filePath: CTRL, language: 'java' }]);
  const templates: Record<string, TemplateFact[]> = { [VIEW]: await deriveTemplateFacts(viewHtml, VIEW) };
  return { project, templates };
}

describe('template hand-offs', () => {
  it('handedNames reads string-literal identifiers from a call', () => {
    expect(handedNames(undefined)).toEqual([]);
    expect(handedNames({ method_name: 'addAttribute', receiver: 'model', arguments: [
      { position: 0, expression: '"q"', literal: 'q' }, { position: 1, expression: 'q', variable: 'q' },
    ], location: { line: 1, column: 0 } })).toEqual(['q']);
  });

  it('a fix made in the view: the code path is unchanged, the sink carries the template, templateChanged', async () => {
    const b = await pin(view('th:utext'));
    const a = await pin(view('th:text'));
    const d = pathSetDiff(b.project, a.project, { cwe: 79, templates: { before: b.templates, after: a.templates } });
    expect(d.entries.length).toBeGreaterThan(0);
    const e = d.entries[0];
    expect(e.change).toBe('unchanged');
    expect(e.templateChanged).toBe(true);
    expect(e.before?.sink.templates?.[0]).toMatchObject({ file: VIEW, engine: 'thymeleaf', construct: 'th:utext', names: ['q'] });
    expect(e.after?.sink.templates?.[0].construct).toBe('th:text');
    // without template facts nothing is linked
    const plain = pathSetDiff(b.project, a.project, { cwe: 79 });
    expect(plain.entries[0].templateChanged).toBeUndefined();
    expect(plain.entries[0].after?.sink.templates).toBeUndefined();
  });

  it('the matcher labels the sink by the template and matches the template row', async () => {
    const b = await pin(view('th:utext'));
    const a = await pin(view('th:text'));
    const templates = { before: b.templates, after: a.templates };
    const d = pathSetDiff(b.project, a.project, { cwe: 79, templates });
    const r = remedyClassOf(d, b.project, a.project, loadSafeConstructTable(TABLE), { templates });
    expect(r.sinks).toHaveLength(1);
    expect(r.sinks[0]).toMatchObject({
      change: 'unchanged', templateChanged: true, match: 'S79-1', class: 'safe',
      sink: { tableSink: 'utext', tableSinkMatch: 'template', via: 'template' },
    });
    expect(r.sinks[0].rows[0].steps[0]).toMatchObject({ holds: true, typeMatch: 'template', at: { file: VIEW } });
  });

  it('an unchanged view is not observed by default; the weak row when it is', async () => {
    const b = await pin(view('th:utext'));
    const templates = { before: b.templates, after: b.templates };
    const d = pathSetDiff(b.project, b.project, { cwe: 79, templates });
    expect(d.entries.every(e => !e.templateChanged)).toBe(true);
    expect(remedyClassOf(d, b.project, b.project, loadSafeConstructTable(TABLE), { templates }).sinks).toEqual([]);
    const all = remedyClassOf(d, b.project, b.project, loadSafeConstructTable(TABLE), { templates, scope: 'all' });
    expect(all.sinks[0]).toMatchObject({ match: 'W79-1', class: 'weak' });
  });

  it('without template facts the template rows abstain or the sink is unlisted, as before', async () => {
    const b = await pin(view('th:utext'));
    const a = await pin(view('th:text'));
    const d = pathSetDiff(b.project, a.project, { cwe: 79 });
    const r = remedyClassOf(d, b.project, a.project, loadSafeConstructTable(TABLE), { scope: 'all' });
    expect(r.sinks[0]).toMatchObject({ match: 'unrecognized', reason: 'sink-not-in-table' });
  });
});
