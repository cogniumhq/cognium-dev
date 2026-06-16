/**
 * Repro for cognium-dev#88 — Polyglot/templates gaps:
 *  - #88.1 .jsx not recognized (CLI LANG_MAP gap, covered in cli tests/glob.test.ts)
 *  - #88.2 .tsx JSX partial-parse (requires shipping tree-sitter-tsx.wasm — deferred)
 *  - #88.3 Go `text/template.Execute` XSS sink unmodeled
 *
 * This file focuses on #88.3. The text/template package renders user data
 * *without* HTML-escaping (unlike html/template which auto-escapes). Both
 * `Execute` and `ExecuteTemplate` on a `*template.Template` are XSS sinks
 * when the second/third argument flows from a user source.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#88.3 — Go text/template XSS sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const xssFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
    (flows ?? []).filter((f) => f.sink_type === 'xss').length;

  it('chained: template.Must(template.New("p").Parse(src)).Execute(w, r.FormValue) — FIRES', async () => {
    const code = `package main

import (
\t"net/http"
\t"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
\ttemplate.Must(template.New("p").Parse("<p>{{.}}</p>")).Execute(w, r.FormValue("name"))
}
`;
    const result = await analyze(code, 'chained.go', 'go');
    expect(xssFlows(result.taint.flows)).toBeGreaterThanOrEqual(1);
  });

  it('direct: tmpl.Execute(w, r.FormValue) — FIRES (receiver `tmpl` matches Template class)', async () => {
    const code = `package main

import (
\t"net/http"
\t"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
\ttmpl := template.Must(template.New("p").Parse("<p>{{.}}</p>"))
\tname := r.FormValue("name")
\ttmpl.Execute(w, name)
}
`;
    const result = await analyze(code, 'tmpl.go', 'go');
    expect(xssFlows(result.taint.flows)).toBeGreaterThanOrEqual(1);
  });

  it('ExecuteTemplate: tmpl.ExecuteTemplate(w, "name", r.FormValue) — FIRES', async () => {
    const code = `package main

import (
\t"net/http"
\t"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
\ttmpl := template.Must(template.ParseFiles("page.tmpl"))
\tdata := r.FormValue("data")
\ttmpl.ExecuteTemplate(w, "page", data)
}
`;
    const result = await analyze(code, 'exectmpl.go', 'go');
    expect(xssFlows(result.taint.flows)).toBeGreaterThanOrEqual(1);
  });
});
