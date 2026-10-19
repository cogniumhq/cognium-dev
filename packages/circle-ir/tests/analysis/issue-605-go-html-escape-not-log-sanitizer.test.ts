/**
 * cognium-dev#605 / #562 (Go sk66): `html.EscapeString` and
 * `template.HTMLEscapeString` must not suppress `log_injection` — HTML escaping
 * does not strip CR/LF. `template.JSEscapeString` may still credit log injection.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const logInjectionSinkLines = async (code: string, file: string) => {
  const r = await analyze(code, file, 'go');
  return [
    ...new Set(
      (r.taint.flows ?? [])
        .filter((f) => f.sink_type === 'log_injection')
        .map((f) => f.sink_line),
    ),
  ].sort((a, b) => a - b);
};

const auditHandler = `package audit

import (
	"fmt"
	"html"
	"log"
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	log.Printf("user=%s", html.EscapeString(u))
	fmt.Fprint(w, html.EscapeString(u))
}
`;

const templateHtmlHandler = `package audit

import (
	"html/template"
	"log"
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	log.Printf("user=%s", template.HTMLEscapeString(u))
}
`;

const jsEscapeHandler = `package audit

import (
	"html/template"
	"log"
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	log.Printf("user=%s", template.JSEscapeString(u))
}
`;

describe('#605 Go html/template escape is not a log_injection sanitizer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('html.EscapeString before log.Printf reports log_injection (sk66 TP)', async () => {
    const lines = await logInjectionSinkLines(auditHandler, 'audit_handler.go');
    expect(lines).toContain(12);
  });

  it('template.HTMLEscapeString before log.Printf reports log_injection', async () => {
    const lines = await logInjectionSinkLines(templateHtmlHandler, 'template_html_handler.go');
    expect(lines.length).toBeGreaterThan(0);
  });

  it('template.JSEscapeString may suppress log_injection (control sanitizer)', async () => {
    const lines = await logInjectionSinkLines(jsEscapeHandler, 'js_escape_handler.go');
    expect(lines).toHaveLength(0);
  });
});
