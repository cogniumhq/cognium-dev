/**
 * cognium-dev#605 / #562 (minimal slice): Go `html.EscapeString` and
 * `template.HTMLEscapeString` escape HTML metacharacters, not CR/LF, so they are
 * not log-injection sanitizers. They keep their xss / open_redirect /
 * external_taint_escape credit.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function flowLines(code: string, file: string, type: string) {
  const r = await analyze(code, file, 'go');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort((a, b) => a - b);
}

const handler = `package audit

import (
	"fmt"
	"html"
	"log"
	"net/http"
)

func Record(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	log.Printf("actor=%s", html.EscapeString(actor))
	fmt.Fprint(w, html.EscapeString(actor))
}
`;

const tmpl = `package audit

import (
	"fmt"
	"log"
	"net/http"
	"text/template"
)

func Note(w http.ResponseWriter, r *http.Request) {
	who := r.URL.Query().Get("who")
	log.Printf("who=%s", template.HTMLEscapeString(who))
	fmt.Fprint(w, template.HTMLEscapeString(who))
}
`;

const logBare = `package audit

import (
	"log"
	"net/http"
)

func Bare(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	log.Printf("actor=%s", actor)
}
`;

const replacer = `package audit

import (
	"log"
	"net/http"
	"strings"
)

func Clean(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	cr := strings.NewReplacer("\\r", "", "\\n", "")
	log.Printf("actor=%s", cr.Replace(actor))
}
`;

describe('cognium-dev#605 Go html escapers are not log-injection sanitizers', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('html.EscapeString into log.Printf still reports log_injection', async () => {
    expect(await flowLines(handler, 'audit_handler.go', 'log_injection')).toEqual([12]);
  });

  it('html.EscapeString keeps its xss credit at the response writer', async () => {
    expect(await flowLines(handler, 'audit_handler.go', 'xss')).toEqual([]);
  });

  it('template.HTMLEscapeString into log.Printf still reports log_injection, xss stays credited', async () => {
    expect(await flowLines(tmpl, 'note_handler.go', 'log_injection')).toEqual([12]);
    expect(await flowLines(tmpl, 'note_handler.go', 'xss')).toEqual([]);
  });

  it('control: an unescaped value into log.Printf reports log_injection', async () => {
    expect(await flowLines(logBare, 'bare_handler.go', 'log_injection')).toEqual([10]);
  });

  it('other Go rows are unchanged: a CR+LF NewReplacer keeps its log credit', async () => {
    expect(await flowLines(replacer, 'clean_handler.go', 'log_injection')).toEqual([]);
  });
});
