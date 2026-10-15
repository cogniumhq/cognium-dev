/**
 * cognium-dev#348 (Go half) and #293 (Go escaper cell): `strings.NewReplacer`
 * sanitizer credit, argument-aware.
 *
 *   - log_injection is cleared only when both "\r" and "\n" are replaced by
 *     strings without CR/LF;
 *   - xss is cleared only when both "<" and ">" are replaced by strings
 *     without them.
 *
 * Recognised inline (`strings.NewReplacer(...).Replace(x)`) and through a
 * package-level or local variable bound to the replacer. A raw value beside
 * a replaced one, in the same statement or the same call, still fires.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { findGoStringsReplacerSanitizers, goReplacerCoverage } from '../../src/analysis/go-strings-replacer.js';

const logCode = `package main

import (
	"log"
	"net/http"
	"strings"
)

var oneLine = strings.NewReplacer("\\r", "", "\\n", "")
var visibleBreaks = strings.NewReplacer("\\r", "\\\\r", "\\n", "\\\\n")
var keepsNewline = strings.NewReplacer("\\r", "", "\\n", "\\n")

func archiveItem(w http.ResponseWriter, r *http.Request) {
	operator := r.Header.Get("X-Operator")
	item := r.FormValue("item")
	safeOperator := oneLine.Replace(operator)
	safeItem := oneLine.Replace(item)
	log.Printf("archive by=%s id=%s", safeOperator, safeItem)
}

func signIn(w http.ResponseWriter, r *http.Request) {
	login := strings.NewReplacer("\\r", " ", "\\n", " ").Replace(r.FormValue("login"))
	log.Printf("sign-in user=%s", login)
}

func escapedBreaks(w http.ResponseWriter, r *http.Request) {
	login := visibleBreaks.Replace(r.FormValue("login"))
	log.Printf("sign-in user=%s", login)
}

func atTheCall(w http.ResponseWriter, r *http.Request) {
	log.Printf("sign-in user=%s", oneLine.Replace(r.FormValue("login")))
}

func spacesOnly(w http.ResponseWriter, r *http.Request) {
	login := strings.NewReplacer(" ", "_").Replace(r.FormValue("login"))
	log.Printf("sign-in user=%s", login)
}

func lfKept(w http.ResponseWriter, r *http.Request) {
	login := keepsNewline.Replace(r.FormValue("login"))
	log.Printf("sign-in user=%s", login)
}

func rawBeside(w http.ResponseWriter, r *http.Request) {
	login := oneLine.Replace(r.FormValue("login"))
	team := r.FormValue("team")
	log.Printf("sign-in user=%s grp=%s", login, team)
}

func rawBesideAtTheCall(w http.ResponseWriter, r *http.Request) {
	team := r.FormValue("team")
	log.Printf("sign-in user=%s grp=%s", oneLine.Replace(r.FormValue("login")), team)
}
`;

const xssCode = `package main

import (
	"net/http"
	"strings"
)

var markup = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", \`"\`, "&quot;")

func shipment(w http.ResponseWriter, r *http.Request) {
	units := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(r.FormValue("units"))
	doc := "<shipment><units>" + units + "</units></shipment>"
	w.Write([]byte(doc))
}

func comment(w http.ResponseWriter, r *http.Request) {
	text := markup.Replace(r.FormValue("text"))
	w.Write([]byte("<p>" + text + "</p>"))
}

func halfEscaped(w http.ResponseWriter, r *http.Request) {
	text := strings.NewReplacer("<", "&lt;").Replace(r.FormValue("text"))
	w.Write([]byte("<p>" + text + "</p>"))
}

func unescaped(w http.ResponseWriter, r *http.Request) {
	text := r.FormValue("text")
	w.Write([]byte("<p>" + text + "</p>"))
}
`;

type Flow = { sink_type: string; source_line: number; sink_line: number };

async function flowsOf(code: string, type: string): Promise<Flow[]> {
  const r = await analyze(code, 'handlers.go', 'go');
  return (r.taint.flows ?? []).filter(f => f.sink_type === type && !f.sanitized);
}

function sinkIn(code: string, fn: string, sinkText: string): number {
  const lines = code.split('\n');
  const start = lines.findIndex(l => l.startsWith(`func ${fn}(`));
  return lines.findIndex((l, i) => i > start && l.includes(sinkText)) + 1;
}

describe('#348 Go strings.NewReplacer CR/LF strip', () => {
  let flows: Flow[] = [];
  beforeAll(async () => {
    await initAnalyzer();
    flows = await flowsOf(logCode, 'log_injection')
  });
  const firesIn = (fn: string) => flows.some(f => f.sink_line === sinkIn(logCode, fn, 'log.Printf'));

  it('clears log_injection for a package-level replacer, an inline one, and one at the call', () => {
    expect(firesIn('archiveItem')).toBe(false);
    expect(firesIn('signIn')).toBe(false);
    expect(firesIn('escapedBreaks')).toBe(false);
    expect(firesIn('atTheCall')).toBe(false);
  });

  it('still fires when the replacer leaves CR or LF in place', () => {
    expect(firesIn('spacesOnly')).toBe(true);
    expect(firesIn('lfKept')).toBe(true);
  });

  it('still fires for a raw value beside a replaced one, from the raw source only', () => {
    for (const fn of ['rawBeside', 'rawBesideAtTheCall']) {
      const sink = sinkIn(logCode, fn, 'log.Printf');
      const team = sinkIn(logCode, fn, 'r.FormValue("team")');
      const hits = flows.filter(f => f.sink_line === sink);
      expect(hits.some(f => f.source_line === team)).toBe(true);
    }
    const sink = sinkIn(logCode, 'rawBeside', 'log.Printf');
    const login = sinkIn(logCode, 'rawBeside', 'r.FormValue("login")');
    expect(flows.some(f => f.sink_line === sink && f.source_line === login)).toBe(false);
  });
});

describe('#293 Go strings.NewReplacer entity escaping', () => {
  let flows: Flow[] = [];
  beforeAll(async () => {
    await initAnalyzer();
    flows = await flowsOf(xssCode, 'xss');
  });
  const firesIn = (fn: string) => flows.some(f => f.sink_line === sinkIn(xssCode, fn, 'w.Write'));

  it('clears xss for an inline and a package-level entity escaper', () => {
    expect(firesIn('shipment')).toBe(false);
    expect(firesIn('comment')).toBe(false);
  });

  it('still fires when only < is escaped, and with no escaping', () => {
    expect(firesIn('halfEscaped')).toBe(true);
    expect(firesIn('unescaped')).toBe(true);
  });
});

describe('go-strings-replacer helpers', () => {
  it('coverage needs both characters, each replaced safely', () => {
    expect(goReplacerCoverage([['\r', ''], ['\n', '']])).toEqual(['log_injection']);
    expect(goReplacerCoverage([['\n', '']])).toEqual([]);
    expect(goReplacerCoverage([['\r', ''], ['\n', '\r\n']])).toEqual([]);
    expect(goReplacerCoverage([['<', '&lt;'], ['>', '&gt;']])).toEqual(['xss']);
    expect(goReplacerCoverage([['<', '&lt;'], ['>', '>']])).toEqual([]);
  });

  it('ignores a replacer built from non-literal operands', () => {
    expect(findGoStringsReplacerSanitizers('x := strings.NewReplacer(a, "", "\\n", "").Replace(v)')).toEqual([]);
  });

  it('a name rebound to a weaker replacer loses the credit', () => {
    const code = [
      'r := strings.NewReplacer("\\r", "", "\\n", "")',
      'r = strings.NewReplacer(" ", "")',
      'v := r.Replace(x)',
    ].join('\n');
    expect(findGoStringsReplacerSanitizers(code)).toEqual([]);
  });
});
