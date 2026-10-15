/**
 * cognium-dev#293 (Go allow-list cell): a host allow-list lookup written as
 * one `||` disjunct of a rejecting guard was not credited.
 *
 *     u, err := url.Parse(r.URL.Query().Get("next"))
 *     if err != nil || !permittedHosts[u.Host] { http.Error(...); return }
 *     http.Redirect(w, r, u.String(), http.StatusFound)
 *
 * The guard now accepts the negated lookup as any `||` disjunct, with a
 * selector key (`u.Host`), and the credit ends at the enclosing function
 * instead of running to the end of the file.
 *
 * SAST regression fixture — the handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const code = `package main

import (
	"log"
	"net/http"
	"net/url"
)

var permittedHosts = map[string]bool{"help.example.net": true}

func leadingErr(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("next"))
	if err != nil || !permittedHosts[u.Host] {
		http.Error(w, "blocked", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func trailingErr(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("next"))
	if !permittedHosts[u.Host] || err != nil {
		http.Error(w, "blocked", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func conjunction(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("next"))
	if err != nil && !permittedHosts[u.Host] {
		http.Error(w, "blocked", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func fallsThrough(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("next"))
	if err != nil || !permittedHosts[u.Host] {
		log.Printf("unexpected host")
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func unguardedAfter(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}
`;

const lines = code.split('\n');
const sinkOf = (fn: string) => {
  const start = lines.findIndex(l => l.startsWith(`func ${fn}(`));
  return lines.findIndex((l, i) => i > start && l.includes('http.Redirect')) + 1;
};

describe('#293 Go allow-list guard as an || disjunct', () => {
  let sinks: number[] = [];
  beforeAll(async () => {
    await initAnalyzer();
    const r = await analyze(code, 'redirects.go', 'go');
    sinks = (r.taint.flows ?? []).filter(f => f.sink_type === 'open_redirect' && !f.sanitized).map(f => f.sink_line);
  });

  it('clears open_redirect when the negated lookup leads or trails an || guard that returns', () => {
    expect(sinks).not.toContain(sinkOf('leadingErr'));
    expect(sinks).not.toContain(sinkOf('trailingErr'));
  });

  it('still fires for an && guard and for a guard that falls through', () => {
    expect(sinks).toContain(sinkOf('conjunction'));
    expect(sinks).toContain(sinkOf('fallsThrough'));
  });

  it('does not credit a later function in the same file', () => {
    expect(sinks).toContain(sinkOf('unguardedAfter'));
  });
});
