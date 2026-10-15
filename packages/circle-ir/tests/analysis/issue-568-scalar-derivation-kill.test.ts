/**
 * #568 (parent #349) — an int or bool derived from tainted text by a measure
 * or a test carries no string payload.
 *
 * Before: `n := len(re.FindAllString(text, -1))` then `fmt.Fprintf(w, "%d", n)`
 * reported xss, and JS `const total = (s.match(RE) || []).length` then
 * `res.json({ total })` reported external_taint_escape. The value at the sink
 * is a count or a boolean.
 *
 * The rule is by value type, not credit for the regex call: a string-returning
 * matcher (`re.FindString(text)`, `s.match(re)`) still carries taint.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { isScalarDerivation } from '../../src/analysis/scalar-derivation.js';

const goHandler = (...body: string[]) =>
  [
    'package main',
    '',
    'import (',
    '\t"fmt"',
    '\t"net/http"',
    '\t"regexp"',
    '\t"strings"',
    ')',
    '',
    'var vowelRe = regexp.MustCompile(`[aeiou]`)',
    '',
    'func tally(w http.ResponseWriter, r *http.Request) {',
    '\tword := r.URL.Query().Get("word")',
    ...body.map((l) => '\t' + l),
    '}',
  ].join('\n');

const jsHandler = (...body: string[]) =>
  [
    "const express = require('express');",
    'const app = express();',
    'const VOWELS = /[aeiou]/g;',
    "app.get('/tally', (req, res) => {",
    "  const word = String(req.query.word || '');",
    ...body.map((l) => '  ' + l),
    '});',
  ].join('\n');

const sinkTypes = async (code: string, file: string, lang: 'go' | 'javascript') => {
  const r = await analyze(code, file, lang);
  return (r.taint.flows ?? []).map((f) => f.sink_type);
};

describe('#568 — taint does not flow into an int/bool measure of a value', () => {
  beforeAll(async () => { await initAnalyzer(); });

  describe('Go', () => {
    it.each([
      ['len of a constant-regex match list', 'n := len(vowelRe.FindAllString(word, -1))', 'fmt.Fprintf(w, "%d", n)'],
      ['MatchString result', 'ok := vowelRe.MatchString(word)', 'fmt.Fprintf(w, "%v", ok)'],
      ['negated MatchString', 'bad := !vowelRe.MatchString(word)', 'fmt.Fprintf(w, "%v", bad)'],
      ['strings.Count', 'c := strings.Count(word, "a")', 'fmt.Fprintf(w, "%d", c)'],
    ])('%s is clean', async (_n, ...body) => {
      const t = await sinkTypes(goHandler(...body), 'tally.go', 'go');
      expect(t).not.toContain('xss');
      expect(t).not.toContain('external_taint_escape');
    });

    // The Fprint* pattern detector defers to taint propagation on a line the
    // taint matcher already resolved as an xss sink.
    const fprintPattern = async (...body: string[]) => {
      const r = await analyze(goHandler(...body), 'tally.go', 'go');
      return r.findings.filter((f) => f.rule_id === 'xss' && /^Reflected XSS: fmt\.Fprint/.test(f.message));
    };

    it('the Fprint* pattern finding does not fire on a printed count', async () => {
      expect(await fprintPattern('n := len(vowelRe.FindAllString(word, -1))', 'fmt.Fprintf(w, "%d", n)')).toHaveLength(0);
    });

    // A request read the taint engine has no source for still reports
    // through the pattern detector; only all-scalar arguments are skipped.
    it.each([
      ['the URL path', 'fmt.Fprintf(w, "<p>%s</p>", r.URL.Path)'],
      ['a path value', 'id := r.PathValue("id")', 'fmt.Fprintln(w, "<b>"+id+"</b>")'],
      ['a count beside the raw query', 'n := len(word)', 'fmt.Fprintf(w, "%d %s", n, r.URL.RawQuery)'],
    ])('the Fprint* pattern still fires on %s', async (_n, ...body) => {
      expect(await fprintPattern(...body)).toHaveLength(1);
    });

    it('a printed word still reports xss from taint propagation', async () => {
      const r = await analyze(goHandler('fmt.Fprintf(w, "<b>%s</b>", word)'), 'tally.go', 'go');
      expect((r.taint.flows ?? []).some((f) => f.sink_type === 'xss' && f.sink_line === 14)).toBe(true);
    });

    it.each([
      ['a string-returning matcher', 'w.Write([]byte(vowelRe.FindString(word)))'],
      ['FindString via a local', 'm := vowelRe.FindString(word)', 'fmt.Fprintf(w, "%s", m)'],
      ['the text beside its length', 'n := len(word)', 'fmt.Fprintf(w, "%s %d", word, n)'],
      ['an expression that is more than a measure', 'm := word[:len(word)]', 'fmt.Fprintf(w, "%s", m)'],
    ])('%s still reports xss', async (_n, ...body) => {
      expect(await sinkTypes(goHandler(...body), 'tally.go', 'go')).toContain('xss');
    });
  });

  describe('JavaScript', () => {
    it.each([
      ['a match count', 'const total = (word.match(VOWELS) || []).length;', 'res.json({ total: total });'],
      ['a length', 'const size = word.length;', 'res.json({ size: size });'],
      ['a regex test', 'const ok = /^[a-z]+$/.test(word);', 'res.json({ ok: ok });'],
      ['an includes test', "const hasA = word.includes('a');", 'res.json({ hasA });'],
    ])('%s is clean', async (_n, ...body) => {
      const t = await sinkTypes(jsHandler(...body), 'tally.js', 'javascript');
      expect(t).not.toContain('external_taint_escape');
      expect(t).not.toContain('xss');
    });

    it.each([
      ['the match array', 'const hits = word.match(VOWELS);', 'res.send(hits[0]);'],
      ['a ternary on the length', "const out = word.length > 3 ? word : '';", 'res.send(out);'],
      ['the text beside its length', 'const size = word.length;', "res.send(word + ' ' + size);"],
      ['a search method returning markup', "const html = { search: (s) => '<li>' + s }.search(word);", 'res.send(html);'],
    ])('%s still reports xss', async (_n, ...body) => {
      expect(await sinkTypes(jsHandler(...body), 'tally.js', 'javascript')).toContain('xss');
    });
  });

  describe('isScalarDerivation', () => {
    it.each([
      ['len(re.FindAllString(text, -1))', 'go'],
      ['re.MatchString(text)', 'go'],
      ['!re.MatchString(text)', 'go'],
      ['strings.Count(text, "a")', 'go'],
      ['utf8.RuneCountInString(text)', 'go'],
      ['(text.match(DIGITS) || []).length', 'javascript'],
      ['q.split(",").length', 'javascript'],
      ['/^\\d+$/.test(q)', 'javascript'],
      ['/[/]x/g.test(q)', 'javascript'],
      ['DIGITS.test(q)', 'javascript'],
      ['q.includes("<")', 'typescript'],
    ])('%s (%s) is a measure or test', (expr, lang) => {
      expect(isScalarDerivation(expr, lang)).toBe(true);
    });

    it.each([
      ['re.FindString(text)', 'go'],
      ['db.Index(text)', 'go'],
      ['len(a) + b', 'go'],
      ['strconv.Atoi(q)', 'go'],
      ['q.match(re)', 'javascript'],
      ['q.length > 3 ? q : ""', 'javascript'],
      ['q.slice(0, q.length)', 'javascript'],
      ['q + q.length', 'javascript'],
      ['`${q}x`.length', 'javascript'],
      ['foo(q).bar', 'javascript'],
      ['includes(q)', 'javascript'],
      ['idx.search(q)', 'javascript'],
      ['len(q)', 'python'],
    ])('%s (%s) is not', (expr, lang) => {
      expect(isScalarDerivation(expr, lang)).toBe(false);
    });
  });
});
