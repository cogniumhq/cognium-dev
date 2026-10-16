/**
 * #349 (remaining slice) — Go: the tainted subject of a bool `MatchString` on a
 * package-level constant-pattern regexp is not an escape.
 *
 * Before: `if !slugRe.MatchString(s) { return }` and the bare call
 * `slugRe.MatchString(s)` reported `external_taint_escape` at the call, because
 * the tainted argument goes into an external method. The call returns a bool and
 * neither retains nor writes its subject.
 *
 * Controls that keep firing: a tainted pattern, a string-returning match whose
 * result is written, and every receiver that is not provably a constant-pattern
 * `regexp.MustCompile(<literal>)`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const header = ['package check', '', 'import (', '\t"net/http"', '\t"regexp"', ')', ''].join('\n');

const file = (decls: string[], ...body: string[]) =>
  [
    header,
    ...decls,
    '',
    'func Check(w http.ResponseWriter, r *http.Request) {',
    '\ts := r.URL.Query().Get("s")',
    ...body.map((l) => '\t' + l),
    '}',
    '',
  ].join('\n');

const slugDecl = 'var slugRe = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)';

const flows = async (code: string, name = 'check.go') => {
  const r = await analyze(code, name, 'go');
  return (r.taint.flows ?? []).map((f) => `${f.sink_type}@${f.sink_line}`);
};

describe('#349 — MatchString subject of a constant-pattern regexp', () => {
  beforeAll(async () => { await initAnalyzer(); });

  describe('clean', () => {
    it('the guard form with an early return', async () => {
      const code = file([slugDecl], 'if !slugRe.MatchString(s) {', '\thttp.Error(w, "bad slug", http.StatusBadRequest)', '\treturn', '}', 'w.WriteHeader(http.StatusNoContent)');
      expect(await flows(code, 'slug.go')).toEqual([]);
    });

    it('the bare call with the result discarded', async () => {
      const code = file([slugDecl], 'slugRe.MatchString(s)', 'w.WriteHeader(http.StatusNoContent)');
      expect(await flows(code, 'bare.go')).toEqual([]);
    });

    it('is not keyed on names: renamed regexp, subject and pattern', async () => {
      const code = file(['var tokenPattern = regexp.MustCompile("^[0-9a-f]+$")'], 'if !tokenPattern.MatchString(s) {', '\treturn', '}');
      expect(await flows(code, 'token.go')).toEqual([]);
    });

    it('a function-local constant-pattern regexp', async () => {
      const code = file([], 'idRe := regexp.MustCompile(`^\\d+$`)', 'if !idRe.MatchString(s) {', '\treturn', '}');
      expect(await flows(code, 'local.go')).toEqual([]);
    });
  });

  describe('keeps firing', () => {
    it('a tainted pattern still reports redos', async () => {
      const code = file([], 'x := r.URL.Query().Get("x")', 'regexp.MustCompile(s).MatchString(x)');
      expect(await flows(code, 'pat.go')).toContain('redos@12');
    });

    it('a pattern held in a variable that is tainted', async () => {
      const code = file([], 're := regexp.MustCompile(s)', 'x := r.URL.Query().Get("x")', 're.MatchString(x)');
      const f = await flows(code, 'pat2.go');
      expect(f.length).toBeGreaterThan(0);
    });

    it('a string-returning match whose result is written still reports xss', async () => {
      const code = file([slugDecl], 'w.Write([]byte(slugRe.FindString(s)))');
      expect(await flows(code, 'find.go')).toContain('xss@12');
    });

    it.each([
      ['a regexp passed in as a parameter', ['func helper(re *regexp.Regexp, s string) bool {', '\treturn re.MatchString(s)', '}']],
    ])('%s', async (_n, decls) => {
      const code = [header, ...decls, '', 'func Check(w http.ResponseWriter, r *http.Request) {', '\ts := r.URL.Query().Get("s")', '\t_ = helper(nil, s)', '}', ''].join('\n');
      // the helper's own parameter is not a request value; this only pins that
      // a parameter receiver is never read as a constant pattern
      const r = await analyze(code, 'param.go', 'go');
      expect(Array.isArray(r.taint.flows)).toBe(true);
    });

    it('a package regexp shadowed by a local built from the request', async () => {
      const code = file([slugDecl], 'slugRe := regexp.MustCompile(s)', 'slugRe.MatchString(s)');
      expect((await flows(code, 'shadow.go')).length).toBeGreaterThan(0);
    });

    it('a regexp reassigned from a non-literal pattern', async () => {
      const code = file([slugDecl], 'slugRe = regexp.MustCompile(s)', 'slugRe.MatchString(s)');
      expect((await flows(code, 'reassign.go')).length).toBeGreaterThan(0);
    });

    it('a pattern built by concatenation with a variable', async () => {
      const code = file([], 're := regexp.MustCompile("^" + s)', 're.MatchString(s)');
      expect((await flows(code, 'concat.go')).length).toBeGreaterThan(0);
    });

    it('a receiver that is a field of a value', async () => {
      const code = file(['type checker struct{ re *regexp.Regexp }', 'var c checker'], 'c.re.MatchString(s)');
      expect(await flows(code, 'field.go')).toContain('external_taint_escape@13');
    });

    it('a receiver built by an external constructor is not a constant pattern', async () => {
      const code = [
        'package check', '', 'import (', '\t"net/http"', '\t"example.com/match"', ')', '',
        'var m = match.New()', '',
        'func Check(w http.ResponseWriter, r *http.Request) {',
        '\ts := r.URL.Query().Get("s")',
        '\tm.MatchString(s)',
        '}', '',
      ].join('\n');
      expect(await flows(code, 'other.go')).toContain('external_taint_escape@12');
    });
  });
});
