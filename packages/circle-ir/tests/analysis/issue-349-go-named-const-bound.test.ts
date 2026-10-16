/**
 * #349 (follow-up of the bounded-make slice) — Go: the upper bound of a size
 * guard may be a same-file integer `const`.
 *
 * Before: `if err != nil || n > maxAlloc { return }` followed by
 * `buf := make([]byte, n); w.Write(buf)` still reported xss, while the literal
 * `n > 4096` was credited. A bound against a `var`, a parameter, a local or a
 * request-derived value is not a constant bound and keeps reporting.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const header = ['package pool', '', 'import (', '\t"net/http"', '\t"strconv"', ')', ''].join('\n');

const handler = (decls: string[], cond: string, ...pre: string[]) =>
  [
    header,
    ...decls,
    '',
    'func Sized(w http.ResponseWriter, r *http.Request) {',
    '\tn, err := strconv.Atoi(r.URL.Query().Get("size"))',
    ...pre.map((l) => '\t' + l),
    `\t${cond} {`,
    '\t\thttp.Error(w, "bad size", http.StatusBadRequest)',
    '\t\treturn',
    '\t}',
    '\tbuf := make([]byte, n)',
    '\tw.Write(buf)',
    '}',
    '',
  ].join('\n');

const flows = async (code: string, file: string) => {
  const r = await analyze(code, file, 'go');
  return (r.taint.flows ?? []).map((f) => `${f.sink_type}@${f.sink_line}`);
};

const GUARD = 'if err != nil || n < 0 || n > maxAlloc';

describe('#349 — a named integer const is a constant bound', () => {
  beforeAll(async () => { await initAnalyzer(); });

  describe('clean', () => {
    it.each([
      ['const declaration', ['const maxAlloc = 4096']],
      ['typed const', ['const maxAlloc int = 4096']],
      ['const in a block', ['const (', '\tlabel     = "x"', '\tmaxAlloc  = 4096', ')']],
      ['typed const in a block', ['const (', '\tmaxAlloc int = 65536', ')']],
    ])('%s', async (_n, decls) => {
      expect(await flows(handler(decls, GUARD), 'named.go')).toEqual([]);
    });

    it('is not keyed on names: renamed const and size', async () => {
      const code = handler(['const replyLimit = 8192'], 'if err != nil || n >= replyLimit').replace(/\bn\b/g, 'count');
      expect(await flows(code, 'renamed.go')).toEqual([]);
    });

    it('the literal bound is unchanged', async () => {
      expect(await flows(handler([], 'if err != nil || n < 0 || n > 4096'), 'literal.go')).toEqual([]);
    });
  });

  describe('still reports', () => {
    it.each([
      ['a package var is not a constant', ['var maxAlloc = 4096']],
      ['a const that is not an integer literal', ['const maxAlloc = "4096"']],
      ['a const computed from a name', ['const base = 4096', 'const maxAlloc = base']],
      ['no declaration at all', []],
    ])('%s', async (_n, decls) => {
      expect((await flows(handler(decls, GUARD), 'var.go')).length).toBeGreaterThan(0);
    });

    it('the const name is shadowed by a local in the handler', async () => {
      const code = handler(['const maxAlloc = 4096'], GUARD, 'maxAlloc := n + 1');
      expect((await flows(code, 'shadow_local.go')).length).toBeGreaterThan(0);
    });

    it('the const name is shadowed by a parameter in another function', async () => {
      const code = handler(['const maxAlloc = 4096', 'func other(maxAlloc int) int { return maxAlloc }'], GUARD);
      expect((await flows(code, 'shadow_param.go')).length).toBeGreaterThan(0);
    });

    it('the const name is declared twice', async () => {
      const code = handler(['const maxAlloc = 4096', 'func f() {', '\tconst maxAlloc = 1 << 40', '}'], GUARD);
      expect((await flows(code, 'twice.go')).length).toBeGreaterThan(0);
    });

    it('the bound is compared with a request-derived value', async () => {
      const code = handler(['const maxAlloc = 4096'], 'if err != nil || n > limit', 'limit, _ := strconv.Atoi(r.URL.Query().Get("max"))');
      expect((await flows(code, 'derived.go')).length).toBeGreaterThan(0);
    });

    it('the guard is after the make', async () => {
      const code = [
        header,
        'const maxAlloc = 4096',
        '',
        'func Late(w http.ResponseWriter, r *http.Request) {',
        '\tn, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        '\tbuf := make([]byte, n)',
        '\tif n > maxAlloc {',
        '\t\treturn',
        '\t}',
        '\tw.Write(buf)',
        '}',
        '',
      ].join('\n');
      expect((await flows(code, 'late.go')).length).toBeGreaterThan(0);
    });

    it('the bound joined with && does not reject every large value', async () => {
      const code = handler(['const maxAlloc = 4096'], 'if err != nil && n > maxAlloc');
      expect((await flows(code, 'and.go')).length).toBeGreaterThan(0);
    });

    it('the size is reassigned after the guard', async () => {
      const code = [
        header,
        'const maxAlloc = 4096',
        '',
        'func Reassigned(w http.ResponseWriter, r *http.Request) {',
        '\tn, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        '\tif n > maxAlloc {',
        '\t\treturn',
        '\t}',
        '\tn, _ = strconv.Atoi(r.URL.Query().Get("other"))',
        '\tbuf := make([]byte, n)',
        '\tw.Write(buf)',
        '}',
        '',
      ].join('\n');
      expect((await flows(code, 'reassigned.go')).length).toBeGreaterThan(0);
    });
  });
});
