/**
 * #349 (minimal slice) — Go: a size parsed from request text, rejected with an
 * early return when it exceeds a constant, is bounded where it sizes a `make`.
 *
 * Before: the bounded `make([]byte, n)` buffer was still treated as carrying the
 * request taint into `w.Write(buf)`. The unbounded size keeps reporting.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const header = [
  'package pool',
  '',
  'import (',
  '\t"fmt"',
  '\t"net/http"',
  '\t"strconv"',
  ')',
  '',
].join('\n');

const handler = (name: string, ...body: string[]) =>
  [
    header,
    `func ${name}(w http.ResponseWriter, r *http.Request) {`,
    ...body.map((l) => '\t' + l),
    '}',
    '',
  ].join('\n');

const sizedReply = handler(
  'SizedReply',
  'n, err := strconv.Atoi(r.URL.Query().Get("size"))',
  'if err != nil || n < 0 || n > 4096 {',
  '\thttp.Error(w, "bad size", http.StatusBadRequest)',
  '\treturn',
  '}',
  'buf := make([]byte, n)',
  'w.Write(buf)',
);

const sizedReplyOpen = handler(
  'SizedReplyOpen',
  'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
  'buf := make([]byte, n)',
  'w.Write(buf)',
);

const flows = async (code: string, file: string) => {
  const r = await analyze(code, file, 'go');
  return (r.taint.flows ?? []).map((f) => `${f.sink_type}@${f.sink_line}`);
};

describe('#349 — a bounded size is not tainted where it sizes a make', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the early-return upper bound clears the buffer; the unbounded size still reports', async () => {
    expect(await flows(sizedReply, 'sized_reply.go')).toEqual([]);
    expect((await flows(sizedReplyOpen, 'sized_reply_open.go')).length).toBeGreaterThan(0);
  });

  it('is not keyed on names: renamed size, buffer and bound still clear', async () => {
    const code = sizedReply
      .replace(/\bn\b/g, 'count')
      .replace(/\bbuf\b/g, 'payload')
      .replace('4096', '65536');
    expect(await flows(code, 'renamed.go')).toEqual([]);
  });

  it.each([
    ['>= bound', 'if n >= 4096 {', []],
    ['bound as the left operand of ||', 'if n < 0 || n > 4096 {', []],
    ['panic instead of return', 'if n > 4096 {', []],
  ])('credits %s', async (_label, cond, expected) => {
    const exit = _label.startsWith('panic') ? 'panic("too big")' : 'return';
    const code = handler(
      'Sized',
      'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
      cond,
      '\t' + exit,
      '}',
      'buf := make([]byte, n)',
      'w.Write(buf)',
    );
    expect(await flows(code, 'sized.go')).toEqual(expected);
  });

  it('cap argument: make([]byte, 0, n) with a bounded n clears', async () => {
    const code = handler(
      'SizedCap',
      'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
      'if n > 4096 {',
      '\treturn',
      '}',
      'buf := make([]byte, 0, n)',
      'w.Write(buf)',
    );
    expect(await flows(code, 'sized_cap.go')).toEqual([]);
  });

  it('a guard inside a block that is still open at the make clears', async () => {
    const code = handler(
      'OpenBlock',
      'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
      'if r.Method == "POST" {',
      '\tif n > 4096 {',
      '\t\treturn',
      '\t}',
      '\tbuf := make([]byte, n)',
      '\tw.Write(buf)',
      '}',
    );
    expect(await flows(code, 'open_block.go')).toEqual([]);
  });

  it('an outer guard still clears after a later nested guard closes', async () => {
    const code = handler(
      'TwoGuards',
      'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
      'if n > 4096 {',
      '\treturn',
      '}',
      'if r.Method == "POST" {',
      '\tif n > 1024 {',
      '\t\treturn',
      '\t}',
      '}',
      'buf := make([]byte, n)',
      'w.Write(buf)',
    );
    expect(await flows(code, 'two_guards.go')).toEqual([]);
  });

  describe('still reports when the bound does not hold at the make', () => {
    it('the guard does not exit', async () => {
      const code = handler(
        'NoExit',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'if n > 4096 {',
        '\thttp.Error(w, "big", http.StatusBadRequest)',
        '}',
        'buf := make([]byte, n)',
        'w.Write(buf)',
      );
      expect((await flows(code, 'no_exit.go')).length).toBeGreaterThan(0);
    });

    it('the guard is after the make', async () => {
      const code = handler(
        'Late',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'buf := make([]byte, n)',
        'if n > 4096 {',
        '\treturn',
        '}',
        'w.Write(buf)',
      );
      expect((await flows(code, 'late.go')).length).toBeGreaterThan(0);
    });

    it('the guard is on a different variable', async () => {
      const code = handler(
        'Other',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'limit := 10',
        'if limit > 4096 {',
        '\treturn',
        '}',
        'buf := make([]byte, n)',
        'w.Write(buf)',
      );
      expect((await flows(code, 'other.go')).length).toBeGreaterThan(0);
    });

    it('the size is reassigned after the guard', async () => {
      const code = handler(
        'Reassigned',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'if n > 4096 {',
        '\treturn',
        '}',
        'n, _ = strconv.Atoi(r.URL.Query().Get("other"))',
        'buf := make([]byte, n)',
        'w.Write(buf)',
      );
      expect((await flows(code, 'reassigned.go')).length).toBeGreaterThan(0);
    });

    it('the bound is joined with && so it does not reject every large value', async () => {
      const code = handler(
        'Conditional',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'if n > 4096 && err != nil {',
        '\treturn',
        '}',
        'buf := make([]byte, n)',
        'w.Write(buf)',
      );
      expect((await flows(code, 'conditional.go')).length).toBeGreaterThan(0);
    });

    it('the guard sits in a nested block that closes before the make', async () => {
      const code = handler(
        'NestedGuard',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'if r.Method == "POST" {',
        '\tif n > 4096 {',
        '\t\treturn',
        '\t}',
        '}',
        'buf := make([]byte, n)',
        'w.Write(buf)',
      );
      expect((await flows(code, 'nested_guard.go')).length).toBeGreaterThan(0);
    });

    it('the guard sits in a loop body that closes before the make', async () => {
      const code = handler(
        'LoopGuard',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'for i := 0; i < 3; i++ {',
        '\tif n > 4096 {',
        '\t\tcontinue',
        '\t}',
        '}',
        'buf := make([]byte, n)',
        'w.Write(buf)',
      );
      expect((await flows(code, 'loop_guard.go')).length).toBeGreaterThan(0);
    });

    it('the guard sits in an if branch and the make in its else branch', async () => {
      const code = handler(
        'ElseMake',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'if r.Method == "POST" {',
        '\tif n > 4096 {',
        '\t\treturn',
        '\t}',
        '} else {',
        '\tbuf := make([]byte, n)',
        '\tw.Write(buf)',
        '}',
      );
      expect((await flows(code, 'else_make.go')).length).toBeGreaterThan(0);
    });

    it('the guard sits in another switch case than the make', async () => {
      const code = handler(
        'CaseMake',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'switch r.Method {',
        'case "POST":',
        '\tif n > 4096 {',
        '\t\treturn',
        '\t}',
        'case "GET":',
        '\tbuf := make([]byte, n)',
        '\tw.Write(buf)',
        '}',
      );
      expect((await flows(code, 'case_make.go')).length).toBeGreaterThan(0);
    });

    it.each([
      ['n++', 'n++'],
      ['n--', 'n--'],
      ['&n passed to fmt.Sscanf', 'fmt.Sscanf(r.URL.Query().Get("other"), "%d", &n)'],
    ])('the size is rewritten after the guard by %s', async (_label, rewrite) => {
      const code = handler(
        'Rewritten',
        'n, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        'if n > 4096 {',
        '\treturn',
        '}',
        rewrite,
        'buf := make([]byte, n)',
        'w.Write(buf)',
      );
      expect((await flows(code, 'rewritten.go')).length).toBeGreaterThan(0);
    });

    it('the bound is read in another function', async () => {
      const code = [
        header,
        'func check(n int) {',
        '\tif n > 4096 {',
        '\t\treturn',
        '\t}',
        '}',
        '',
        'func Elsewhere(w http.ResponseWriter, r *http.Request) {',
        '\tn, _ := strconv.Atoi(r.URL.Query().Get("size"))',
        '\tbuf := make([]byte, n)',
        '\tw.Write(buf)',
        '}',
        '',
      ].join('\n');
      expect((await flows(code, 'elsewhere.go')).length).toBeGreaterThan(0);
    });
  });
});
