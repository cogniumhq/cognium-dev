/**
 * cognium-dev #353 — a tainted variable's name appearing as a bare word inside
 * a STRING LITERAL was treated as a use of that variable, so a flow was
 * reported for a value never passed to the sink:
 *
 *   actor = request.headers.get("X-Actor", "")
 *   x = "hi"
 *   log.info("actor=%s", x)        # log_injection, path 6:actor -> 8:actor
 *
 * `detectExpressionScanFlows` tokenises the sink argument's RAW text and (for a
 * simple identifier) trusts that token index as proof the source occurs in the
 * argument — there is no second check for bare names. The literal `"actor=%s"`
 * tokenises to ['actor', 's'], so `actor` matched.
 *
 * Not a curiosity: format strings routinely name the field they interpolate,
 * and those are the names the variables have. The nastier consequence is that
 * it re-attributes a SANITIZED flow to the raw source —
 * `safe = strip(actor); log.info("actor=%s", safe)` reported against `actor` —
 * so a correct CWE-117 defence still showed a finding and the advice a user
 * follows did not clear it. That is what made the Python fixture on #348 look
 * like a sanitizer bug when the sanitizer was working.
 *
 * The fix blanks literal TEXT before tokenising while preserving
 * interpolations, because there the identifier is a genuine use:
 * `f"actor={actor}"` and `` `actor=${actor}` `` must keep firing. Concatenation,
 * `%` and `.format()` are unaffected either way — the identifier sits outside
 * the quotes in all three.
 *
 * LANGUAGE SCOPE is load-bearing and was found by the suite, not by review:
 * masking is applied to Python and JS/TS only. Bash double quotes interpolate,
 * so masking `eval "${lines[0]}"` would drop a true positive
 * (`bash-read-sources.test.ts`). Rust inline format captures and C#
 * interpolated strings are the same hazard and are equally excluded.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { maskStringLiteralsForTokenScan as mask } from '../../src/analysis/passes/taint-propagation-pass.js';

const tokens = (expr: string): string[] => mask(expr).match(/[\p{L}\p{N}_]+/gu) ?? [];

const py = (body: string[]) =>
  analyze(
    [
      'import logging',
      'from flask import request',
      'log=logging.getLogger("a")',
      '',
      'def f():',
      '    actor = request.headers.get("X-Actor","")',
      ...body.map(l => '    ' + l),
    ].join('\n'),
    'a.py',
    'python'
  );

const js = (body: string[]) =>
  analyze(
    [
      'const express=require("express");const app=express();',
      'app.get("/x",(req,res)=>{',
      '  const actor = req.query.actor;',
      ...body.map(l => '  ' + l),
      '  res.end();',
      '});',
    ].join('\n'),
    'a.js',
    'javascript'
  );

const logInj = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'log_injection' && !f.sanitized);

describe('#353 a name inside a string literal is not a use', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('the false positives this removes', () => {
    it('Python: literal names the variable, a constant is passed', async () => {
      expect(logInj(await py(['x = "hi"', 'log.info("actor=%s", x)']))).toHaveLength(0);
    });

    it('Python: a sanitized local is logged, the literal names the raw source', async () => {
      // The #348 shape. Reported against `actor` even though only the
      // CR/LF-stripped local reaches the sink.
      expect(
        logInj(
          await py([
            'safe = actor.replace("\\r","").replace("\\n","")',
            'log.info("actor=%s", safe)',
          ])
        )
      ).toHaveLength(0);
    });

    it('JavaScript: literal names the variable, a constant is passed', async () => {
      expect(logInj(await js(['const x="hi";', 'console.log("actor=" + x);']))).toHaveLength(0);
    });
  });

  describe('the true positives it must not touch', () => {
    it('Python: the raw variable is logged', async () => {
      expect(logInj(await py(['log.info("by %s", actor)'])).length).toBeGreaterThan(0);
    });

    it('Python: f-string interpolation is a real use', async () => {
      expect(logInj(await py(['log.info(f"actor={actor}")'])).length).toBeGreaterThan(0);
    });

    it('Python: % operator', async () => {
      expect(logInj(await py(['log.info("actor=%s" % actor)'])).length).toBeGreaterThan(0);
    });

    it('Python: concatenation', async () => {
      expect(logInj(await py(['log.info("actor=" + actor)'])).length).toBeGreaterThan(0);
    });

    it('Python: .format()', async () => {
      expect(logInj(await py(['log.info("actor={}".format(actor))'])).length).toBeGreaterThan(0);
    });

    it('JavaScript: template-literal interpolation is a real use', async () => {
      expect(logInj(await js(['console.log(`actor=${actor}`);'])).length).toBeGreaterThan(0);
    });

    it('JavaScript: concatenation of the raw variable', async () => {
      expect(logInj(await js(['console.log("by " + actor);'])).length).toBeGreaterThan(0);
    });
  });

  // The masker's edge cases are much cheaper to pin down directly than through
  // full analysis, and they are where this fix can silently go wrong.
  describe('maskStringLiteralsForTokenScan', () => {
    it('drops plain literal text', () => {
      expect(tokens('"actor=%s"')).not.toContain('actor');
      expect(tokens('"""actor=%s"""')).not.toContain('actor');
      expect(tokens('`plain actor text`')).not.toContain('actor');
    });

    it('keeps identifiers outside the quotes', () => {
      expect(tokens('"actor=%s" % actor')).toContain('actor');
      expect(tokens('"actor=" + actor')).toContain('actor');
      expect(tokens('"actor={}".format(actor)')).toContain('actor');
      expect(tokens('foo(actor, "actor")')).toContain('actor');
    });

    it('keeps f-string and template-literal interpolations', () => {
      expect(tokens('f"actor={actor}"')).toContain('actor');
      expect(tokens("f'actor={actor}'")).toContain('actor');
      expect(tokens('rf"actor={actor}"')).toContain('actor');
      expect(tokens('f"""x={actor}"""')).toContain('actor');
      expect(tokens('`actor=${actor}`')).toContain('actor');
    });

    it('handles conversion and format specs', () => {
      const t = tokens('f"actor={actor!r} n={n:>3}"');
      expect(t).toContain('actor');
      expect(t).toContain('n');
    });

    it('treats {{ }} as escaped braces, not an interpolation', () => {
      expect(tokens('f"literal {{actor}} only"')).not.toContain('actor');
    });

    it('masks nested literals inside an interpolation', () => {
      // A quoted subscript must not smuggle the literal back in.
      expect(tokens('f"{d[\'actor\']}"')).toEqual(['d']);
      expect(tokens('`a=${obj["actor"]}`')).toEqual(['obj']);
    });

    it('does not mistake an escaped quote for the end of the literal', () => {
      expect(tokens('"it\\"s actor"')).not.toContain('actor');
    });
  });
});
