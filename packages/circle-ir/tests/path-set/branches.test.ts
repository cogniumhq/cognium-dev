import { describe, it, expect } from 'vitest';
import { deriveBranchFacts, sideOf } from '../../src/index.js';
import type { BranchFact } from '../../src/index.js';

describe('deriveBranchFacts', () => {
  it('reads condition calls, negation and exiting branches (Java)', async () => {
    const code = `class A {
  byte[] read(String name) throws Exception {
    Path p = base.resolve(name).normalize();
    if (!p.startsWith(base)) {
      throw new IllegalArgumentException("outside");
    }
    if (!(!ok(p))) { log(p); } else { return null; }
    return Files.readAllBytes(p);
  }
}`;
    const facts = await deriveBranchFacts(code, 'java');
    expect(facts).toHaveLength(2);
    expect(facts[0]).toMatchObject({ line: 4, endLine: 4, stmtEnd: 6, then: { start: 4, end: 6, exits: true } });
    expect(facts[0].else).toBeUndefined();
    expect(facts[0].calls).toEqual([{ method: 'startsWith', line: 4, column: 9, negated: true }]);
    expect(facts[1].calls[0]).toMatchObject({ method: 'ok', negated: false });
    expect(facts[1].then.exits).toBe(false);
    expect(facts[1].else?.exits).toBe(true);
  });

  it('reads JavaScript and Python conditions', async () => {
    const js = await deriveBranchFacts(`function f(p) {\n  if (!p.startsWith(base)) { throw new Error('x'); }\n  return read(p);\n}`, 'javascript');
    expect(js[0].calls[0]).toMatchObject({ method: 'startsWith', negated: true });
    expect(js[0].then.exits).toBe(true);
    const py = await deriveBranchFacts(`def f(p):\n    if not p.startswith(base):\n        raise ValueError("x")\n    return open(p)\n`, 'python');
    expect(py[0].calls[0]).toMatchObject({ method: 'startswith', negated: true });
    expect(py[0].then.exits).toBe(true);
  });

  it('treats an if/else where both sides exit as exiting', async () => {
    const facts = await deriveBranchFacts(`class A { int f(int x) {\n  if (x > 0) {\n    if (x > 9) { return 1; } else { throw new E(); }\n  }\n  return 0;\n} }`, 'java');
    const outer = facts.find(f => f.line === 2) as BranchFact;
    expect(outer.then.exits).toBe(true);
  });
});

describe('sideOf', () => {
  const fact = (thenExits: boolean, elseExits?: boolean): BranchFact => ({
    line: 2, endLine: 2, stmtEnd: 6, calls: [],
    then: { start: 2, end: 4, exits: thenExits },
    ...(elseExits !== undefined ? { else: { start: 4, end: 6, exits: elseExits } } : {}),
  });

  it('inside a branch, that branch', () => {
    expect(sideOf(fact(false, false), 3)).toBe(true);
    expect(sideOf(fact(false, false), 5)).toBe(false);
  });

  it('after the statement, the side that does not exit', () => {
    expect(sideOf(fact(true), 8)).toBe(false);
    expect(sideOf(fact(false, true), 8)).toBe(true);
    expect(sideOf(fact(false), 8)).toBe('both');
    expect(sideOf(fact(true, true), 8)).toBe('both');
  });

  it('on the condition line itself, both', () => {
    expect(sideOf({ ...fact(true), then: { start: 3, end: 4, exits: true } }, 2)).toBe('both');
  });
});
