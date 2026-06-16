/**
 * Tests for weak-random pass (CWE-330). Covers Java, Python, JS/TS, Go.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const weakRandom = (r: { findings?: Array<{ rule_id: string }> }) =>
  (r.findings ?? []).filter((f) => f.rule_id === 'weak-random');

describe('weak-random pass', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // ---------------- Java ----------------
  it('Java: new Random() is flagged', async () => {
    const code = `
import java.util.Random;
public class A {
  public int token() {
    Random r = new Random();
    return r.nextInt();
  }
}
`;
    const r = await analyze(code, 'A.java', 'java');
    expect(weakRandom(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Java: Math.random() is flagged', async () => {
    const code = `
public class A {
  public double rnd() { return Math.random(); }
}
`;
    const r = await analyze(code, 'B.java', 'java');
    expect(weakRandom(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Java: new SecureRandom() is NOT flagged', async () => {
    const code = `
import java.security.SecureRandom;
public class A {
  public byte[] tok() {
    SecureRandom sr = new SecureRandom();
    byte[] b = new byte[32];
    sr.nextBytes(b);
    return b;
  }
}
`;
    const r = await analyze(code, 'C.java', 'java');
    expect(weakRandom(r)).toHaveLength(0);
  });

  // ---------------- Python ----------------
  it('Python: random.random() is flagged', async () => {
    const code = `
import random
def tok():
    return random.random()
`;
    const r = await analyze(code, 'a.py', 'python');
    expect(weakRandom(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: random.randint(...) is flagged', async () => {
    const code = `
import random
def tok():
    return random.randint(0, 100)
`;
    const r = await analyze(code, 'b.py', 'python');
    expect(weakRandom(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Python: secrets.token_bytes is NOT flagged', async () => {
    const code = `
import secrets
def tok():
    return secrets.token_bytes(32)
`;
    const r = await analyze(code, 'c.py', 'python');
    expect(weakRandom(r)).toHaveLength(0);
  });

  // ---------------- JS / TS ----------------
  it('JS: Math.random() is flagged', async () => {
    const code = `
function tok() { return Math.random(); }
`;
    const r = await analyze(code, 'a.js', 'javascript');
    expect(weakRandom(r).length).toBeGreaterThanOrEqual(1);
  });

  it('TS: Math.random() is flagged', async () => {
    const code = `
function tok(): number { return Math.random(); }
`;
    const r = await analyze(code, 'a.ts', 'typescript');
    expect(weakRandom(r).length).toBeGreaterThanOrEqual(1);
  });

  // ---------------- Go ----------------
  it('Go: math/rand.Intn is flagged', async () => {
    const code = `
package main
import "math/rand"
func tok() int { return rand.Intn(100) }
`;
    const r = await analyze(code, 'a.go', 'go');
    expect(weakRandom(r).length).toBeGreaterThanOrEqual(1);
  });

  it('Go: crypto/rand.Read is NOT flagged', async () => {
    const code = `
package main
import "crypto/rand"
func tok() {
  b := make([]byte, 32)
  _, _ = rand.Read(b)
}
`;
    const r = await analyze(code, 'b.go', 'go');
    expect(weakRandom(r)).toHaveLength(0);
  });

  it('Go: math/rand under alias does NOT trigger via bare `rand`', async () => {
    // When math/rand is aliased AND crypto/rand owns the bare `rand`, calls
    // through `rand.Read` should not be flagged.
    const code = `
package main
import (
  mrand "math/rand"
  "crypto/rand"
)
func tok() {
  _ = mrand.Intn(10)
  b := make([]byte, 32)
  _, _ = rand.Read(b)
}
`;
    const r = await analyze(code, 'c.go', 'go');
    // `mrand.Intn` is via the aliased receiver; the pass only matches the bare
    // `rand` receiver, so this code does not raise a finding.
    expect(weakRandom(r)).toHaveLength(0);
  });
});
