/**
 * #612 — a method parameter declared `Random` is a generator whose runtime
 * type is decided by the caller (often another file, often a `SecureRandom`).
 * Treat it as unknown, not weak: no weak-random finding on the parameter's
 * own method calls. A local `new Random()`, a field initialised with
 * `new Random()`, `Math.random()` and `ThreadLocalRandom` keep firing.
 *
 * Fixtures use renamed classes, methods and variables on purpose.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

async function weakLines(code: string): Promise<number[]> {
  const r = await analyze(code, 'Svc.java', 'java');
  return (r.findings ?? []).filter((f) => f.rule_id === 'weak-random').map((f) => f.line);
}

describe('#612 weak-random: a Random-typed parameter is unknown, not weak', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('safe mirror: a Random parameter with only SecureRandom callers is clean', async () => {
    const lines = await weakLines(`import java.util.Random;
import java.security.SecureRandom;
public class Svc {
  void fill(Random gen, byte[] buf) { gen.nextBytes(buf); }
  void run(byte[] buf) { fill(new SecureRandom(), buf); }
}
`);
    expect(lines).toEqual([]);
  });

  it('every Random-typed parameter use is clean (nextInt, nextLong, ...)', async () => {
    const lines = await weakLines(`import java.util.Random;
public class Svc {
  int a(Random src) { return src.nextInt(); }
  long b(int n, Random src2) { return src2.nextLong() + n; }
}
`);
    expect(lines).toEqual([]);
  });

  it('a parameter in a constructor is clean', async () => {
    const lines = await weakLines(`import java.util.Random;
public class Svc {
  private int seedValue;
  Svc(Random rng) { this.seedValue = rng.nextInt(); }
}
`);
    expect(lines).toEqual([]);
  });

  // ---- positive controls: these must keep firing ----------------------------

  it('a local new Random() still fires', async () => {
    const lines = await weakLines(`import java.util.Random;
public class Svc {
  void run(byte[] b) {
    Random r = new Random();
    r.nextBytes(b);
  }
}
`);
    expect(lines).toEqual([5]);
  });

  it('a field initialised with new Random() still fires', async () => {
    const lines = await weakLines(`import java.util.Random;
public class Svc {
  private final Random rnd = new Random();
  int draw() { return rnd.nextInt(); }
}
`);
    expect(lines).toEqual([4]);
  });

  it('Math.random() and ThreadLocalRandom still fire', async () => {
    const lines = await weakLines(`import java.util.concurrent.ThreadLocalRandom;
public class Svc {
  double a() { return Math.random(); }
  int b() { return ThreadLocalRandom.current().nextInt(); }
}
`);
    expect(lines).toEqual([3, 4]);
  });

  it('a parameter name reused as a local in another method does not hide that local', async () => {
    const lines = await weakLines(`import java.util.Random;
public class Svc {
  void viaParam(Random gen, byte[] buf) { gen.nextBytes(buf); }
  void viaLocal(byte[] buf) {
    Random gen = new Random();
    gen.nextBytes(buf);
  }
}
`);
    expect(lines).toEqual([6]);
  });

  it('a Random-typed field is still weak when a different method has a parameter of that name', async () => {
    const lines = await weakLines(`import java.util.Random;
public class Svc {
  private final Random gen = new Random();
  void viaParam(Random gen, byte[] buf) { gen.nextBytes(buf); }
  void viaField(byte[] buf) { gen.nextBytes(buf); }
}
`);
    expect(lines).toEqual([5]);
  });

  it('a SplittableRandom parameter is still weak (its concrete type is fixed)', async () => {
    const lines = await weakLines(`import java.util.SplittableRandom;
public class Svc {
  int a(SplittableRandom s) { return s.nextInt(); }
}
`);
    expect(lines).toEqual([3]);
  });
});
