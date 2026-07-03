/**
 * Regression tests for cognium-dev #226 and #227.
 *
 * Both are Java `resource-leak` (Pass #21) false-positive tickets:
 *
 *   #226 — stream ownership transfer through wrapping Closeable
 *          constructors (calcite-avatica `Sources.java`).
 *   #227 — `close()` inside Executor `Runnable` finally not tracked
 *          across the anonymous-class boundary (angus-mail
 *          `IdleManager.java`).
 *
 * Locks:
 *   - The FP fixtures produce ZERO `resource-leak` findings.
 *   - Recall guards: unrelated leak shapes still fire.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

beforeAll(async () => {
  await initAnalyzer();
});

async function resourceLeakFindings(code: string, path = 'Fix.java') {
  const ir = await analyze(code, path, 'java');
  return (ir.findings ?? []).filter((f) => f.rule_id === 'resource-leak');
}

describe('cognium-dev#226 — wrapper-constructor ownership transfer', () => {
  it('does not flag `fis` when wrapped by GZIPInputStream (calcite Sources.java shape)', async () => {
    const code = `
public class Sources {
    public Reader reader() throws IOException {
        final InputStream is;
        if (path().endsWith(".gz")) {
            final InputStream fis = openStream();
            is = new GZIPInputStream(fis);
        } else {
            is = openStream();
        }
        return new InputStreamReader(is, StandardCharsets.UTF_8);
    }
}`;
    const leaks = await resourceLeakFindings(code, 'Sources.java');
    expect(leaks).toHaveLength(0);
  });

  it('does not flag `raw` when wrapped by BufferedReader → InputStreamReader chain', async () => {
    const code = `
public class Chain {
    public String read() throws IOException {
        InputStream raw = openStream();
        InputStreamReader isr = new InputStreamReader(raw);
        BufferedReader br = new BufferedReader(isr);
        return br.readLine();
    }
}`;
    const leaks = await resourceLeakFindings(code, 'Chain.java');
    const rawLeak = leaks.find((f) => /'raw'/.test(f.message));
    expect(rawLeak, 'raw is wrapped by InputStreamReader').toBeUndefined();
  });

  it('RECALL GUARD: still flags an unwrapped openStream() that is never closed', async () => {
    // Use a factory-method open (Java parser reliably emits these);
    // no `return fis...` so suppression 1 does not trigger.
    const code = `
public class Leak {
    public void read() throws IOException {
        InputStream fis = openStream();
        System.out.println(fis.available());
    }
}`;
    const leaks = await resourceLeakFindings(code, 'Leak.java');
    expect(leaks.length).toBeGreaterThan(0);
    expect(leaks[0].severity).toBe('high');
  });

  it('RECALL GUARD: still flags when wrapped by a non-whitelisted class', async () => {
    const code = `
public class Custom {
    public void go() throws IOException {
        InputStream is = openStream();
        Object wrapper = new MyCustomWrapper(is);
    }
}`;
    const leaks = await resourceLeakFindings(code, 'Custom.java');
    // MyCustomWrapper is outside WRAPPER_CTORS — the #226 suppression
    // MUST NOT apply. Assert findings > 0 to lock recall.
    expect(leaks.length).toBeGreaterThan(0);
  });
});

describe('cognium-dev#227 — nested-worker field-close suppression', () => {
  it('does not flag the resource field closed inside a Runnable#run finally', async () => {
    const code = `
public class IdleManager {
    private Selector selector;
    public IdleManager(Session session, ExecutorService es) throws IOException {
        selector = Selector.open();
        es.execute(new Runnable() {
            public void run() {
                try {
                    select();
                } finally {
                    try { selector.close(); } catch (IOException e) {}
                }
            }
        });
    }
}`;
    const leaks = await resourceLeakFindings(code, 'IdleManager.java');
    expect(leaks).toHaveLength(0);
  });

  it('RECALL GUARD: leak of a bare local (not a field) still fires', async () => {
    const code = `
public class BareLocal {
    public void go() throws IOException {
        InputStream fis = openStream();
        System.out.println(fis.available());
    }
}`;
    const leaks = await resourceLeakFindings(code, 'BareLocal.java');
    expect(leaks.length).toBeGreaterThan(0);
  });
});
