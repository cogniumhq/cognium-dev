/**
 * Sprint 45 — cognium-dev #158.
 *
 * `resource-leak` (CWE-772) FP reduction. Adds three additive
 * suppressions in `resource-leak-pass.ts`:
 *
 *   1. Return-flow — resource variable appears in a `return ...`
 *      expression within the enclosing method (caller owns the handle).
 *   2. Field-store with paired close-method — resource stored to
 *      `this.<field>` AND the enclosing class declares any method
 *      that calls `<field>.close()` / `release()` / etc.
 *   3. Factory-method-name heuristic — enclosing method matches the
 *      prefix family `open` / `create` / `new` / `get` / `make` / `build`
 *      followed by a capital letter, AND has non-void return type.
 *
 * Recall locks: unreturned, unstored, non-factory resources continue
 * to fire as definite HIGH leaks.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countByRule = (
  arr: Array<{ rule_id?: string }> | undefined,
  r: string,
) => (arr ?? []).filter((f) => f.rule_id === r).length;

describe('cognium-dev #158 — resource-leak factory / field-store FP suppressions', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // --------------------------------------------------------------------------
  // 1. FP Pattern 1 — factory returns the handle (URLConnection)
  // --------------------------------------------------------------------------
  it('factory: openHttp() returns the URLConnection — no leak finding', async () => {
    const code = `import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.net.URL;

public class Http {
  public HttpURLConnection openHttp(URL url) throws Exception {
    URLConnection conn = url.openConnection();
    return (HttpURLConnection) conn;
  }
}
`;
    const r = await analyze(code, 'Http.java', 'java');
    expect(countByRule(r.findings, 'resource-leak')).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 2. FP Pattern 1 — factory returns BufferedInputStream wrapping resource
  // --------------------------------------------------------------------------
  it('factory: openInputStream() returns BufferedInputStream wrapper — no leak finding', async () => {
    const code = `import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.URI;

public class StreamFactory {
  private InputStream inputStream;
  public InputStream openInputStream(URI uri) throws Exception {
    if (inputStream == null) {
      inputStream = uri.toURL().openStream();
    }
    return new BufferedInputStream(inputStream);
  }
}
`;
    const r = await analyze(code, 'StreamFactory.java', 'java');
    expect(countByRule(r.findings, 'resource-leak')).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 3. FP Pattern 1 — factory returns conn.getInputStream() (still returns)
  // --------------------------------------------------------------------------
  it('factory: getInputStream() returns the connection-derived stream — no leak finding', async () => {
    const code = `import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

public class Fetcher {
  public InputStream getInputStream(URL url) throws Exception {
    URLConnection conn = url.openConnection();
    return conn.getInputStream();
  }
}
`;
    const r = await analyze(code, 'Fetcher.java', 'java');
    expect(countByRule(r.findings, 'resource-leak')).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 4. FP Pattern 2 — field-store + paired close method on class. Uses
  //    a factory method (openConnection) since Java constructors are not
  //    tagged is_constructor in the IR; the suppression logic itself is
  //    constructor-vs-factory-agnostic.
  // --------------------------------------------------------------------------
  it('field-store + paired close method (open/release pair) — no leak finding', async () => {
    // Mirrors the #158 ticket-body Camera example: OpenCameraInterface.open
    // factory method, stored to `this.camera`, paired with a `closeDriver`
    // method that calls `camera.release()` (release is in CLOSE_METHODS).
    const code = `public class Driver {
  private Camera camera;

  public void openDriver(int id) throws Exception {
    Camera theCamera = OpenCameraInterface.open(id);
    this.camera = theCamera;
  }

  public void closeDriver() throws Exception {
    if (camera != null) camera.release();
  }
}
`;
    const r = await analyze(code, 'Driver.java', 'java');
    expect(countByRule(r.findings, 'resource-leak')).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 5. FP factory-name heuristic — `createInputStream` named factory that
  //    transfers ownership without textually returning the variable
  //    (caller takes ownership via cache / registry / wrapper). Exercises
  //    suppression 3 in isolation (suppression 1 doesn't apply because
  //    the resource variable is not in the `return ...` expression; the
  //    method's factory-shape name + non-void return type is what gates
  //    the suppression).
  // --------------------------------------------------------------------------
  it('factory-name: createInputStream() with non-direct-return — no leak finding', async () => {
    const code = `import java.io.InputStream;
import java.net.URL;

public class Builder {
  public InputStream createInputStream(URL url) throws Exception {
    InputStream is = url.openStream();
    registerForCleanup(is);
    return null;
  }

  private void registerForCleanup(InputStream s) {}
}
`;
    const r = await analyze(code, 'Builder.java', 'java');
    expect(countByRule(r.findings, 'resource-leak')).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 6. Recall — void method opens a stream via factory and never closes
  //             or returns it (factory method openStream on URL).
  // --------------------------------------------------------------------------
  it('recall: void doWork() opens URL.openStream() and never closes/returns — leak fires', async () => {
    const code = `import java.io.InputStream;
import java.net.URL;

public class Reader {
  public void doWork(URL url) throws Exception {
    InputStream is = url.openStream();
    is.read();
  }
}
`;
    const r = await analyze(code, 'Reader.java', 'java');
    expect(countByRule(r.findings, 'resource-leak')).toBeGreaterThanOrEqual(1);
  });

  // --------------------------------------------------------------------------
  // 7. Recall — void method opens URLConnection via openConnection() and
  //             never closes/returns it.
  // --------------------------------------------------------------------------
  it('recall: void doWork() opens openConnection() and never closes/returns — leak fires', async () => {
    const code = `import java.net.URL;
import java.net.URLConnection;

public class Worker {
  public void doWork(URL url) throws Exception {
    URLConnection conn = url.openConnection();
    conn.connect();
  }
}
`;
    const r = await analyze(code, 'Worker.java', 'java');
    expect(countByRule(r.findings, 'resource-leak')).toBeGreaterThanOrEqual(1);
  });

  // --------------------------------------------------------------------------
  // 8. Recall — field-store but NO paired close method in class. Method
  //             name is `store` (non-factory) so suppression 3 also doesn't
  //             apply, and the value isn't returned either.
  // --------------------------------------------------------------------------
  it('recall: field-store without any close method in class — leak fires', async () => {
    const code = `import java.net.URL;
import java.net.URLConnection;

public class Holder {
  private URLConnection cached;

  public void store(URL url) throws Exception {
    URLConnection conn = url.openConnection();
    this.cached = conn;
  }
}
`;
    const r = await analyze(code, 'Holder.java', 'java');
    expect(countByRule(r.findings, 'resource-leak')).toBeGreaterThanOrEqual(1);
  });
});
