import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * Regression lock for issue #189 (3.142.0) — Sprint 93 Java FN patches.
 *
 * Covers the remaining false negatives from the Sprint 92 top-100 rerun:
 *
 * 1. CRLF via Cookie constructor / HttpServletResponse.addCookie
 *    (fixture: V02SetCookie). Requires the new CRLF sink pattern
 *    `Cookie(constructor)@arg[0,1]` + `HttpServletResponse.addCookie@arg[0]`.
 *
 * 2. Insecure deserialization via `new Yaml().load(taint)` inline receiver
 *    and `Yaml y = new Yaml(); y.load(taint)` intermediate receiver
 *    (fixture: V02YamlUnsafe). Requires:
 *    - `new X(...)` constructor-receiver resolution in
 *      `resolveReceiverType` so `new Yaml().load(...)` binds to `Yaml`
 *    - `http_param`/`http_query` reach `deserialization` in
 *      `canSourceReachSink`
 *    - Colocation-source filter admits sources with LHS-bound variable
 *      when the variable is absent from the sink's RHS (nested-source
 *      shape `Object o = y.load(req.getParameter("y"))`)
 *
 * 3. ObjectInputStream baseline — regression guard for the pre-existing
 *    io_input → deserialization path.
 */
describe('#189 3.142.0 Java FN patches', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('CRLF: inline addCookie(new Cookie(name, taint))', async () => {
    const code = `
import javax.servlet.http.*;
public class A {
    public void doGet(HttpServletRequest req, HttpServletResponse res) {
        res.addCookie(new Cookie("k", req.getParameter("v")));
    }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.source_type === 'http_param' && f.sink_type === 'crlf')).toBe(true);
  });

  it('CRLF: intermediate Cookie variable', async () => {
    const code = `
import javax.servlet.http.*;
public class A {
    public void doGet(HttpServletRequest req, HttpServletResponse res) {
        String v = req.getParameter("v");
        Cookie c = new Cookie("k", v);
        res.addCookie(c);
    }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.source_type === 'http_param' && f.sink_type === 'crlf')).toBe(true);
  });

  it('CRLF: Cookie constructor only (no addCookie)', async () => {
    const code = `
import javax.servlet.http.*;
public class A {
    public void doGet(HttpServletRequest req, HttpServletResponse res) {
        Cookie c = new Cookie("k", req.getParameter("v"));
    }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.source_type === 'http_param' && f.sink_type === 'crlf')).toBe(true);
  });

  it('deserialization: new Yaml().load(taint) inline receiver', async () => {
    const code = `
import org.yaml.snakeyaml.Yaml;
import javax.servlet.http.*;
public class A {
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
        Object o = new Yaml().load(req.getParameter("y"));
    }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.source_type === 'http_param' && f.sink_type === 'deserialization')).toBe(true);
  });

  it('deserialization: intermediate Yaml var then y.load(taint)', async () => {
    const code = `
import org.yaml.snakeyaml.Yaml;
import javax.servlet.http.*;
public class A {
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
        Yaml y = new Yaml();
        Object o = y.load(req.getParameter("y"));
    }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.source_type === 'http_param' && f.sink_type === 'deserialization')).toBe(true);
  });

  it('deserialization: ObjectInputStream.readObject baseline', async () => {
    const code = `
import java.io.*;
import javax.servlet.http.*;
public class A {
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
        byte[] b = req.getParameter("d").getBytes();
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(b));
        Object o = ois.readObject();
    }
}`;
    const ir = await analyze(code, 'A.java', 'java');
    const flows = ir.taint?.flows ?? [];
    expect(flows.some((f) => f.sink_type === 'deserialization')).toBe(true);
  });
});
