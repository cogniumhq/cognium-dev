/**
 * cognium-dev#915 — OWASP Benchmark Java XSS false positives where the helper
 * is an inner class (`new Test().doSomething(request, param)`) and the caller's
 * value comes from `SeparateClassRequest` (`getTheParameter` / `getTheValue`),
 * or where the sink's string literal names a tainted local.
 *
 * Each safe case mirrors an OWASP file; each `keeps` case mirrors a true
 * positive of the same shape that must keep firing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

/** An OWASP-style servlet: `paramLines` set `param`, `Test.doSomething` is `helperBody`. */
function servlet(paramLines: string, helperBody: string, sinkLine: string): string {
  return `package org.owasp.benchmark.testcode;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class BenchmarkTest extends HttpServlet {
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
${paramLines}
        String bar = new Test().doSomething(request, param);
        response.setHeader("X-XSS-Protection", "0");
        ${sinkLine}
    } // end doPost

    private class Test {

        public String doSomething(HttpServletRequest request, String param)
                throws ServletException, IOException {
${helperBody}
        }
    } // end innerclass Test
} // end DataflowThruInnerClass
`;
}

/** OWASP writes the null check only after `getTheParameter`. */
const SCR = (getter: 'getTheParameter' | 'getTheValue') => `        org.owasp.benchmark.helpers.SeparateClassRequest scr =
                new org.owasp.benchmark.helpers.SeparateClassRequest(request);
        String param = scr.${getter}("BenchmarkTest");${getter === 'getTheParameter' ? '\n        if (param == null) param = "";' : ''}`;

const PARAM_NAMES = `        String param = "";
        boolean flag = true;
        java.util.Enumeration<String> names = request.getParameterNames();
        while (names.hasMoreElements() && flag) {
            String name = (String) names.nextElement();
            String[] values = request.getParameterValues(name);
            if (values != null) {
                for (int i = 0; i < values.length && flag; i++) {
                    String value = values[i];
                    if (value.equals("BenchmarkTest")) {
                        param = name;
                        flag = false;
                    }
                }
            }
        }`;

const MAP_SAFE_KEY = `            String bar = "safe!";
            java.util.HashMap<String, Object> map56316 = new java.util.HashMap<String, Object>();
            map56316.put("keyA-56316", "a_Value"); // put some stuff in the collection
            map56316.put("keyB-56316", param); // put it in a collection
            map56316.put("keyC", "another_Value"); // put some stuff in the collection
            bar = (String) map56316.get("keyB-56316"); // get it back out
            bar = (String) map56316.get("keyA-56316"); // get safe value back out

            return bar;`;

const SPLIT = `            String bar = "";
            if (param != null) bar = param.split(" ")[0];
            return bar;`;

const LIST_LIVE = `            String bar = "";
            if (param != null) {
                java.util.List<String> valuesList = new java.util.ArrayList<String>();
                valuesList.add("safe");
                valuesList.add(param);
                valuesList.add("moresafe");

                valuesList.remove(0); // remove the 1st safe value

                bar = valuesList.get(0); // get the param value
            }

            return bar;`;

const xss = async (src: string) => {
  const r = await analyze(src, 'BenchmarkTest.java', 'java');
  return (r.taint?.flows ?? []).filter(f => f.sink_type === 'xss');
};

describe('#915 OWASP xss: inner-class helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // BenchmarkTest01514: getTheParameter, helper returns the safe map key.
  it('safe: getTheParameter + helper returning a safe map key does not fire', async () => {
    expect(await xss(servlet(SCR('getTheParameter'), MAP_SAFE_KEY, 'response.getWriter().write(bar);'))).toEqual([]);
  });

  // BenchmarkTest01768: getTheValue (a constant in SeparateClassRequest) through a pass-through helper.
  it('safe: getTheValue through a pass-through helper does not fire', async () => {
    expect(await xss(servlet(SCR('getTheValue'), SPLIT, 'response.getWriter().print(bar);'))).toEqual([]);
  });

  // BenchmarkTest01439: the sink literal "Parameter value: " names the tainted loop local `value`.
  it('safe: a tainted name inside the sink string literal is not a use', async () => {
    expect(
      await xss(servlet(PARAM_NAMES, MAP_SAFE_KEY, 'response.getWriter().write("Parameter value: " + bar);')),
    ).toEqual([]);
  });

  // BenchmarkTest01509 (TP): same helper as 01768, but getTheParameter.
  it('keeps: getTheParameter through a pass-through helper still fires', async () => {
    expect((await xss(servlet(SCR('getTheParameter'), SPLIT, 'response.getWriter().print(bar);'))).length).toBeGreaterThan(0);
  });

  // BenchmarkTest01437 (TP): same sink literal as 01439, helper returns the parameter.
  it('keeps: getParameterNames + a live list helper + "Parameter value: " + bar still fires', async () => {
    expect(
      (await xss(servlet(PARAM_NAMES, LIST_LIVE, 'response.getWriter().write("Parameter value: " + bar);'))).length,
    ).toBeGreaterThan(0);
  });
});
