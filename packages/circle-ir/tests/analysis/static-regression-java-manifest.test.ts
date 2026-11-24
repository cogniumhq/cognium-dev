import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * Static-regression manifest anchors for sast-validation (Refs cognium-dev#1349).
 * Fixture text mirrors coggiyadmin/java-vuln-demo paths named in manifest.json;
 * strings are fabricated for this repo (no corpus copy).
 */
describe('static-regression manifest Java TP anchors (#1349)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('#155t JexlUserEval — user JEXL expression reaches createExpression', async () => {
    const code = `
package com.demo.libapi;

import org.apache.commons.jexl3.*;

public class JexlUserEval {
    private static final JexlEngine JEXL = new JexlBuilder().create();
    public Object run(String userExpr) {
        return JEXL.createExpression(userExpr).evaluate(new MapContext());
    }
}
`;
    const result = await analyze(code, 'JexlUserEval.java', 'java');
    const hasFlow = (result.taint.flows ?? []).some(
      (f) => f.sink_type === 'code_injection',
    );
    expect(hasFlow).toBe(true);
  });

  it('#470t UnsafeReflection — HTTP param selects Class.forName target', async () => {
    const code = `
package com.demo;

import javax.servlet.http.HttpServletRequest;

public class UnsafeReflection {
    public Object make(HttpServletRequest req) throws Exception {
        String cls = req.getParameter("cls");
        return Class.forName(cls).getDeclaredConstructor().newInstance();
    }
}
`;
    const result = await analyze(code, 'UnsafeReflection.java', 'java');
    const flows = result.taint.flows ?? [];
    expect(flows.some((f) => f.sink_type === 'code_injection')).toBe(true);
    expect(flows.some((f) => f.sink_type === 'deserialization')).toBe(false);
  });
});