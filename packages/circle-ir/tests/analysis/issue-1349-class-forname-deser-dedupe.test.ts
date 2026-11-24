/**
 * cognium-dev#1349 — static-regression rows #155t/#470t expect code_injection only.
 * Class.forName must not emit a parallel deserialization flow when code_injection fires.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

const UNSAFE_REFLECTION = `
package com.demo;
import javax.servlet.http.HttpServletRequest;
public class UnsafeReflection {
    public Object make(HttpServletRequest req) throws Exception {
        String cls = req.getParameter("cls");
        return Class.forName(cls).getDeclaredConstructor().newInstance();
    }
}
`;

describe('#1349 Class.forName deserialization dedupe', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('UnsafeReflection: code_injection only, no deserialization flow', async () => {
    const result = await analyze(UNSAFE_REFLECTION, 'UnsafeReflection.java', 'java');
    const flows = result.taint?.flows ?? [];
    expect(flows.some((f) => f.sink_type === 'code_injection')).toBe(true);
    expect(flows.some((f) => f.sink_type === 'deserialization')).toBe(false);
  });
});