/**
 * Sprint 53 — cognium-dev #196: Java `java.util.logging.Logger.warning(...)`
 * log_injection FN.
 *
 * The fluent `Logger.getLogger("app").warning("user=" + user)` shape used
 * by JDK-only Spring controllers does not flag CWE-117 even when `user`
 * is a `@RequestParam`.
 *
 * Existing sink registry in `config-loader.ts:1407-1413` registers
 * `Logger.warning` / `Logger.severe` / `Logger.info` etc. with
 * `arg_positions: [0]`. Phase 0 reveals whether the FN is:
 *   (a) sink-registration gap — class match fails on `getLogger("…")`
 *       fluent receiver (no local `Logger` variable), or
 *   (b) taint-propagation gap — concat at sink line is not recognised
 *       as a flow even when the sink itself is registered.
 *
 * The recall lock asserts that constant-only `Logger.warning("started")`
 * (no taint) produces zero findings.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countLogSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'log_injection').length;
const countLogFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'log_injection').length;

describe('cognium-dev #196 — Java JDK Logger.<level> log_injection FN', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FN — Logger.getLogger("app").warning concat with @RequestParam fires log_injection', async () => {
    const code = `package com.example;
import java.util.logging.Logger;
import org.springframework.web.bind.annotation.*;
@RestController
public class LogCtl {
  private static final Logger logger = Logger.getLogger("app");
  @GetMapping("/login")
  public String login(@RequestParam String user) {
    logger.warning("login user=" + user);
    return "ok";
  }
}
`;
    const r = await analyze(code, 'LogCtl.java', 'java');
    expect(countLogSinks(r.taint?.sinks)).toBeGreaterThan(0);
    expect(countLogFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('FN — Logger.getLogger fluent-receiver shape fires log_injection', async () => {
    const code = `package com.example;
import java.util.logging.Logger;
import org.springframework.web.bind.annotation.*;
@RestController
public class LogCtl2 {
  @GetMapping("/event")
  public String event(@RequestParam String user) {
    Logger.getLogger("app").warning("event user=" + user);
    return "ok";
  }
}
`;
    const r = await analyze(code, 'LogCtl2.java', 'java');
    expect(countLogFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — Logger.warning with constant message produces zero log_injection', async () => {
    const code = `package com.example;
import java.util.logging.Logger;
public class Boot {
  private static final Logger logger = Logger.getLogger("app");
  public static void main(String[] args) {
    logger.warning("startup complete");
  }
}
`;
    const r = await analyze(code, 'Boot.java', 'java');
    expect(countLogFlows(r.taint?.flows)).toBe(0);
  });
});
