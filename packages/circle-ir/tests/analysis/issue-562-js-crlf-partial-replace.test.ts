/**
 * cognium-dev#562 (minimal slice, JavaScript Stage 16): non-global
 * `.replace(/[\r\n]/, '')` and CRLF-pair-only `.replace(/\r\n/g, '')` must not
 * suppress log_injection; global `[\r\n]` strip stays credited.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sessionAudit = `const express = require("express");
const app = express();

app.get("/session-audit", (req, res) => {
  const user = req.query.user;
  const firstOnly = user.replace(/[\\r\\n]/, "");
  console.log("user=" + firstOnly);
  const pairOnly = user.replace(/\\r\\n/g, "");
  console.log("user=" + pairOnly);
  const bothGlobal = user.replace(/[\\r\\n]/g, "");
  console.log("user=" + bothGlobal);
  console.log("user=" + user);
  res.end("ok");
});
`;

describe('cognium-dev#562 JS Stage 16 partial replace credit', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('non-global and CRLF-pair-only strips report; global class strip stays clean', async () => {
    const r = await analyze(sessionAudit, 'session_audit.js', 'javascript');
    const lines = [
      ...new Set(
        (r.taint.flows ?? [])
          .filter((f) => f.sink_type === 'log_injection')
          .map((f) => f.sink_line),
      ),
    ].sort((a, b) => a - b);
    expect(lines).toEqual([7, 9, 12]);
  });
});
