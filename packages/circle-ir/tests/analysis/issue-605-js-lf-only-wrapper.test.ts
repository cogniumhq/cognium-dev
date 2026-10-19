/**
 * cognium-dev#605 / #562 (sk57 JS): user-defined CRLF wrapper functions must use
 * the same argument-aware replace credit as inline `.replace` chains.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function logLines(code: string, file: string) {
  const r = await analyze(code, file, 'javascript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'log_injection').map((f) => f.sink_line))].sort(
    (a, b) => a - b,
  );
}

const sessionAudit = `const express = require("express");
const app = express();

function scrub(v) {
  return v.replace(/\\n/g, "");
}

function scrubBoth(v) {
  return v.replace(/\\n/g, "").replace(/\\r/g, "");
}

app.get("/session-audit", (req, res) => {
  const user = req.query.user;
  console.log("user=" + scrub(user));
  console.log("user=" + scrubBoth(user));
  res.end("ok");
});
`;

describe('cognium-dev#605 JS CRLF wrapper credit', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('LF-only helper reports log_injection; CR+LF chain helper stays clean', async () => {
    expect(await logLines(sessionAudit, 'session_audit.js')).toEqual([14]);
  });
});
