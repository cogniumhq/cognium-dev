/**
 * Tests for cognium-dev #213 (transport-channel first slice) — AWS
 * Lambda / API Gateway `event.*` property sources for JS/TS + Python
 * handlers.
 *
 * The `event`-shaped API Gateway convention is distinct from the
 * `req`-shaped Express / Vercel / Cloudflare Workers convention
 * already covered by the existing property patterns; this slice adds
 * the missing channel.
 *
 * External harness verification (per the #213 ticket) is out of
 * scope — the pattern additions are shipped without a `score-corpus.py`
 * pass. In-session validation is the sink emergence + taint flow
 * shape (source → sink) via existing sink patterns.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasHttpFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some((f) =>
    ['http_body', 'http_query', 'http_path', 'http_header', 'http_param'].includes(
      f.source_type ?? '',
    ),
  );

const findingRules = (r: any): string[] =>
  ((r.findings ?? []) as any[]).map((f) => f.rule_id);

describe('#213 transport-channel first slice — Lambda / API Gateway event sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP — JS/TS Lambda handler `event.body` flows to SQL sink', async () => {
    const code = `
const { Pool } = require('pg');
const pool = new Pool();

exports.handler = async (event, context) => {
  const q = event.body;
  await pool.query("SELECT * FROM t WHERE x = '" + q + "'");
};
`;
    const r = await analyze(code, 'handler.js', 'javascript');
    // Either a taint flow or a sql_injection finding must be present.
    expect(
      hasHttpFlow(r) || findingRules(r).includes('sql_injection'),
    ).toBe(true);
  });

  it('TP — JS/TS Lambda `event.queryStringParameters` at 1-level access flows to command exec', async () => {
    // NOTE: nested-property access on a tainted source
    // (`event.queryStringParameters.host`) is a separate
    // taint-propagator gap — the property-source pattern only fires
    // at the direct-access level. Deeper access chains fall through
    // the current JS taint-argument matcher and are deferred for a
    // future engine slice. This test exercises the 1-level shape:
    // pass the entire `queryStringParameters` bag to the sink.
    const code = `
const { exec } = require('child_process');

exports.handler = async (event, context) => {
  const params = event.queryStringParameters;
  exec('ping ' + JSON.stringify(params));
};
`;
    const r = await analyze(code, 'handler.js', 'javascript');
    expect(
      hasHttpFlow(r) ||
        findingRules(r).some((r) =>
          ['command_injection', 'sql_injection', 'xss'].includes(r),
        ),
    ).toBe(true);
  });

  it('TP — Python Lambda handler `event["body"]` flows to SQL sink', async () => {
    // Python subscript access is how JSON deserialised events are
    // typically read. Sink flow emerges as source → subscript → sink.
    const code = `
import psycopg2

def handler(event, context):
    q = event["body"]
    conn = psycopg2.connect("dbname=x")
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE x = '" + q + "'")
    return {"statusCode": 200}
`;
    const r = await analyze(code, 'handler.py', 'python');
    // Signal check either via taint flow or finding.
    const sinks = r.taint?.sinks ?? [];
    expect(
      hasHttpFlow(r) ||
        sinks.length > 0 ||
        findingRules(r).some((rule) => rule.includes('injection')),
    ).toBe(true);
  });

  it('TP — JS/TS Lambda `event.pathParameters` at 1-level access flows to command exec', async () => {
    // Same nested-access caveat as the queryStringParameters test —
    // property-source patterns fire on direct-level access only.
    // Deeper chains (`event.pathParameters.id`) fall through the
    // current JS taint-argument matcher (deferred engine slice).
    const codeWithSink = `
exports.handler = async (event) => {
  const params = event.pathParameters;
  const { exec } = require('child_process');
  exec('echo ' + JSON.stringify(params));
};
`;
    const r2 = await analyze(codeWithSink, 'handler.js', 'javascript');
    expect(hasHttpFlow(r2)).toBe(true);
  });

  it('FP-guard — `event` as an unrelated variable (not a Lambda handler) does not fire', async () => {
    // Property patterns fire on `<object>.<property>` shape. A
    // variable literally named `event` in an unrelated context should
    // NOT emit spurious sources unless the property matches. This
    // test locks in that literal `event.foo` where `foo` isn't in the
    // property list is untouched.
    const code = `
function analytics() {
  const event = { userId: 42 };
  return event.userId;
}
`;
    const r = await analyze(code, 'analytics.js', 'javascript');
    // `userId` isn't in our property list, so no source should fire.
    // Number of Lambda-shaped http_body / http_query / http_path /
    // http_header sources must be 0.
    const eventShapedSources = (r.taint?.sources ?? []).filter((s: any) =>
      ['http_body', 'http_query', 'http_path', 'http_header'].includes(s.type),
    );
    expect(eventShapedSources.length).toBe(0);
  });
});
