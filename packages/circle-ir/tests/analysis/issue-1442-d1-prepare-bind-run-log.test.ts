/**
 * cognium-dev #1442 — D1 / prepared-statement write: `.bind(user).run()` returns
 * metadata, not bound parameter bytes, so logging the result is not log_injection.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

const d1Worker = `
export async function onRequest({ request, env }) {
  const { email } = await request.json();
  const result = await env.DB.prepare(
    'INSERT INTO subscribers (email) VALUES (?) ON CONFLICT DO NOTHING'
  ).bind(email).run();
  console.log('Saved:', result);
}
`;

const readStillTainted = `
export async function loadUser(env, id) {
  const row = await env.DB.prepare('SELECT email FROM users WHERE id = ?').bind(id).first();
  console.log('user:', row);
}
`;

describe('#1442 prepare().bind().run() write result is not tainted', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('no log_injection flow from http_body through D1 bind().run() result', async () => {
    const r = await analyze(d1Worker, 'worker.js', 'javascript');
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'log_injection');
    expect(flows).toHaveLength(0);
    const backed = (r.taint.flows ?? []).filter(
      f => f.sink_type === 'log_injection' && (f as { flow_backed?: boolean }).flow_backed !== false,
    );
    expect(backed).toHaveLength(0);
  });

  it('parameterised SELECT read still reaches the log sink via row data', async () => {
    const r = await analyze(readStillTainted, 'read.js', 'javascript');
    const sinks = (r.taint.sinks ?? []).filter(s => s.type === 'log_injection');
    expect(sinks.length).toBeGreaterThan(0);
  });
});