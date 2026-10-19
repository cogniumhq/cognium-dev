/**
 * cognium-dev #818 — taint-coverage channel axis: module-exported transport
 * handlers must keep parameter-sourced flows past the #292 gate.
 *
 * Fixtures are hand-written mirrors of the channel shapes (not copied from
 * javascript-vuln-demo).
 */
import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

const hasCmdFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).some(f => f.sink_type === 'command_injection');

const hasSqlFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).some(f => f.sink_type === 'sql_injection');

describe('#818 channel exported handlers', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('serverless handler(event) with event field reaches exec', async () => {
    const code = `const { exec } = require('child_process');
function handler(event) {
  exec('grep ' + (event.q || ''), () => {});
}
module.exports = { handler };
`;
    const r = await analyze(code, 'serverless_evt.js', 'javascript');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('webhook onWebhook(event) reaches execSync', async () => {
    const code = `const { execSync } = require('child_process');
function onWebhook(event) {
  const name = event.repository.name;
  execSync('git clone /srv/' + name);
}
module.exports = { onWebhook };
`;
    const r = await analyze(code, 'webhook_evt.js', 'javascript');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('mqtt onMessage(topic, payload) reaches execSync', async () => {
    const code = `const { execSync } = require('child_process');
function onMessage(topic, payload) {
  const cmd = payload.toString();
  execSync('handle ' + cmd);
}
module.exports = { onMessage };
`;
    const r = await analyze(code, 'mqtt_msg.js', 'javascript');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('grpc-style handle(req) reaches exec', async () => {
    const code = `const { exec } = require('child_process');
function handle(req) { exec('echo ' + req.payload, () => {}); }
module.exports = { handle };
`;
    const r = await analyze(code, 'grpc_handle.js', 'javascript');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('graphql resolveUser args reach sqlite query', async () => {
    const code = `const sqlite3 = require('sqlite3');
function resolveUser(_, { id }) {
  const q = id;
  new sqlite3.Database(':memory:').all("SELECT * FROM u WHERE id='" + q + "'");
}
module.exports = { resolveUser };
`;
    const r = await analyze(code, 'gql_resolver.js', 'javascript');
    expect(hasSqlFlow(r)).toBe(true);
  });

  it('typescript export function onWebhook(event) reaches execSync', async () => {
    const code = `import { execSync } from 'child_process';
export function onWebhook(event: { repository: { name: string } }) {
  execSync('git clone /srv/' + event.repository.name);
}
`;
    const r = await analyze(code, 'webhook_evt.ts', 'typescript');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('typescript export { handler } with typed event reaches exec', async () => {
    const code = `import { exec } from 'child_process';
function handler(event: { q?: string }) {
  exec('grep ' + (event.q || ''), () => {});
}
export { handler };
`;
    const r = await analyze(code, 'serverless_evt.ts', 'typescript');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('rust #[post] handler with DTO param reaches command_injection', async () => {
    const code = `use std::process::Command;

#[post("/webhook")]
fn on_webhook(event: WebhookEvent) -> HttpResponse {
    let name = event.name;
    Command::new("sh").arg("-c").arg(format!("git clone /srv/{}", name)).spawn();
    HttpResponse::Ok()
}
struct WebhookEvent { name: String }
`;
    const r = await analyze(code, 'webhook_evt.rs', 'rust');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('rust HttpResponse handler without route attr keeps DTO param flow', async () => {
    const code = `use std::process::Command;

pub fn handle(req: RequestPayload) -> HttpResponse {
    let cmd = req.payload;
    Command::new("sh").arg("-c").arg(format!("handle {}", cmd)).spawn();
    HttpResponse::Ok()
}

struct RequestPayload {
    payload: String,
}
`;
    const r = await analyze(code, 'grpc_handle.rs', 'rust');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('negative: rust helper with DTO param stays gated', async () => {
    const code = `use std::process::Command;

fn run_job(event: WebhookEvent) {
    Command::new("sh").arg("-c").arg(format!("ls {}", event.name)).spawn();
}

struct WebhookEvent {
    name: String,
}
`;
    const r = await analyze(code, 'run_job.rs', 'rust');
    expect(hasCmdFlow(r)).toBe(false);
  });

  it('negative: exported runJob with arbitrary params stays gated', async () => {
    const code = `const { exec } = require('child_process');
function runJob(a, b) { exec('ls ' + a); }
module.exports = { runJob };
`;
    const r = await analyze(code, 'run_job.js', 'javascript');
    expect(hasCmdFlow(r)).toBe(false);
  });
});
