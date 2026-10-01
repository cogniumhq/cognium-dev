/**
 * End-to-end over the real transport, against the built output.
 *
 * Two things only this test can prove:
 *
 *   1. `dist/bin.js` still serves — the bin was renamed from `index.js` in
 *      this change, and nothing else here would notice if it broke.
 *   2. `dist/index.js` has no side effects — importing the package used to
 *      attach a stdio transport to the host process, which is exactly what
 *      stopped it being mountable over HTTP. A regression would be invisible
 *      to every other test in this suite, because they import from `src`.
 *
 * It drives raw newline-delimited JSON-RPC rather than the SDK client, so the
 * wire format is asserted as a client would actually see it.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = resolve(pkgRoot, 'dist/bin.js');
const LIB = resolve(pkgRoot, 'dist/index.js');

beforeAll(() => {
  if (!existsSync(BIN) || !existsSync(LIB)) {
    execFileSync('npm', ['run', 'build'], { cwd: pkgRoot, stdio: 'pipe' });
  }
}, 120_000);

interface Exchange {
  readonly responses: ReadonlyArray<Record<string, unknown>>;
  readonly stderr: string;
}

/** Spawn the bin, send the requests, collect what comes back. */
function exchange(requests: ReadonlyArray<unknown>, env: NodeJS.ProcessEnv = {}): Promise<Exchange> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [BIN], {
      env: { ...process.env, COGNIUM_CONFIG_DIR: '/nonexistent/cognium-smoke', ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`timed out; stdout so far: ${stdout}\nstderr: ${stderr}`));
    }, 30_000);

    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString();
    });
    child.on('error', reject);
    child.on('close', () => {
      clearTimeout(timer);
      const responses = stdout
        .split('\n')
        .filter((line) => line.trim() !== '')
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      resolvePromise({ responses, stderr });
    });

    for (const req of requests) child.stdin.write(`${JSON.stringify(req)}\n`);
    child.stdin.end();
  });
}

const INITIALIZE = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'phase-1-smoke', version: '0' },
  },
};
const INITIALIZED = { jsonrpc: '2.0', method: 'notifications/initialized' };
const TOOLS_LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list' };

const FLOOR_TOOLS = [
  'attack_surface_summary',
  'check_sanitizer',
  'describe_sink',
  'describe_source',
  'explain_finding',
  'find_similar',
  'list_entry_points',
  'list_reachable_sinks',
  'refresh',
  'scan',
  'taint_paths',
];

describe('the built bin over stdio', () => {
  it('completes a handshake and lists the 11 floor tools', async () => {
    const { responses } = await exchange([INITIALIZE, INITIALIZED, TOOLS_LIST]);

    const init = responses.find((r) => r.id === 1);
    expect(init, 'no initialize response').toBeTruthy();
    const initResult = init!.result as { serverInfo: { name: string; version: string } };
    expect(initResult.serverInfo.name).toBe('@cognium/mcp-server');
    // Identity now comes from the manifest, so the handshake reports the real
    // package version rather than a literal that had drifted to 0.1.0.
    const { version } = JSON.parse(readFileSync(resolve(pkgRoot, 'package.json'), 'utf8')) as { version: string };
    expect(initResult.serverInfo.version).toBe(version);

    const list = responses.find((r) => r.id === 2);
    expect(list, 'no tools/list response').toBeTruthy();
    const tools = (list!.result as { tools: Array<{ name: string; inputSchema: unknown }> }).tools;
    expect(tools.map((t) => t.name).sort()).toEqual(FLOOR_TOOLS);

    // Every tool's inputSchema has to be a JSON Schema object, which is what
    // a client validates against before it will call anything.
    for (const tool of tools) {
      expect(tool.inputSchema, `${tool.name} has no inputSchema`).toBeTruthy();
      expect((tool.inputSchema as { type?: string }).type).toBe('object');
    }
  }, 60_000);

  it('writes one startup line, naming the licence state, to stderr and not to stdout', async () => {
    const { responses, stderr } = await exchange([INITIALIZE, INITIALIZED, TOOLS_LIST]);
    const lines = stderr.trim().split('\n').filter((l) => l.trim() !== '');

    expect(lines[0]).toContain('[@cognium/mcp-server]');
    expect(lines[0]).toContain('licence floor');
    expect(lines[0]).toContain('modules none');

    // stdout must stay pure JSON-RPC; a stray log line there corrupts the
    // stream for every client.
    expect(responses.length).toBeGreaterThan(0);
  }, 60_000);

  it('serves the floor when the module specifier cannot resolve', async () => {
    const { responses, stderr } = await exchange([INITIALIZE, INITIALIZED, TOOLS_LIST], {
      COGNIUM_MCP_MODULES: 'definitely-not-installed/mcp',
    });
    const list = responses.find((r) => r.id === 2);
    const tools = (list!.result as { tools: Array<{ name: string }> }).tools;
    expect(tools.map((t) => t.name).sort()).toEqual(FLOOR_TOOLS);
    expect(stderr).toContain('licence floor');
  }, 60_000);
});

describe('the built library entry', () => {
  it('imports without attaching a transport, and exits', () => {
    // If `index.js` still bootstrapped stdio, this process would connect a
    // server to its own stdin and never exit — the failure mode that made
    // the package unmountable. `execFileSync` would then time out.
    const out = execFileSync(
      process.execPath,
      [
        '-e',
        `const m = await import(${JSON.stringify(LIB)});
         process.stdout.write([typeof m.buildServer, typeof m.createServer, typeof m.verifyLicence, m.SERVER_NAME].join(','));`,
      ],
      { timeout: 30_000, stdio: 'pipe' },
    ).toString();

    expect(out).toBe('function,function,function,@cognium/mcp-server');
  }, 60_000);

  it('builds a floor server when imported and called, with no process state touched', () => {
    const out = execFileSync(
      process.execPath,
      [
        '-e',
        `const m = await import(${JSON.stringify(LIB)});
         const s = m.buildServer();
         const names = Object.keys(s._registeredTools ?? {});
         process.stdout.write(String(names.length));`,
      ],
      { timeout: 30_000, stdio: 'pipe' },
    ).toString();

    expect(out).toBe('11');
  }, 60_000);
});
