/**
 * h3 / Nitro / Nuxt server routes read the request through utilities that
 * take the handler's `event` (`getQuery(event)`, `readBody(event)`,
 * `getRouterParam(event, 'id')`, …). Inside `defineEventHandler(...)` or
 * `eventHandler(...)` those reads are taint sources; validated reads are
 * still attacker input. The same names called on something else, or outside
 * an event handler, are not.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function cmdFlows(code: string): Promise<Array<[number, number]>> {
  const r = await analyze(code, 'server/api/ping.get.ts', 'typescript');
  return r.taint.flows
    .filter(f => f.sink_type === 'command_injection')
    .map(f => [f.source_line, f.sink_line] as [number, number]);
}

const IMPORTS = "import { defineEventHandler, eventHandler, getQuery, readBody, readRawBody, readFormData, readMultipartFormData, readValidatedBody, getValidatedQuery, getRouterParam, getRouterParams, getHeader, getHeaders, getCookie, parseCookies, H3Event } from 'h3';\nimport { exec, execSync } from 'node:child_process';\n";

describe('h3 event handler request inputs are taint sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('getQuery(event) through a derived local', async () => {
    expect(await cmdFlows(`${IMPORTS}
export default defineEventHandler((event) => {
  const query = getQuery(event);
  const host = String(query.host || '');
  return execSync(\`ping -c 1 \${host}\`).toString();
});
`)).toEqual([[5, 7]]);
  });

  it('each request reader, with eventHandler and a typed event parameter', async () => {
    const reads: Array<[string, string]> = [
      ['const { cmd } = await readBody(event);', 'cmd'],
      ['const raw = await readRawBody(event);', 'raw'],
      ['const form = await readFormData(event);', 'form.get("x")'],
      ['const parts = await readMultipartFormData(event);', 'parts[0].filename'],
      ['const id = getRouterParam(event, "id");', 'id'],
      ['const params = getRouterParams(event);', 'params.id'],
      ['const name = getHeader(event, "x-name");', 'name'],
      ['const headers = getHeaders(event);', 'headers.host'],
      ['const tok = getCookie(event, "tok");', 'tok'],
      ['const cookies = parseCookies(event);', 'cookies.tok'],
    ];
    for (const [read, use] of reads) {
      const code = `${IMPORTS}
export default eventHandler(async (event: H3Event) => {
  ${read}
  exec('echo ' + ${use});
});
`;
      expect(await cmdFlows(code), read).toContainEqual([5, 6]);
    }
  });

  it('validated reads are still attacker input', async () => {
    expect(await cmdFlows(`${IMPORTS}
export default defineEventHandler(async (event) => {
  const body = await readValidatedBody(event, (b) => b as { file: string });
  const q = await getValidatedQuery(event, (x) => x as { dir: string });
  exec('cat ' + body.file);
  exec('ls ' + q.dir);
});
`)).toEqual([[5, 7], [6, 8]]);
  });

  it('the object form `defineEventHandler({ handler })` and an inline read', async () => {
    expect(await cmdFlows(`${IMPORTS}
export default defineEventHandler({
  onRequest: [],
  handler: async (evt) => {
    execSync('ping -c 1 ' + getQuery(evt).host);
  },
});
`)).toEqual([[7, 7]]);
  });

  it('NEGATIVE: the same utility called on something other than the event', async () => {
    expect(await cmdFlows(`${IMPORTS}
export default defineEventHandler((event) => {
  const defaults = { host: 'localhost' };
  const q = getQuery(defaults);
  exec('ping -c 1 ' + q.host);
});
`)).toEqual([]);
  });

  it('NEGATIVE: a read outside an event handler', async () => {
    expect(await cmdFlows(`${IMPORTS}
export function helper(event: H3Event) {
  const q = getQuery(event);
  exec('ping -c 1 ' + q.host);
}
`)).toEqual([]);
  });

  it('NEGATIVE: a sink that does not use the request input', async () => {
    expect(await cmdFlows(`${IMPORTS}
export default defineEventHandler((event) => {
  const q = getQuery(event);
  exec('ping -c 1 localhost');
  return q;
});
`)).toEqual([]);
  });
});
