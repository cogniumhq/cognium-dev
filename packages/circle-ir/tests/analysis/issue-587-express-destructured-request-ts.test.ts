/**
 * cognium-dev#587, TypeScript slice: an Express handler whose first parameter
 * destructures the request with a type annotation —
 * `({ query }: Request, res: Response) => …` — seeds the request sources, as
 * the JS form does. Fastify / Koa stay out of scope.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const routes = `import express, { Request, Response } from "express";
import { exec } from "child_process";

const server = express();

server.get("/dig", ({ query }: Request, res: Response) => {
  const domain = query.domain as string;
  exec("dig " + domain, (err, out) => res.send(out));
});

server.get("/whois", ({ params }: Request, res: Response) => {
  exec("whois " + params.domain, (err, out) => res.send(out));
});
`;

const safe = `import express, { Request } from "express";
import { exec } from "child_process";

const server = express();
const runLater = (fn: (req: Request) => void) => fn({ query: { domain: "example.com" } } as unknown as Request);

runLater(({ query }: Request) => {
  exec("dig " + query.domain, () => {});
});
`;

async function sinkLines(code: string, file: string, type: string) {
  const r = await analyze(code, file, 'typescript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort((a, b) => a - b);
}

describe('#587 TypeScript: destructured Express request parameter', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('typed destructured query / params fire command_injection at 8 and 12', async () => {
    expect(await sinkLines(routes, 'lookup_routes.ts', 'command_injection')).toEqual([8, 12]);
  });

  it('a typed destructured callback that is not an Express handler stays clean', async () => {
    expect(await sinkLines(safe, 'lookup_safe.ts', 'command_injection')).toEqual([]);
  });

  it('generic request type, aliased and nested patterns fire', async () => {
    const code = `import express, { Request, Response } from "express";
import { exec } from "child_process";
const app = express();
app.post("/a", async ({ body }: Request<{}, {}, { cmd: string }>, res: Response) => {
  exec(body.cmd, () => res.end());
});
app.get("/b", ({ query: q }: Request, res: Response) => {
  exec("ls " + q.dir, () => res.end());
});
app.get("/c", ({ query: { target } }: Request, res: Response) => {
  exec("ping " + target, () => res.end());
});
`;
    expect(await sinkLines(code, 'more_routes.ts', 'command_injection')).toEqual([5, 8, 11]);
  });

  it('a non-request key with a type annotation stays clean', async () => {
    const code = `import express, { Request, Response } from "express";
import { exec } from "child_process";
const app = express();
app.get("/env", ({ app: inner }: Request, res: Response) => {
  exec("echo " + inner.get("env"), () => res.end());
});
`;
    expect(await sinkLines(code, 'env_route.ts', 'command_injection')).toEqual([]);
  });

  it('a typed handler with a constant command stays clean', async () => {
    const code = `import express, { Request, Response } from "express";
import { exec } from "child_process";
const app = express();
app.get("/uptime", ({ query }: Request, res: Response) => {
  const unused = query.x;
  exec("uptime", () => res.end());
});
`;
    expect(await sinkLines(code, 'uptime.ts', 'command_injection')).toEqual([]);
  });

  it('the untyped pattern in a .ts file fires too', async () => {
    const code = `import express from "express";
import { exec } from "child_process";
const app = express();
app.get("/x", ({ query }, res) => {
  exec("echo " + query.v, () => res.end());
});
`;
    expect(await sinkLines(code, 'untyped.ts', 'command_injection')).toEqual([5]);
  });
  it('a receiver declared with a type annotation is an Express receiver', async () => {
    const code = `import express, { Express, Request, Response } from "express";
import { exec } from "child_process";
const web: Express = express();
web.get("/x", ({ query }: Request, res: Response) => {
  exec("echo " + query.v, () => res.end());
});
`;
    expect(await sinkLines(code, 'typed_receiver.ts', 'command_injection')).toEqual([5]);
  });
});
