/**
 * require-entry-path: more shapes of an Express handler imported into a router
 * file (cognium-dev #1323, follow-up to #1331).
 *
 * `require-entry-path-issue-1323.test.ts` covers a named import registered by
 * name. These cover a default export bound under another name, a re-export
 * through `index.ts`, a member handler on a namespace import and a handler in
 * an array argument; each was dropped by the gate before. The router's local
 * `headers` function is a JS/TS entry point, so the zero-entry-point safety
 * guard does not fire.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const HANDLER = `import { Request, Response } from "express";
import { execSync } from "child_process";

export const run = (req: Request, res: Response): void => {
  execSync("ls " + String(req.query.name));
  res.send("ok");
};
`;

const DEFAULT_HANDLER = `import { Request, Response } from "express";
import { execSync } from "child_process";

export default function run(req: Request, res: Response): void {
  execSync("ls " + String(req.query.name));
  res.send("ok");
}
`;

const router = (imports: string, registration: string) => `import { Router, Request, Response, NextFunction } from "express";
${imports}

const router = Router();
const headers = (req: Request, res: Response, next: NextFunction): void => {
  next();
};
router.use(headers);
${registration}
export default router;
`;

const cmdiFlows = async (files: Array<[string, string]>, target = 'src/handler.ts', disabledPasses?: string[]) => {
  const result = await analyzeProject(
    files.map(([filePath, code]) => ({ filePath, code, language: 'typescript' as const })),
    disabledPasses ? { disabledPasses } : {},
  );
  const fa = result.files.find(f => f.file === target);
  return (fa?.analysis.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');
};

describe('require-entry-path: default, re-exported, member and array Express handlers', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('keeps a default import', async () => {
    const flows = await cmdiFlows([
      ['src/handler.ts', DEFAULT_HANDLER],
      ['src/routes.ts', router('import runIt from "./handler";', 'router.post("/run", runIt);')],
    ]);
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('keeps a handler re-exported through index.ts', async () => {
    const flows = await cmdiFlows([
      ['src/handlers/handler.ts', HANDLER],
      ['src/handlers/index.ts', 'export { run } from "./handler";\n'],
      ['src/routes.ts', router('import { run } from "./handlers";', 'router.get("/run", run);')],
    ], 'src/handlers/handler.ts');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('keeps a member-access handler on a namespace import', async () => {
    const flows = await cmdiFlows([
      ['src/handler.ts', HANDLER],
      ['src/routes.ts', router('import * as handlers from "./handler";', 'router.get("/run", handlers.run);')],
    ]);
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('keeps a handler inside an array of middleware', async () => {
    const flows = await cmdiFlows([
      ['src/handler.ts', HANDLER],
      ['src/routes.ts', router('import { run } from "./handler";', 'router.get("/run", [headers, run]);')],
    ]);
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });

  it('still drops an exported function that is imported but not registered', async () => {
    const files: Array<[string, string]> = [
      ['src/handler.ts', HANDLER],
      ['src/routes.ts', router('import { run } from "./handler";', 'export const later = run;')],
    ];
    expect(await cmdiFlows(files)).toHaveLength(0);
    // The flow exists; only the gate removes it.
    expect((await cmdiFlows(files, 'src/handler.ts', ['require-entry-path'])).length).toBeGreaterThanOrEqual(1);
  });
});
