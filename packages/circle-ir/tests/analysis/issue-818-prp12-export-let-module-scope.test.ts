/**
 * cognium-dev #818 — prp12 axis: ESM `export let` module bindings written in one
 * handler and read in another (global_var propagation).
 */
import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

const pathTraversalFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal');

describe('#818 prp12 export let module scope', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('export let shared: bind in one export, read in another', async () => {
    const code = `import fs from 'fs';
export let shared;
export function bindReq(req) {
  shared = req.query.f;
}
export function useShared() {
  fs.readFileSync('./uploads/' + shared);
}
`;
    const r = await analyze(code, 'esm_shared.mjs', 'javascript');
    expect(pathTraversalFlows(r).length).toBeGreaterThan(0);
  });

  it('negative: function-local let is not module scope', async () => {
    const code = `const fs = require('fs');
export function only(req) {
  let local = req.query.f;
  fs.readFileSync('./uploads/' + local);
}
`;
    const r = await analyze(code, 'local_only.mjs', 'javascript');
    expect(pathTraversalFlows(r).length).toBeGreaterThan(0);
  });
});
