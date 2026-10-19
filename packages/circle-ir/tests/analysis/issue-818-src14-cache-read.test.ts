/**
 * cognium-dev #818 — src14 axis: second-order cache/redis read reaches cmd sink.
 */
import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

const hasCmdFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).some(f => f.sink_type === 'command_injection');

describe('#818 src14 cache read source', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('createClient().get return reaches exec (src14 shape)', async () => {
    const code = `const { exec } = require('child_process');
const { createClient } = require('redis');
const cache = createClient();

async function runJob() {
  const val = await cache.get('user:cmd');
  exec('sh -c ' + val);
}
module.exports = { runJob };
`;
    const r = await analyze(code, 'cache_src14.js', 'javascript');
    expect(hasCmdFlow(r)).toBe(true);
  });

  it('negative: Map.get stays clean (not a cache read source)', async () => {
    const code = `const { exec } = require('child_process');
const cache = new Map();

function runJob() {
  const val = cache.get('key');
  exec('sh -c ' + val);
}
module.exports = { runJob };
`;
    const r = await analyze(code, 'map_not_cache.js', 'javascript');
    expect(hasCmdFlow(r)).toBe(false);
  });
});
