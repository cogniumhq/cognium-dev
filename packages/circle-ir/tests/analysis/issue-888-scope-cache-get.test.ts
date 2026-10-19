/**
 * cognium-dev #888 — in-memory `scope.cache.get` must not seed db_input (THREE.js loader shape).
 */
import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

const dbInputSources = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.sources ?? []).filter(s => s.type === 'db_input');

describe('#888 scope.cache.get db_input filter', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('scope.cache.get on an object property is not db_input', async () => {
    const code = `function Loader() {
  this.cache = {};
}
Loader.prototype.load = function (url) {
  var scope = this;
  var cached = scope.cache.get(url);
  console.log(cached);
};
`;
    const r = await analyze(code, 'loader_cache.js', 'javascript');
    expect(dbInputSources(r)).toHaveLength(0);
  });

  it('createClient-bound cache.get stays db_input (src14)', async () => {
    const code = `const { exec } = require('child_process');
const { createClient } = require('redis');
const cache = createClient();

async function runJob() {
  const val = await cache.get('user:cmd');
  exec('sh -c ' + val);
}
module.exports = { runJob };
`;
    const r = await analyze(code, 'redis_cache.js', 'javascript');
    expect(dbInputSources(r).length).toBeGreaterThan(0);
  });
});
