/**
 * Functions a JS/TS module exports under a key rather than a declared name
 * are `<module>` methods named by that key, and the calls inside them carry
 * that name as `in_method`, so a call from another file can be resolved to
 * them and the calls in their bodies are attributed to them.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { extractCalls } from '../../src/core/extractors/calls.js';

async function moduleMethods(code: string, language: 'javascript' | 'typescript' = 'javascript') {
  const tree = await parse(code, language);
  const types = extractTypes(tree, undefined, language);
  return types.find(t => t.name === '<module>')?.methods ?? [];
}

async function inMethodOf(code: string, callee: string, language: 'javascript' | 'typescript' = 'javascript') {
  const tree = await parse(code, language);
  return extractCalls(tree, undefined, language).find(c => c.method_name === callee)?.in_method ?? null;
}

describe('JS/TS module export functions', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('CommonJS `exports.fn = (…) => …` and `module.exports.fn = function …`', async () => {
    const code = `exports.runPing = (host, cb) => {
  exec('ping ' + host, cb);
};
module.exports.lookup = function (name) {
  return dns(name);
};
`;
    const methods = await moduleMethods(code);
    const run = methods.find(m => m.name === 'runPing');
    expect(run?.parameters.map(p => p.name)).toEqual(['host', 'cb']);
    expect([run?.start_line, run?.end_line]).toEqual([1, 3]);
    expect(methods.find(m => m.name === 'lookup')?.parameters.map(p => p.name)).toEqual(['name']);
    expect(await inMethodOf(code, 'exec')).toBe('runPing');
    expect(await inMethodOf(code, 'dns')).toBe('lookup');
  });

  it('the function-valued properties and methods of `module.exports = { … }`', async () => {
    const code = `function shared(x) { return x; }
module.exports = {
  shared,
  list: (req, res) => {
    query(req.query.q);
  },
  async show(req) {
    fetchOne(req.params.id);
  },
  'remove': function (id) { drop(id); },
  limit: 10,
};
`;
    const methods = await moduleMethods(code);
    expect(methods.map(m => m.name).sort()).toEqual(['list', 'remove', 'shared', 'show']);
    expect(methods.find(m => m.name === 'show')?.modifiers).toContain('async');
    expect(await inMethodOf(code, 'query')).toBe('list');
    expect(await inMethodOf(code, 'fetchOne')).toBe('show');
    expect(await inMethodOf(code, 'drop')).toBe('remove');
  });

  it('`module.exports = function …`: its own name, else `default`', async () => {
    expect((await moduleMethods('module.exports = function (a) { run(a); };\n')).map(m => m.name)).toEqual(['default']);
    expect(await inMethodOf('module.exports = function (a) { run(a); };\n', 'run')).toBe('default');
    expect((await moduleMethods('module.exports = function ping(a) { run(a); };\n')).map(m => m.name)).toEqual(['ping']);
    expect(await inMethodOf('module.exports = (a) => run(a);\n', 'run')).toBe('default');
  });

  it('an anonymous ES default export and `export default { … }`', async () => {
    const fn = "export default function (a: string) { run(a); }\n";
    expect((await moduleMethods(fn, 'typescript')).map(m => m.name)).toEqual(['default']);
    expect(await inMethodOf(fn, 'run', 'typescript')).toBe('default');
    const arrow = 'export default async (a: string) => { run(a); };\n';
    expect((await moduleMethods(arrow, 'typescript')).map(m => m.name)).toEqual(['default']);
    const obj = 'export default {\n  go(a: string) { run(a); },\n};\n';
    expect((await moduleMethods(obj, 'typescript')).map(m => m.name)).toEqual(['go']);
    expect(await inMethodOf(obj, 'run', 'typescript')).toBe('go');
  });

  it('a top-level `const f = function (…) {…}` is a module method like an arrow', async () => {
    const methods = await moduleMethods('const f = function (x) { run(x); };\nconst g = (y) => run(y);\n');
    expect(methods.map(m => m.name).sort()).toEqual(['f', 'g']);
  });

  it('nested and non-function shapes add nothing', async () => {
    const code = `function setup() {
  exports.inner = (x) => run(x);
}
exports.value = compute();
module.exports.handler = wrap((x) => run(x));
const app = { list: (x) => run(x) };
`;
    const methods = await moduleMethods(code);
    expect(methods.map(m => m.name)).toEqual(['setup']);
    // The wrapped arrow is not an exported function: no exported name.
    const tree = await parse(code, 'javascript');
    const inMethods = extractCalls(tree, undefined, 'javascript').filter(c => c.method_name === 'run').map(c => c.in_method);
    expect(inMethods).not.toContain('handler');
    expect(inMethods).not.toContain('list');
  });

  it('an exported key that a declared function already uses is not added twice', async () => {
    const methods = await moduleMethods('function run(a) { go(a); }\nexports.run = (a) => run(a);\n');
    expect(methods.filter(m => m.name === 'run')).toHaveLength(1);
  });
});
