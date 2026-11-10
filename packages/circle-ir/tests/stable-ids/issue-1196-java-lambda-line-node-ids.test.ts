/**
 * cognium-dev#1196 — Java DFG defs/uses on a line shared with a lambda carry column
 * so node ids stay under the method body, not the lambda.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { assignNodeIds, deriveStableIds, type StableDecl } from '../../src/stable-ids/index.js';

const HOST = [
  'package app;',
  'import java.util.function.Function;',
  'public class Host {',
  '  public String run(String input) {',
  '    String tagged = input; Function<String, String> fn = (x) -> x.trim(); return tagged + fn.apply("z");',
  '  }',
  '}',
  '',
].join('\n');

beforeAll(async () => {
  await initAnalyzer();
});

describe('cognium-dev#1196 — Java lambda same-line DFG node ids', () => {
  it('places tagged def/use under run; lambda x def/use under the lambda', async () => {
    const file = 'src/app/Host.java';
    const ir = await analyze(HOST, file, 'java');
    const ids = await deriveStableIds(HOST, file, 'java');
    const nodes = assignNodeIds(ids, ir);

    const run = ids.decls.find((d) => d.qualified_name === 'app:Host.run' && !d.flags.includes('unstable:anonymous'));
    const lambda = ids.decls.find((d) => d.flags.includes('unstable:anonymous'));
    expect(run, 'run method decl').toBeDefined();
    expect(lambda, 'lambda decl').toBeDefined();
    expect(run!.body_id).not.toBe(lambda!.body_id);

    const taggedDef = ir.dfg.defs.find((d) => d.variable === 'tagged');
    const taggedUse = ir.dfg.uses.find((u) => u.variable === 'tagged');
    expect(taggedDef?.column, 'tagged def column').toEqual(expect.any(Number));
    expect(taggedUse?.column, 'tagged use column').toEqual(expect.any(Number));

    const xDef = ir.dfg.defs.find((d) => d.variable === 'x');
    const xUse = ir.dfg.uses.find((u) => u.variable === 'x');
    expect(xDef?.column, 'x def column').toEqual(expect.any(Number));
    expect(xUse?.column, 'x use column').toEqual(expect.any(Number));

    const idOf = (kind: 'dfg_defs' | 'dfg_uses', idx: number) => nodes[kind][idx];

    const taggedDefIdx = ir.dfg.defs.indexOf(taggedDef!);
    const taggedUseIdx = ir.dfg.uses.indexOf(taggedUse!);
    const xDefIdx = ir.dfg.defs.indexOf(xDef!);
    const xUseIdx = ir.dfg.uses.indexOf(xUse!);

    expect(idOf('dfg_defs', taggedDefIdx), 'tagged def node id').toMatch(new RegExp(`^${run!.body_id}/d`));
    expect(idOf('dfg_uses', taggedUseIdx), 'tagged use node id').toMatch(new RegExp(`^${run!.body_id}/u`));
    expect(idOf('dfg_defs', xDefIdx), 'x def node id').toMatch(new RegExp(`^${lambda!.body_id}/d`));
    expect(idOf('dfg_uses', xUseIdx), 'x use node id').toMatch(new RegExp(`^${lambda!.body_id}/u`));
  });
});
