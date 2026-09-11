/**
 * cognium-dev #286 C — C# `path_traversal`: canonicalize-then-contain not credited.
 *
 * `Path.GetFileName` was the only C# path_traversal sanitizer, and it cannot
 * express the case where a legitimate subdirectory must be preserved — it
 * flattens the path. So the OWASP-canonical containment defence reported a
 * false positive:
 *
 *   var root = Path.GetFullPath("/srv/data") + Path.DirectorySeparatorChar;
 *   var full = Path.GetFullPath(Path.Combine(root, input));
 *   if (!full.StartsWith(root)) return;
 *   File.ReadAllText(full);            // reported path_traversal
 *
 * Java and JS/TS already credited their equivalents
 * (`findJavaCanonicalPathStartsWithGuardSanitizers`,
 * `findJsPathResolveStartsWithGuardSanitizers`); C# was the gap.
 *
 * Two properties matter more than the headline fix, and both have tests below.
 *
 * 1. The guarded variable must be traceable to `Path.GetFullPath(`. In Java the
 *    canonicalisation and the containment test are one expression, so matching
 *    the guard proves the value is canonical. In C# they are separate
 *    statements and the guard alone is `full.StartsWith(root)` —
 *    indistinguishable from an ordinary prefix test. Crediting on the guard
 *    alone would silence path_traversal for any
 *    `if (!name.StartsWith("safe")) return;`.
 *
 * 2. The guard must actually reject. A guard whose block opens and closes on
 *    one line without returning or throwing lets control fall through to the
 *    sink, so it is not a rejection.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const traversal = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal' && !f.sanitized);

const cs = (body: string[], cls = 'C') =>
  analyze(
    [
      'using System.IO;',
      `public class ${cls} {`,
      '    public string Read(string input) {',
      ...body.map(l => '        ' + l),
      '    }',
      '}',
    ].join('\n'),
    `${cls}.cs`,
    'csharp'
  );

const ROOT = 'var root = Path.GetFullPath("/srv/data") + Path.DirectorySeparatorChar;';
const FULL = 'var full = Path.GetFullPath(Path.Combine(root, input));';

describe('#286 C# canonicalize-then-contain is credited', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('reject guard on its own line suppresses the finding', async () => {
    const r = await cs([
      ROOT,
      FULL,
      'if (!full.StartsWith(root))',
      '    return null;',
      'return File.ReadAllText(full);',
    ], 'C1');
    expect(traversal(r).length).toBe(0);
  });

  it('reject guard with an inline return suppresses the finding', async () => {
    const r = await cs([
      ROOT,
      FULL,
      'if (!full.StartsWith(root)) { return null; }',
      'return File.ReadAllText(full);',
    ], 'C8');
    expect(traversal(r).length).toBe(0);
  });

  it('reject guard that throws suppresses the finding', async () => {
    const r = await cs([
      ROOT,
      FULL,
      'if (!full.StartsWith(root))',
      '    throw new System.Exception("escape");',
      'return File.ReadAllText(full);',
    ], 'C7');
    expect(traversal(r).length).toBe(0);
  });

  it('the same code WITHOUT a guard still fires', async () => {
    const r = await cs([
      ROOT,
      FULL,
      'return File.ReadAllText(full);',
    ], 'C2');
    expect(traversal(r).length).toBeGreaterThan(0);
  });

  it('Path.GetFileName remains credited (pre-existing control)', async () => {
    const r = await cs([
      'var name = Path.GetFileName(input);',
      'return File.ReadAllText(Path.Combine("/srv/data", name));',
    ], 'C3');
    expect(traversal(r).length).toBe(0);
  });
});

describe('#286 the guard alone must not be trusted', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a StartsWith guard on a NON-canonicalised variable still fires', async () => {
    // `name` never passes through Path.GetFullPath, so this is an ordinary
    // string prefix test and proves nothing about containment. Crediting it
    // would silence path_traversal for a huge class of unrelated code.
    const r = await cs([
      'var name = input;',
      'if (!name.StartsWith("safe"))',
      '    return null;',
      'return File.ReadAllText(Path.Combine("/srv/data", name));',
    ], 'C4');
    expect(traversal(r).length).toBeGreaterThan(0);
  });

  it('a guard that falls through to the sink still fires', async () => {
    // The block opens and closes on one line without returning or throwing, so
    // the path was never rejected. Naively scanning ahead for a terminator
    // finds the enclosing method's own `return` and credits an unguarded path
    // — a silent false negative. Caught by this fixture during development.
    const r = await cs([
      ROOT,
      FULL,
      'if (!full.StartsWith(root)) { System.Console.WriteLine("odd"); }',
      'return File.ReadAllText(full);',
    ], 'C6');
    expect(traversal(r).length).toBeGreaterThan(0);
  });

  it('the enclosing (positive) polarity is NOT credited — documented gap', async () => {
    // `if (full.StartsWith(root)) { sink; }` is equally safe, but crediting it
    // would need the credit scoped to the then-block; the whole-file credit
    // used for the reject form would also cover uses outside it. Left firing
    // deliberately, matching the Java precedent, and pinned here so the gap
    // stays visible instead of being assumed fixed.
    const r = await cs([
      ROOT,
      FULL,
      'if (full.StartsWith(root)) {',
      '    return File.ReadAllText(full);',
      '}',
      'return null;',
    ], 'C5');
    expect(traversal(r).length).toBeGreaterThan(0);
  });
});
