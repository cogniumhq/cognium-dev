/**
 * cognium-dev #539 — a conditional-compilation directive in a C# class body
 * dropped every method and field from `ir.types`.
 *
 * tree-sitter keeps a member declared inside `#if …/#endif` in the tree, but
 * nests it one level down under `preproc_if`. The extractor looped over the
 * class body's direct children looking for `method_declaration`, saw
 * `preproc_if`, and skipped it — so a class whose members are all guarded
 * contributed no methods at all.
 *
 * The damage was not cosmetic. `methods[].start_line`/`end_line` is what the
 * #361 method-scoping gate uses to refuse a source→sink pairing that crosses a
 * method boundary, so with no ranges that gate silently stopped working. Every
 * NIST Juliet C# file wraps its members in `#if (!OMITBAD)` / `#if (!OMITGOOD)`,
 * and `#if DEBUG` / `#if NET6_0_OR_GREATER` are ordinary production C#.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const run = (code: string) => analyze(code, 'P.cs', 'csharp');

const PLAIN = `
namespace T {
class A {
    private string state;
    public void Bad(string req) { var x = req; }
    private void GoodG2B(string req) { var y = "const"; }
}
}
`;

const GUARDED = `
namespace T {
class A {
#if (!OMITBAD)
    private string state;
    public void Bad(string req) { var x = req; }
#endif
#if (!OMITGOOD)
    private void GoodG2B(string req) { var y = "const"; }
#endif
}
}
`;

describe('#539 C# members inside a preprocessor directive reach ir.types', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('extracts the same method names whether or not the members are guarded', async () => {
    const plain = await run(PLAIN);
    const guarded = await run(GUARDED);

    const names = (r: Awaited<ReturnType<typeof run>>) =>
      r.types.flatMap(t => t.methods.map(m => m.name)).sort();

    expect(names(plain)).toEqual(['Bad', 'GoodG2B']);
    // The regression: this came back as [] before the fix.
    expect(names(guarded)).toEqual(['Bad', 'GoodG2B']);
  });

  it('gives every guarded method a usable line range', async () => {
    const r = await run(GUARDED);
    const methods = r.types.flatMap(t => t.methods);

    expect(methods).toHaveLength(2);
    for (const m of methods) {
      expect(m.start_line).toBeGreaterThan(0);
      expect(m.end_line).toBeGreaterThanOrEqual(m.start_line);
    }
    // Ranges must be disjoint — this is what method scoping relies on.
    const [a, b] = methods.slice().sort((x, y) => x.start_line - y.start_line);
    expect(a.end_line).toBeLessThan(b.start_line);
  });

  it('extracts a field declared inside a directive', async () => {
    const guarded = await run(GUARDED);
    const fields = guarded.types.flatMap(t => t.fields.map(f => f.name));
    expect(fields).toContain('state');
  });

  it('yields both arms of an #if/#else, since the compiled arm is not knowable here', async () => {
    const r = await run(`
namespace T {
class A {
#if NET6_0_OR_GREATER
    public void Modern(string req) { var x = req; }
#else
    public void Legacy(string req) { var x = req; }
#endif
}
}
`);
    const names = r.types.flatMap(t => t.methods.map(m => m.name)).sort();
    expect(names).toEqual(['Legacy', 'Modern']);
  });

  it('handles a nested directive', async () => {
    const r = await run(`
namespace T {
class A {
#if (!OMITBAD)
#if DEBUG
    public void Inner(string req) { var x = req; }
#endif
#endif
}
}
`);
    expect(r.types.flatMap(t => t.methods.map(m => m.name))).toEqual(['Inner']);
  });
});
