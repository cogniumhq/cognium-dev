/**
 * #1308 — Java records and enum members in the type extraction.
 *
 *   - An enum's methods, constructors and fields sit in
 *     `enum_body_declarations`, below the `enum_body` the default path walks,
 *     so the default output declared none of them.
 *   - A record's compact constructor (`P { … }`) is a
 *     `compact_constructor_declaration`, which no path extracted.
 *
 * Records themselves stay behind `navigationTypes` until the resolver's
 * name-only fallback is fixed (see the hold on #1308).
 *
 * Fixtures in `tests/fixtures/java-enum-body/`, read through `analyze()` with
 * default options:
 *   - Op.java    — constants with their own bodies, a static map and
 *                  initializer, a constructor, an abstract method, a static
 *                  factory
 *   - Shape.java — a class with a nested enum that declares members
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { initParser, parse } from '../../src/core/parser.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/java-enum-body');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

const ENUM = `
package app;

public enum Kind {
    A(1), B(2);

    private final int code;

    Kind(int code) {
        this.code = code;
    }

    public static Kind fromInt(int i) {
        return i == 1 ? A : B;
    }
}
`;

const RECORD = `
package app;

public record Endpoint(String host, int port) {
    public Endpoint {
        if (port < 0) throw new IllegalArgumentException(host);
    }

    public String url() {
        return host + ":" + port;
    }
}
`;

describe('#1308 Java enum members and record constructors', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('declares an enum\'s methods, constructor and fields in the default output', async () => {
    const types = extractTypes(await parse(ENUM, 'java'), undefined, 'java');
    const kind = types.find(t => t.name === 'Kind');
    expect(kind?.kind).toBe('enum');

    const fromInt = kind!.methods.find(m => m.name === 'fromInt');
    expect(fromInt).toMatchObject({ return_type: 'Kind', start_line: 13, end_line: 15 });
    expect(fromInt!.parameters.map(p => [p.name, p.type])).toEqual([['i', 'int']]);
    expect(fromInt!.modifiers).toEqual(expect.arrayContaining(['public', 'static']));

    const ctor = kind!.methods.find(m => m.name === 'Kind');
    expect(ctor).toMatchObject({ return_type: null, start_line: 9, end_line: 11 });
    expect(ctor!.parameters.map(p => [p.name, p.type])).toEqual([['code', 'int']]);

    expect(kind!.fields.map(f => [f.name, f.type])).toEqual([['code', 'int']]);
  });

  it('declares each enum member once under navigationTypes', async () => {
    const types = extractTypes(await parse(ENUM, 'java'), undefined, 'java', { navigationTypes: true });
    const kind = types.find(t => t.name === 'Kind')!;
    expect(kind.methods.map(m => m.name).sort()).toEqual(['Kind', 'fromInt']);
    expect(kind.fields.map(f => f.name)).toEqual(['code']);
  });

  it('declares a record\'s compact constructor with the header\'s components', async () => {
    const types = extractTypes(await parse(RECORD, 'java'), undefined, 'java', { navigationTypes: true });
    const rec = types.find(t => t.name === 'Endpoint');
    expect(rec?.is_record).toBe(true);

    const ctors = rec!.methods.filter(m => m.name === 'Endpoint');
    expect(ctors).toHaveLength(1);
    expect(ctors[0]).toMatchObject({ return_type: null, start_line: 5, end_line: 7 });
    expect(ctors[0].modifiers).toContain('public');
    expect(ctors[0].parameters.map(p => [p.name, p.type])).toEqual([['host', 'String'], ['port', 'int']]);

    // The components stay declared as fields and accessors, and the explicit
    // method is still there.
    expect(rec!.fields.map(f => f.name)).toEqual(['host', 'port']);
    expect(rec!.methods.map(m => m.name).sort()).toEqual(['Endpoint', 'host', 'port', 'url']);
  });

  it('still leaves records out of the default output', async () => {
    const types = extractTypes(await parse(RECORD, 'java'), undefined, 'java');
    expect(types.find(t => t.name === 'Endpoint')).toBeUndefined();
  });
});

describe('#1308 enum-body fixtures through analyze()', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('declares the members after the constants, and none from a constant\'s own body', async () => {
    const ir = await analyze(fixture('Op.java'), 'Op.java', 'java');
    const op = ir.types.find(t => t.name === 'Op');
    expect(op?.kind).toBe('enum');

    const sig = (m: { name: string; parameters: { type: string | null }[] }) =>
      `${m.name}(${m.parameters.map(p => p.type).join(',')})`;
    // `apply` is declared once, by the abstract method; the two overrides
    // inside ADD { … } and SUB { … } belong to the constants, not to Op.
    expect(op!.methods.map(sig).sort()).toEqual(['Op(String)', 'apply(int,int)', 'of(String)', 'symbol()']);

    const ctor = op!.methods.find(m => m.name === 'Op')!;
    expect(ctor).toMatchObject({ return_type: null, start_line: 31, end_line: 33 });
    expect(op!.methods.find(m => m.name === 'apply')!.modifiers).toContain('abstract');
    expect(op!.methods.find(m => m.name === 'of')).toMatchObject({ return_type: 'Op', start_line: 41, end_line: 47 });

    expect(op!.fields.map(f => [f.name, f.type])).toEqual([['BY_SYMBOL', 'Map<String, Op>'], ['symbol', 'String']]);
  });

  it('declares a nested enum\'s members on the enum, not on the enclosing class', async () => {
    const ir = await analyze(fixture('Shape.java'), 'Shape.java', 'java');
    const kind = ir.types.find(t => t.name === 'Kind');
    const shape = ir.types.find(t => t.name === 'Shape');
    expect(kind?.kind).toBe('enum');

    expect(kind!.methods.map(m => [m.name, m.start_line]).sort()).toEqual([['Kind', 10], ['sides', 14]]);
    expect(kind!.fields.map(f => f.name)).toEqual(['sides']);

    expect(shape!.methods.map(m => [m.name, m.start_line]).sort()).toEqual([['Shape', 21], ['sides', 25]]);
    expect(shape!.fields.map(f => f.name)).toEqual(['kind']);
  });
});
