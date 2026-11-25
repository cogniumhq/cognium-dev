/**
 * cognium-dev#1308 — Java method references (`Foo::bar`) are call sites in
 * `ir.calls`, each with its form (`reference_form`).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { analyze } from '../../src/analyzer.js';
import type { CallInfo } from '../../src/types/index.js';

const SOURCE = `package app;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class Refs extends Base {
    void run(List<String> xs) {
        xs.forEach(System.out::println);
        xs.stream().map(String::length).map(this::twice).map(super::shift).count();
        Supplier<Box> s = Box::new;
        Object o = xs.stream().collect(Collectors.toCollection(java.util.LinkedList::new));
        String[] a = xs.stream().toArray(String[]::new);
    }

    int twice(int n) { return n * 2; }
}
`;

const refs = (calls: CallInfo[]) => calls.filter(c => c.reference_form !== undefined);

describe('#1308 Java method references are call sites', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('extracts each method reference with its form, receiver and enclosing method', async () => {
    const calls = extractCalls(await parse(SOURCE, 'java'));
    const got = refs(calls).map(c => [c.reference_form, c.receiver, c.method_name, c.location.line, c.in_method]);
    expect(got).toEqual([
      ['method', 'System.out', 'println', 9, 'run'],
      ['method', 'String', 'length', 10, 'run'],
      ['method', 'this', 'twice', 10, 'run'],
      ['super', 'super', 'shift', 10, 'run'],
      ['constructor', null, 'Box', 11, 'run'],
      ['constructor', null, 'java.util.LinkedList', 12, 'run'],
    ]);
    for (const c of refs(calls)) expect(c.arguments).toEqual([]);
  });

  it('resolves them like the matching invocation or constructor call', async () => {
    const calls = refs(extractCalls(await parse(SOURCE, 'java')));
    const byName = new Map(calls.map(c => [c.method_name, c]));
    expect(byName.get('twice')?.resolution).toEqual({ status: 'resolved', target: 'Refs.twice' });
    expect(byName.get('twice')?.receiver_type).toBe('Refs');
    expect(byName.get('length')?.receiver_type).toBe('String');
    expect(byName.get('Box')?.resolution).toEqual({ status: 'resolved', target: 'Box.<init>' });
    expect(byName.get('Box')?.receiver_type).toBe('Box');
  });

  it('does not count an array constructor reference (`T[]::new`)', async () => {
    const calls = extractCalls(await parse(SOURCE, 'java'));
    expect(calls.some(c => c.location.line === 13 && c.reference_form !== undefined)).toBe(false);
    expect(calls.some(c => c.method_name.includes('[]'))).toBe(false);
  });

  it('leaves invocations without a form', async () => {
    const calls = extractCalls(await parse(SOURCE, 'java'));
    const forEach = calls.find(c => c.method_name === 'forEach');
    expect(forEach).toBeDefined();
    expect(forEach?.reference_form).toBeUndefined();
  });

  it('appears in the default analyze() output', async () => {
    const ir = await analyze(SOURCE, 'app/Refs.java', 'java');
    expect(refs(ir.calls).map(c => `${c.reference_form}:${c.method_name}`)).toEqual([
      'method:println', 'method:length', 'method:twice', 'super:shift',
      'constructor:Box', 'constructor:java.util.LinkedList',
    ]);
  });
});
