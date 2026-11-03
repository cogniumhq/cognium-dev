// Unit tests for the labelling rule (node --test).
import test from 'node:test';
import assert from 'node:assert/strict';
import { declarationsOf, isLabelledPath, labelPair, modulePath, summarize } from './label.mjs';

/** Label a one-file pair; returns `name -> record` (chain-qualified) plus the result. */
function one(before, after, path = 'src/a.ts') {
  const r = labelPair([{ before: path, after: path }], (side) => (side === 'before' ? before : after));
  const by = {};
  for (const x of r.records) by[(x.chain ? x.chain + '.' : '') + (x.name || '<file>')] = x;
  return { ...r, by };
}

const outcome = x => x.judgement ? `judgement:${x.judgement}` : x.label === 'stable' ? 'stable' : `changed:${x.change}`;

test('paths and module names', () => {
  assert.equal(isLabelledPath('src/a.ts'), true);
  assert.equal(isLabelledPath('src/a.tsx'), true);
  assert.equal(isLabelledPath('src/a.d.ts'), true);
  assert.equal(isLabelledPath('src/a.js'), false);
  assert.equal(isLabelledPath('node_modules/x/a.ts'), false);
  assert.equal(modulePath('src/a.d.ts'), 'src/a');
  assert.equal(modulePath('src/a.mts'), 'src/a');
  assert.equal(modulePath('src\\b.tsx'), 'src/b');
});

test('declarations: kinds, names, signatures, enclosing names', () => {
  const { decls, partial } = declarationsOf('src/a.ts', `
export function f<T>(a: T, b?: string, ...rest: number[]): void {}
export default function () {}
export class K<T> extends B {
  static s = 1;
  x?: number;
  #p = 2;
  constructor(private y: string) { super(); }
  get v(): string { return '' }
  set v(n: string) {}
  m(this: K<T>, a = 1): T { return null as any }
  ['computed']() {}
}
interface I { a: string; b?(x: number): void }
type U<X> = X | null;
enum E { A, B }
namespace N.M { export const z = 1; }
const g = (x: number) => x, h = 2;
let { d } = obj;
`);
  assert.equal(partial, false);
  const got = decls.map(d => `${d.kind} ${[...d.chain, d.name].join('.')} ${d.signature}`);
  assert.deepEqual(got, [
    'module  ',
    'function f <T>(T,string?,...number[]):void',
    'function default ()',
    'type K <T>',
    'field K.s static _',
    'field K.x ?number',
    'field K.#p _',
    'method K.constructor (string)',
    'method K.v get ():string',
    'method K.v set (string)',
    'method K.m (this:K<T>,_?):T',
    'method K.computed ()',
    'type I ',
    'field I.a string',
    'method I.b ?(number):void',
    'type U <X>',
    'type E ',
    'module N.M ',
    'field N.M.z _',
    'function g (number)',
    'field h _',
  ]);
});

test('whitespace and comment edits keep a declaration stable', () => {
  const r = one(
    'export function keep(a: string): number { return a.length }\n',
    '// a comment\n/** docs */\nexport function keep(a:string):number{\n  return a.length // why\n}\n',
  );
  assert.equal(outcome(r.by.keep), 'stable');
  assert.equal(outcome(r.by['<file>']), 'stable');
  assert.ok(r.kinds.includes('format'));
});

test('a body edit changes the body and keeps the identity', () => {
  const r = one('function f(a: string) { return 1 }\n', 'function f(a: string) { return 2 }\n');
  assert.equal(outcome(r.by.f), 'changed:body');
  assert.deepEqual(r.by.f.after, { file: 'src/a.ts', line: 1, start: 1, end: 1 });
  assert.equal(outcome(r.by['<file>']), 'stable', 'a member body edit does not change the module');
  assert.deepEqual(r.kinds, ['body']);
});

test('a signature change is an identity change', () => {
  const r = one('function f(a: string): void {}\n', 'function f(a: number): void {}\n');
  assert.equal(outcome(r.by.f), 'changed:identity');
  assert.equal(r.by.f.reason, 'signature');
  assert.equal(r.by.f.after, null);
  assert.equal(outcome(r.by['<file>']), 'changed:body', 'the module holds the member header');
  assert.ok(r.kinds.includes('signature'));
});

test('parameter names do not take part in the signature', () => {
  const r = one('function f(a: string) { return a }\n', 'function f(b: string) { return b }\n');
  assert.equal(outcome(r.by.f), 'changed:body');
});

test('reordered signature tokens are set aside', () => {
  const r = one('function f(a: A | B) {}\n', 'function f(a: B | A) {}\n');
  assert.equal(outcome(r.by.f), 'judgement:signature-order');
  assert.equal(outcome(r.by['<file>']), 'judgement:member-header');
});

test('a rename is an identity change with reason renamed', () => {
  const r = one('export function oldName(a: number) { return a * 2 }\n', 'export function newName(a: number) { return a * 2 }\n');
  assert.equal(r.by.oldName.reason, 'renamed');
  assert.equal(r.added, 1);
  assert.ok(r.kinds.includes('rename') && r.kinds.includes('add'));
});

test('a renamed container re-keys its members (parent-changed)', () => {
  const r = one('class A { m() { go() } }\n', 'class B { m() { go() } }\n');
  assert.equal(r.by.A.reason, 'renamed');
  assert.equal(r.by['A.m'].reason, 'parent-changed');
});

test('a file move is an identity change with reason moved', () => {
  const text = 'export function mv(): void { go() }\n';
  const r = labelPair([{ before: 'src/old.ts', after: 'lib/new.ts' }], () => text);
  const mv = r.records.find(x => x.name === 'mv');
  const file = r.records.find(x => x.name === '');
  assert.equal(outcome(mv), 'changed:identity');
  assert.equal(mv.reason, 'moved');
  assert.equal(file.reason, 'moved');
  assert.ok(r.kinds.includes('move'));
});

test('a declaration moved to another touched file is moved', () => {
  const r = labelPair(
    [{ before: 'src/a.ts', after: 'src/a.ts' }, { before: 'src/b.ts', after: 'src/b.ts' }],
    (side, path) => ({
      'before:src/a.ts': 'export function x() { one() }\nexport function y() {}\n',
      'after:src/a.ts': 'export function y() {}\n',
      'before:src/b.ts': 'export const k = 1;\n',
      'after:src/b.ts': 'export const k = 1;\nexport function x() { one() }\n',
    })[`${side}:${path}`],
  );
  const x = r.records.find(d => d.name === 'x');
  assert.equal(x.reason, 'moved');
  assert.equal(outcome(r.records.find(d => d.name === 'y')), 'stable');
});

test('reordered members stay stable; the container is set aside', () => {
  const r = one('class K {\n  a() { one() }\n  b() { two() }\n}\n', 'class K {\n  b() { two() }\n  a() { one() }\n}\n');
  assert.equal(outcome(r.by['K.a']), 'stable');
  assert.equal(outcome(r.by['K.b']), 'stable');
  assert.equal(outcome(r.by.K), 'judgement:member-order');
  assert.ok(r.kinds.includes('reorder'));
});

test('a reorder plus a new member changes the container', () => {
  const r = one('class K { a() {} b() {} }\n', 'class K { b() {} a() {} c() {} }\n');
  assert.equal(outcome(r.by.K), 'changed:body');
});

test('formatting-only differences are set aside', () => {
  const r = one(
    "export const f = (x) => { return g('a', x,); };\n",
    'export const f = x => { return g("a", x) }\n',
  );
  assert.equal(outcome(r.by.f), 'judgement:formatting');
});

test('JSX whitespace is whitespace; JSX parentheses are formatting', () => {
  const r = one(
    'export function C() { return <div>\n  hi  there\n</div> }\n',
    'export function C() { return <div>hi there</div> }\n',
    'src/c.tsx',
  );
  assert.equal(outcome(r.by.C), 'stable');
  const p = one('export function C() { return (<b>x</b>) }\n', 'export function C() { return <b>x</b> }\n', 'src/c.tsx');
  assert.equal(outcome(p.by.C), 'judgement:formatting');
});

test('a header-only change is set aside, and so is its container', () => {
  const r = one('class K { m(a = 1) { return 0 } }\n', 'class K { m(a = 2) { return 0 } }\n');
  assert.equal(outcome(r.by['K.m']), 'judgement:header');
  assert.equal(outcome(r.by.K), 'judgement:member-header');
  const e = one('function f() { return 0 }\n', 'export function f() { return 0 }\n');
  assert.equal(outcome(e.by.f), 'judgement:header');
  assert.equal(outcome(e.by['<file>']), 'judgement:member-header');
});

test('duplicate identities are set aside', () => {
  const r = one('interface I { a: string }\ninterface I { b: string }\n', 'interface I { a: string }\ninterface I { b: number }\n');
  const is = r.records.filter(x => x.name === 'I');
  assert.equal(is.length, 2);
  assert.ok(is.every(x => x.judgement === 'duplicate'));
});

test('a file with syntax errors is set aside whole', () => {
  const r = one('function f() { return 1 }\n', 'function f() { return 1 \n');
  assert.ok(r.records.every(x => x.judgement === 'parse-error'));
});

test('a removed declaration and an added file', () => {
  const r = labelPair(
    [{ before: 'src/a.ts', after: 'src/a.ts' }, { before: null, after: 'src/n.ts' }, { before: 'src/d.ts', after: null }],
    (side, path) => ({
      'before:src/a.ts': 'export function gone() { x() }\nexport function kept() {}\n',
      'after:src/a.ts': 'export function kept() {}\n',
      'after:src/n.ts': 'export function fresh() {}\n',
      'before:src/d.ts': 'export function dead() {}\n',
    })[`${side}:${path}`],
  );
  assert.equal(r.records.find(x => x.name === 'gone').reason, 'removed');
  assert.equal(r.records.find(x => x.name === 'dead').reason, 'removed');
  assert.equal(r.added, 2, 'the new file and its function');
  assert.deepEqual(summarize(r.records), { declarations: 5, stable: 1, body: 1, identity: 3, judgement: 0 });
});

test('labels are deterministic and sorted by file and position', () => {
  const files = [{ before: 'b.ts', after: 'b.ts' }, { before: 'a.ts', after: 'a.ts' }];
  const read = (side, path) => (path === 'a.ts' ? 'function z() {}\nfunction y() {}\n' : 'const q = 1;\n');
  const r1 = labelPair(files, read);
  const r2 = labelPair([...files].reverse(), read);
  assert.deepEqual(r1, r2);
  assert.deepEqual(r1.records.map(x => `${x.file}:${x.name}`), ['a.ts:', 'a.ts:z', 'a.ts:y', 'b.ts:', 'b.ts:q']);
});
