/**
 * Vue template HTML sinks
 *
 * A Vue Single-File Component's `<template>` writes raw HTML through the
 * attribute bindings `v-html`, `v-bind:innerHTML` / `:innerHTML` and
 * `v-bind:outerHTML` / `:outerHTML` (CWE-79). `v-text` and `{{ … }}` write
 * text, which the browser escapes, so they are not sinks.
 *
 * The bound expression is evaluated against the component's script: the
 * top-level bindings of `<script setup>`, or the `data()`, `computed`,
 * `methods` and `setup()` members of an Options API component. Rather than
 * guess which names carry taint, this module builds a probe copy of a script
 * block in which each binding becomes an ordinary DOM sink
 * (`<marker>.innerHTML = (<expr>)`). `analyzeMarkupFile()` runs the normal
 * JS/TS analysis on the probe, and the flows that end at a probe sink are
 * mapped back to the template line. Sanitisers, `ref()` / `computed()`
 * wrappers and reassignments are then decided by the same engine that
 * decides them for plain JS.
 *
 * The probe keeps the script's line numbers. Template expressions are
 * appended after the script's last line (one per line), and Options API
 * member values are wrapped where they stand, without adding a line.
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { CircleIR, TaintFlowInfo, TaintFlowStep, TaintSink, TaintSource } from '../../types/index.js';
import { findChildByType, stripQuotes } from './html-extractor.js';

/**
 * Template attribute bindings that write raw HTML. `v-text` is excluded:
 * it writes `textContent`, which the browser escapes.
 */
const DANGEROUS_BINDINGS = new Set<string>([
  'v-html',
  'v-bind:innerhtml',
  ':innerhtml',
  'v-bind:outerhtml',
  ':outerhtml',
]);

/** Receiver of every probe sink; never a name a component would use. */
export const VUE_PROBE_SINK = '__vueTemplateHtml__';

/** Most bindings probed in one file; past it the rest are skipped. */
const MAX_BINDINGS = 16;

const ID_RE = /(?<![\w$.])([A-Za-z_$][\w$]*)/g;

/** Words that never name a component member. */
const RESERVED = new Set<string>([
  'true', 'false', 'null', 'undefined', 'this', 'new', 'typeof',
  'void', 'delete', 'instanceof', 'in', 'of', 'NaN', 'Infinity',
  'Math', 'Number', 'String', 'Boolean', 'Array', 'Object', 'JSON',
]);

/** A template attribute binding that writes raw HTML. */
export interface VueHtmlBinding {
  /** The attribute as written, e.g. `v-html`. */
  attribute: string;
  /** The bound JavaScript expression. */
  expression: string;
  /** 1-based line of the attribute in the `.vue` file. */
  line: number;
}

/** A script block rewritten so that template bindings are DOM sinks. */
export interface VueTemplateProbe {
  code: string;
  /** Probe line (1-based) of each probe sink → the binding it stands for. */
  sinkLines: Map<number, VueHtmlBinding>;
  /** Number of lines of the original script; later probe lines are appended. */
  scriptLineCount: number;
}

/**
 * Every raw-HTML binding in the template whose expression could name script
 * data (a literal such as `v-html="'<b>x</b>'"` is skipped).
 */
export function collectVueHtmlBindings(rootNode: SyntaxNode): VueHtmlBinding[] {
  const out: VueHtmlBinding[] = [];
  const stack: SyntaxNode[] = [rootNode];
  while (stack.length > 0) {
    const node = stack.pop()!;
    if (node.type === 'script_element' || node.type === 'style_element') continue;
    if (node.type === 'start_tag' || node.type === 'self_closing_tag') {
      for (let i = 0; i < node.childCount; i++) {
        const attr = node.child(i);
        if (!attr || attr.type !== 'attribute') continue;
        const nameNode = findChildByType(attr, 'attribute_name');
        if (!nameNode || !DANGEROUS_BINDINGS.has(nameNode.text.toLowerCase())) continue;
        const valueNode =
          findChildByType(attr, 'quoted_attribute_value') ?? findChildByType(attr, 'attribute_value');
        if (!valueNode) continue;
        const expression = stripQuotes(valueNode.text).trim();
        if (!expression || referencedNames(expression).length === 0) continue;
        out.push({ attribute: nameNode.text, expression, line: nameNode.startPosition.row + 1 });
      }
    }
    for (let i = node.childCount - 1; i >= 0; i--) {
      const c = node.child(i);
      if (c) stack.push(c);
    }
  }
  out.sort((a, b) => a.line - b.line);
  return out.slice(0, MAX_BINDINGS);
}

/**
 * The `.vue` file's text outside its `<script>` and `<style>` blocks (blanked
 * in place): what the template can name.
 */
export function vueTemplateText(rootNode: SyntaxNode, code: string): string {
  let out = code;
  const stack: SyntaxNode[] = [rootNode];
  while (stack.length > 0) {
    const node = stack.pop()!;
    if (node.type === 'script_element' || node.type === 'style_element') {
      if (code.slice(node.startIndex, node.endIndex) === node.text) {
        out = out.slice(0, node.startIndex) + ' '.repeat(node.endIndex - node.startIndex) + out.slice(node.endIndex);
      }
      continue;
    }
    for (let i = 0; i < node.childCount; i++) {
      const c = node.child(i);
      if (c) stack.push(c);
    }
  }
  return out;
}

/** Free identifiers an expression reads (not property names, not keywords, not inside strings). */
function referencedNames(expression: string): string[] {
  const code = expression.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, '""');
  const names: string[] = [];
  ID_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ID_RE.exec(code)) !== null) {
    if (!RESERVED.has(m[1]) && !names.includes(m[1])) names.push(m[1]);
  }
  return names;
}

/**
 * The member an expression reads when it is a plain reference (`note`,
 * `state.text`, `render()`, `render(id)`), or null. Only such expressions are
 * followed into Options API members; anything else (`sanitize(note)`) is
 * probed as written, so a wrapping call is never skipped over.
 */
function memberRoot(expression: string): string | null {
  const m = /^([A-Za-z_$][\w$]*)(?:\??\.[A-Za-z_$][\w$]*)*(?:\([^()]*\))?$/.exec(expression.replace(/\s+/g, ''));
  return m && !RESERVED.has(m[1]) ? m[1] : null;
}

/** A value expression to wrap in place: `[start, end)` in the script text. */
interface Wrap {
  start: number;
  end: number;
  line: number;
}

/**
 * Value expressions of the Options API members of `export default { … }` /
 * `export default defineComponent({ … })`, by member name: `computed` and
 * `methods` functions (their `return` values), and the keys of the objects
 * returned by `data()` and `setup()`.
 */
function optionsApiMembers(root: SyntaxNode, code: string): Map<string, Wrap[]> {
  const members = new Map<string, Wrap[]>();
  const add = (name: string, node: SyntaxNode | null): void => {
    if (!node || code.slice(node.startIndex, node.endIndex) !== node.text) return;
    const list = members.get(name) ?? [];
    list.push({ start: node.startIndex, end: node.endIndex, line: node.startPosition.row + 1 });
    members.set(name, list);
  };

  for (let i = 0; i < root.childCount; i++) {
    const stmt = root.child(i);
    if (!stmt || stmt.type !== 'export_statement' || !findChildByType(stmt, 'default')) continue;
    let value = stmt.childForFieldName('value');
    if (value?.type === 'call_expression') {
      value = value.childForFieldName('arguments')?.namedChild(0) ?? null;
    }
    if (!value || value.type !== 'object') continue;

    for (const [key, member] of objectMembers(value)) {
      if (key === 'computed' || key === 'methods') {
        if (member.type !== 'pair') continue;
        const group = member.childForFieldName('value');
        if (group?.type !== 'object') continue;
        for (const [name, fn] of objectMembers(group)) {
          for (const ret of functionReturns(fn)) add(name, ret);
        }
      } else if (key === 'data' || key === 'setup') {
        for (const ret of functionReturns(member)) {
          const obj = unwrapParens(ret);
          if (obj.type !== 'object') continue;
          for (const [name, prop] of objectMembers(obj)) {
            if (prop.type === 'pair') add(name, prop.childForFieldName('value'));
            else if (prop.type === 'shorthand_property_identifier') add(name, prop);
          }
        }
      }
    }
  }
  return members;
}

/** `key → member node` for the pairs, methods and shorthand keys of an object literal. */
function objectMembers(obj: SyntaxNode): Array<[string, SyntaxNode]> {
  const out: Array<[string, SyntaxNode]> = [];
  for (let i = 0; i < obj.namedChildCount; i++) {
    const m = obj.namedChild(i);
    if (!m) continue;
    if (m.type === 'shorthand_property_identifier') {
      out.push([m.text, m]);
      continue;
    }
    if (m.type !== 'pair' && m.type !== 'method_definition') continue;
    const keyNode = m.childForFieldName(m.type === 'pair' ? 'key' : 'name');
    if (!keyNode) continue;
    out.push([stripQuotes(keyNode.text), m]);
  }
  return out;
}

function unwrapParens(node: SyntaxNode): SyntaxNode {
  let n = node;
  while (n.type === 'parenthesized_expression' && n.namedChild(0)) n = n.namedChild(0)!;
  return n;
}

/**
 * The returned expressions of a member that is a function: a method
 * (`name() { … }`), a `name: function () { … }` / arrow pair, or a computed
 * `{ get() { … } }`. Returns inside nested functions are not the member's.
 */
function functionReturns(member: SyntaxNode): SyntaxNode[] {
  let fn: SyntaxNode | null = member;
  if (member.type === 'pair') {
    fn = member.childForFieldName('value');
    if (fn?.type === 'object') {
      const getter = objectMembers(fn).find(([k]) => k === 'get');
      fn = getter ? getter[1] : null;
      if (fn?.type === 'pair') fn = fn.childForFieldName('value');
    }
  }
  if (!fn) return [];
  if (!['method_definition', 'function_expression', 'function', 'arrow_function'].includes(fn.type)) return [];
  const body = fn.childForFieldName('body');
  if (!body) return [];
  if (body.type !== 'statement_block') return [body];

  const out: SyntaxNode[] = [];
  const stack: SyntaxNode[] = [body];
  while (stack.length > 0) {
    const n = stack.pop()!;
    if (n !== body && /function|arrow_function|method_definition|class/.test(n.type)) continue;
    if (n.type === 'return_statement') {
      const arg = n.namedChild(0);
      if (arg) out.push(arg);
      continue;
    }
    for (let i = n.childCount - 1; i >= 0; i--) {
      const c = n.child(i);
      if (c) stack.push(c);
    }
  }
  return out;
}

/**
 * Probe copies of one script block covering every binding. Each binding's
 * expression is appended as a sink statement; when the expression is a plain
 * reference to an Options API member, that member's value expressions are
 * wrapped as sinks too. Two bindings never share a probe line: a binding
 * whose wrapped lines collide with an earlier one goes to another probe.
 *
 * @param code - the script block's text
 * @param scriptRoot - its JS/TS syntax tree, or null when it did not parse
 */
export function buildVueTemplateProbes(
  code: string,
  scriptRoot: SyntaxNode | null,
  bindings: VueHtmlBinding[],
): VueTemplateProbe[] {
  if (bindings.length === 0) return [];
  const scriptLineCount = code.split('\n').length;
  const members = scriptRoot ? optionsApiMembers(scriptRoot, code) : new Map<string, Wrap[]>();

  const groups: Array<{ bindings: VueHtmlBinding[]; wraps: Map<number, { wrap: Wrap; binding: VueHtmlBinding }> }> = [];
  for (const binding of bindings) {
    const root = memberRoot(binding.expression);
    const wraps = root ? members.get(root) ?? [] : [];
    let group = groups.find((g) => wraps.every((w) => !g.wraps.has(w.line)));
    if (!group) {
      group = { bindings: [], wraps: new Map() };
      groups.push(group);
    }
    group.bindings.push(binding);
    for (const w of wraps) group.wraps.set(w.line, { wrap: w, binding });
  }

  return groups.map((g) => {
    const sinkLines = new Map<number, VueHtmlBinding>();
    let body = code;
    const edits = [...g.wraps.values()].sort((a, b) => b.wrap.start - a.wrap.start);
    for (const { wrap, binding } of edits) {
      const value = body.slice(wrap.start, wrap.end);
      // A shorthand key (`{ msg }`) becomes `msg: <sink> = (msg)`.
      const isShorthand = /^[A-Za-z_$][\w$]*$/.test(value) && body[wrap.end] !== '(' &&
        /[{,]\s*$/.test(body.slice(Math.max(0, wrap.start - 64), wrap.start));
      const replacement = `${isShorthand ? `${value}: ` : ''}${VUE_PROBE_SINK}.innerHTML = (${value})`;
      body = body.slice(0, wrap.start) + replacement + body.slice(wrap.end);
      sinkLines.set(wrap.line, binding);
    }
    const appended = g.bindings.map((b, i) => {
      sinkLines.set(scriptLineCount + 1 + i, b);
      const oneLine = b.expression.split('\n').map((part) => part.trim()).join(' ');
      return `;${VUE_PROBE_SINK}.innerHTML = (${oneLine});`;
    });
    return { code: `${body}\n${appended.join('\n')}`, sinkLines, scriptLineCount };
  });
}

/**
 * The template flows found by one probe, with their sinks and sources, in
 * `.vue` file lines.
 * Script lines move by `lineOffset - 1`; appended lines and probe sinks map
 * to the binding's template line. A flow the unmodified script already has is
 * not a template flow and is skipped.
 */
export function mapVueProbeFlows(
  probeIr: CircleIR,
  probe: VueTemplateProbe,
  lineOffset: number,
  scriptIr: CircleIR | undefined,
): { flows: TaintFlowInfo[]; sinks: TaintSink[]; sources: TaintSource[] } {
  const shift = lineOffset - 1;
  const probeSinkLines = new Set(
    probeIr.taint.sinks.filter((s) => s.location.includes(VUE_PROBE_SINK)).map((s) => s.line),
  );
  const own = new Set(
    (scriptIr?.taint.flows ?? []).map((f) => `${f.source_line}:${f.sink_line}:${f.sink_type}`),
  );
  const toFileLine = (line: number, binding: VueHtmlBinding): number =>
    line > probe.scriptLineCount ? binding.line : line + shift;

  const flows: TaintFlowInfo[] = [];
  const sinks = new Map<number, TaintSink>();
  const sources = new Map<string, TaintSource>();
  const seen = new Set<string>();
  for (const flow of probeIr.taint.flows ?? []) {
    if (flow.sink_type !== 'xss') continue;
    const binding = probe.sinkLines.get(flow.sink_line);
    if (!binding || !probeSinkLines.has(flow.sink_line)) continue;
    if (own.has(`${flow.source_line}:${flow.sink_line}:${flow.sink_type}`)) continue;
    const sourceLine = toFileLine(flow.source_line, binding);
    const key = `${sourceLine}:${binding.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const path: TaintFlowStep[] = flow.path.map((step) => ({
      ...step,
      line: step.type === 'sink' ? binding.line : toFileLine(step.line, binding),
    }));
    flows.push({ ...flow, source_line: sourceLine, sink_line: binding.line, path });
    for (const src of probeIr.taint.sources) {
      if (src.line !== flow.source_line || src.type !== flow.source_type) continue;
      const mapped = { ...src, line: sourceLine };
      if (flow.source_line > probe.scriptLineCount) mapped.code = `${binding.attribute}="${binding.expression}"`;
      sources.set(`${sourceLine}:${src.type}:${src.location}`, mapped);
    }
    if (!sinks.has(binding.line)) {
      sinks.set(binding.line, {
        type: 'xss',
        cwe: 'CWE-79',
        location: `${binding.attribute}="${binding.expression}"`,
        line: binding.line,
        confidence: flow.confidence,
        method: binding.attribute,
        argPositions: [0],
        code: `${binding.attribute}="${binding.expression}"`,
      });
    }
  }
  return { flows, sinks: [...sinks.values()], sources: [...sources.values()] };
}
