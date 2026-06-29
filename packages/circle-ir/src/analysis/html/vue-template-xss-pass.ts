/**
 * Vue Template XSS Pass
 *
 * Sprint 64 (cognium-dev #184, sprint 2 of 2). Synthetic-emission pass
 * that walks the `<template>` subtree of a Vue Single-File Component
 * looking for attribute bindings that write raw HTML
 * (`v-html`, `v-bind:innerHTML`, `:innerHTML`, `v-bind:outerHTML`,
 * `:outerHTML`). For each match it parses the RHS expression for JS
 * identifiers and resolves them against the set of tainted variable
 * names extracted from the file's `<script>` blocks. A match emits a
 * `vue-template-xss` finding (CWE-79).
 *
 * The pass is invoked from `analyzeMarkupFile()` only when
 * `language === 'vue'`; plain `.html` files skip it because raw-HTML
 * sinks there land in `javascript_dom_xss.yaml` via the JS pipeline.
 *
 * Pattern mirrors `html-attribute-security-pass.ts`: walk the tree
 * iteratively, emit `SastFinding` objects directly, no taint matcher,
 * no sink-config YAML.
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { SastFinding } from '../../types/index.js';
import type { ScriptBlockResult } from './html-merge.js';
import { findChildByType, stripQuotes } from './html-extractor.js';

/**
 * Vue template attribute bindings that write raw HTML.
 * v-text is intentionally excluded — it writes via textContent which
 * the browser escapes, so it's safe.
 */
const DANGEROUS_BINDINGS = new Set<string>([
  'v-html',
  'v-bind:innerhtml',
  ':innerhtml',
  'v-bind:outerhtml',
  ':outerhtml',
]);

/**
 * JS identifier matcher used to extract referenced names from the RHS
 * expression of a binding. Chained access like `state.user.name`
 * yields each identifier in turn (`state`, `user`, `name`); the first
 * one that resolves to a tainted variable wins.
 */
const ID_RE = /\b([A-Za-z_$][A-Za-z0-9_$]*)\b/g;

/**
 * JS keywords / safe globals that must never count as taint candidates.
 */
const RESERVED = new Set<string>([
  'true', 'false', 'null', 'undefined', 'this', 'new', 'typeof',
  'void', 'delete', 'instanceof', 'in', 'of',
  'Math', 'Number', 'String', 'Boolean', 'Array', 'Object', 'JSON',
]);

/**
 * Walk the parse tree for a Vue SFC and emit `vue-template-xss`
 * findings for dangerous template-attribute bindings that reference
 * tainted identifiers from the file's script blocks.
 *
 * @param rootNode - tree-sitter-html root node of the .vue file
 * @param filePath - path to the .vue file (for finding `file` field)
 * @param scriptResults - per-script-block IRs produced earlier in
 *   `analyzeMarkupFile()`. Each block's `ir.taint` + `ir.dfg` is the
 *   source of truth for which identifiers are tainted.
 */
export function runVueTemplateXssChecks(
  rootNode: SyntaxNode,
  filePath: string,
  scriptResults: ScriptBlockResult[],
): SastFinding[] {
  const taintedNames = collectTaintedNames(scriptResults);
  if (taintedNames.size === 0) return [];

  const findings: SastFinding[] = [];

  // Iterative DFS — guard against stack overflow on deep templates,
  // matches the pattern used in html-attribute-security-pass.ts.
  const stack: SyntaxNode[] = [rootNode];
  while (stack.length > 0) {
    const node = stack.pop()!;
    if (node.type === 'start_tag' || node.type === 'self_closing_tag') {
      checkElementBindings(node, filePath, taintedNames, findings);
    }
    for (let i = node.childCount - 1; i >= 0; i--) {
      const c = node.child(i);
      if (c) stack.push(c);
    }
  }

  return findings;
}

function checkElementBindings(
  tag: SyntaxNode,
  filePath: string,
  tainted: Set<string>,
  out: SastFinding[],
): void {
  for (let i = 0; i < tag.childCount; i++) {
    const attr = tag.child(i);
    if (!attr || attr.type !== 'attribute') continue;

    const nameNode = findChildByType(attr, 'attribute_name');
    if (!nameNode) continue;
    const lcName = nameNode.text.toLowerCase();
    if (!DANGEROUS_BINDINGS.has(lcName)) continue;

    const valueNode =
      findChildByType(attr, 'quoted_attribute_value') ??
      findChildByType(attr, 'attribute_value');
    if (!valueNode) continue;

    const rhs = stripQuotes(valueNode.text);
    if (!rhs.trim()) continue;

    const matched = matchTaint(rhs, tainted);
    if (!matched) continue;

    const line = nameNode.startPosition.row + 1;
    out.push({
      id: `vue-template-xss-${filePath}-${line}-${lcName}`,
      pass: 'vue-template-xss',
      category: 'security',
      rule_id: 'vue-template-xss',
      cwe: 'CWE-79',
      severity: 'high',
      level: 'error',
      message: `Vue template attribute "${nameNode.text}" binds tainted identifier "${matched}" — writes raw HTML (XSS risk).`,
      file: filePath,
      line,
      snippet: `${nameNode.text}="${rhs}"`,
    });
  }
}

function matchTaint(rhs: string, tainted: Set<string>): string | undefined {
  ID_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ID_RE.exec(rhs)) !== null) {
    const id = m[1];
    if (RESERVED.has(id)) continue;
    if (tainted.has(id)) return id;
  }
  return undefined;
}

/**
 * Build the set of identifier names that should be treated as tainted
 * when they appear on the RHS of a template binding. A name qualifies
 * if either:
 *   1. A `DFGDef` at the same line as a `TaintSource` carries it (the
 *      variable directly captures a source expression), or
 *   2. It appears in the `path` of any `TaintFlowInfo` (so
 *      re-assignments like `const y = x;` where `x` is tainted carry
 *      the taint through to `y`), or
 *   3. The `TaintSource.variable` field is populated directly.
 */
function collectTaintedNames(blocks: ScriptBlockResult[]): Set<string> {
  const names = new Set<string>();
  for (const { ir } of blocks) {
    const sourceLines = new Set<number>();
    for (const source of ir.taint.sources) {
      sourceLines.add(source.line);
      if (source.variable) names.add(source.variable);
    }
    for (const def of ir.dfg.defs) {
      if (sourceLines.has(def.line) && def.variable) names.add(def.variable);
    }
    for (const flow of ir.taint.flows ?? []) {
      for (const step of flow.path ?? []) {
        if (step.variable) names.add(step.variable);
      }
    }
  }
  return names;
}
