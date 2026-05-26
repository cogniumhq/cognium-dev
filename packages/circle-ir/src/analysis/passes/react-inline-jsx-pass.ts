/**
 * Pass #33: react-inline-jsx (category: performance)
 *
 * Detects inline object literals or arrow functions passed as JSX props.
 * These create a new reference on every render, defeating React.memo /
 * shouldComponentUpdate optimisations and causing unnecessary re-renders.
 *
 * Detection strategy:
 *   1. Only runs on JavaScript/TypeScript files that appear to contain JSX
 *      (quick check: source contains a `<UpperCase` JSX component pattern).
 *   2. Scans each source line for:
 *      a. Inline object prop:  propName={{   (double-brace)
 *      b. Inline arrow prop:   propName={(...) =>   or   propName={identifier =>
 *      c. Inline function prop: propName={function(
 *   3. Skips:
 *      - `style={{` — idiomatic and near-impossible to hoist statically
 *      - `key=` — must be inline
 *      - `data-*` attribute names
 *      - Lines that are comments
 *   4. Emits one finding per matched line.
 *
 * Languages: JavaScript and TypeScript only.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Quick heuristic: does the file contain any JSX component usage? */
const JSX_COMPONENT_RE = /<[A-Z][A-Za-z0-9]*/;

/** Inline object prop: propName={{  (but NOT style={{ ) */
const INLINE_OBJECT_RE = /\s([A-Za-z][A-Za-z0-9_]*)=\{\{/g;

/** Inline arrow function prop: propName={(...) =>  or  propName={x => */
const INLINE_ARROW_RE = /\s([A-Za-z][A-Za-z0-9_]*)=\{(?:\(|[A-Za-z_$]).*?=>/g;

/** Inline function expression prop: propName={function( */
const INLINE_FUNCTION_RE = /\s([A-Za-z][A-Za-z0-9_]*)=\{function\s*\(/g;

/** Props to always skip regardless of value shape. */
const SKIP_PROPS = new Set(['style', 'key', 'ref', 'className', 'id']);

export interface ReactInlineJsxResult {
  inlineProps: Array<{ line: number; propName: string; kind: 'object' | 'arrow' | 'function' }>;
}

export class ReactInlineJsxPass implements AnalysisPass<ReactInlineJsxResult> {
  readonly name = 'react-inline-jsx';
  readonly category = 'performance' as const;

  run(ctx: PassContext): ReactInlineJsxResult {
    const { graph, code, language } = ctx;

    if (language !== 'javascript' && language !== 'typescript') {
      return { inlineProps: [] };
    }

    // Quick file-level JSX check
    if (!JSX_COMPONENT_RE.test(code)) {
      return { inlineProps: [] };
    }

    const file = graph.ir.meta.file;
    const codeLines = code.split('\n');
    const inlineProps: ReactInlineJsxResult['inlineProps'] = [];

    for (let i = 0; i < codeLines.length; i++) {
      const lineText = codeLines[i];
      const ln = i + 1;

      // Skip comment lines
      const trimmed = lineText.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
        continue;
      }

      // --- Inline object prop: propName={{ ---
      INLINE_OBJECT_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = INLINE_OBJECT_RE.exec(lineText)) !== null) {
        const propName = m[1];
        if (SKIP_PROPS.has(propName)) continue;
        if (propName.startsWith('data-')) continue; // data-* attributes

        inlineProps.push({ line: ln, propName, kind: 'object' });
        ctx.addFinding({
          id: `react-inline-jsx-obj-${file}-${ln}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: undefined,
          severity: 'low',
          level: 'note',
          message:
            `Inline object in JSX prop \`${propName}\` creates a new reference on every render, ` +
            `defeating memoization`,
          file,
          line: ln,
          snippet: lineText.trim(),
          fix:
            `Extract the object literal into a \`useMemo\` hook or a module-level constant, ` +
            `then pass the reference: \`${propName}={myConstObject}\`.`,
        });
      }

      // --- Inline arrow function prop: propName={(...) => or propName={x => ---
      INLINE_ARROW_RE.lastIndex = 0;
      while ((m = INLINE_ARROW_RE.exec(lineText)) !== null) {
        const propName = m[1];
        if (SKIP_PROPS.has(propName)) continue;
        if (propName.startsWith('data')) continue;

        inlineProps.push({ line: ln, propName, kind: 'arrow' });
        ctx.addFinding({
          id: `react-inline-jsx-arrow-${file}-${ln}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: undefined,
          severity: 'low',
          level: 'note',
          message:
            `Inline arrow function in JSX prop \`${propName}\` creates a new function reference on every render, ` +
            `defeating memoization`,
          file,
          line: ln,
          snippet: lineText.trim(),
          fix:
            `Wrap the handler with \`useCallback\` or define it outside the component: ` +
            `\`const handle${propName.charAt(0).toUpperCase()}${propName.slice(1)} = useCallback(...)\`.`,
        });
      }

      // --- Inline function expression prop: propName={function( ---
      INLINE_FUNCTION_RE.lastIndex = 0;
      while ((m = INLINE_FUNCTION_RE.exec(lineText)) !== null) {
        const propName = m[1];
        if (SKIP_PROPS.has(propName)) continue;
        if (propName.startsWith('data')) continue;

        inlineProps.push({ line: ln, propName, kind: 'function' });
        ctx.addFinding({
          id: `react-inline-jsx-fn-${file}-${ln}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: undefined,
          severity: 'low',
          level: 'note',
          message:
            `Inline function expression in JSX prop \`${propName}\` creates a new function reference on every render, ` +
            `defeating memoization`,
          file,
          line: ln,
          snippet: lineText.trim(),
          fix:
            `Wrap the handler with \`useCallback\` or define it outside the component: ` +
            `\`const handle${propName.charAt(0).toUpperCase()}${propName.slice(1)} = useCallback(...)\`.`,
        });
      }
    }

    return { inlineProps };
  }
}
