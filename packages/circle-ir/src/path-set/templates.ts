/**
 * Template facts: where a server-side template renders a value it was handed,
 * and through which construct — a Thymeleaf attribute (`th:text`, `th:utext`,
 * `th:href`…), inline Thymeleaf (`[[…]]`, `[(…)]`), a JSP custom tag
 * (`<c:out value="${q}" escapeXml="false"/>`) or an EL expression written
 * straight into a JSP page (`${q}`).
 *
 * Read with circle-ir's HTML grammar (JSP directives parse as error nodes and
 * are skipped; elements, attributes and text parse). The facts name constructs
 * and attributes as written; which construct escapes is not decided here — a
 * caller's table says that.
 */

import type { Node } from 'web-tree-sitter';
import { disposeTree, parse } from '../core/parser.js';

export type TemplateEngine = 'thymeleaf' | 'jsp';

export interface TemplateFact {
  file: string;
  /** 1-based line of the construct. */
  line: number;
  engine: TemplateEngine;
  /**
   * The construct as written: a Thymeleaf attribute name (`th:utext`; `data-th-*`
   * normalised to `th:*`), `[[…]]` / `[(…)]` for inline Thymeleaf, a JSP tag name
   * (`c:out`), or `${}` for an EL expression written into the page.
   */
  construct: string;
  /** The element the construct sits on (tag name), when there is one. */
  element?: string;
  /** For `${}` inside a plain attribute value: that attribute's name. */
  inAttribute?: string;
  /** The other attributes of the element, name → value as written. */
  attributes: Record<string, string>;
  /** The expression text. */
  expression: string;
  /** Root names the expression reads (`q` in `${q.name}`, `${fn:escapeXml(q)}`). */
  names: string[];
}

const EXPR = /[$*]\{([^}]*)\}/g;

/** Root names read by the `${…}` / `*{…}` expressions in a string. */
export function expressionNames(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(EXPR)) {
    const body = m[1].replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, '""');
    const ident = /[A-Za-z_][\w]*/g;
    let k: RegExpExecArray | null;
    while ((k = ident.exec(body)) !== null) {
      const before = body[k.index - 1];
      const after = body.slice(k.index + k[0].length).trimStart()[0];
      if (before === '.' || before === ':' || after === ':' || after === '(') continue;
      if (['true', 'false', 'null', 'empty', 'not', 'and', 'or', 'eq', 'ne', 'lt', 'gt', 'le', 'ge', 'div', 'mod', 'instanceof'].includes(k[0])) continue;
      out.add(k[0]);
    }
  }
  return [...out].sort();
}

/** The template engine a file is written for, from its name and, for HTML, its `th:` attributes. */
export function templateEngineOf(filePath: string, code: string): TemplateEngine | null {
  const lower = filePath.toLowerCase();
  if (/\.(jspx?|tagx?)$/.test(lower)) return 'jsp';
  if (/\.html?$/.test(lower) && /\s(?:th|data-th)[:-][a-z]/i.test(code)) return 'thymeleaf';
  return null;
}

function attributesOf(tag: Node): Array<{ name: string; value: string; line: number }> {
  const out: Array<{ name: string; value: string; line: number }> = [];
  for (const a of tag.namedChildren) {
    if (!a || a.type !== 'attribute') continue;
    const name = a.namedChildren.find(c => c?.type === 'attribute_name')?.text ?? '';
    const v = a.namedChildren.find(c => c?.type === 'quoted_attribute_value' || c?.type === 'attribute_value');
    const value = v?.type === 'quoted_attribute_value'
      ? (v.namedChildren.find(c => c?.type === 'attribute_value')?.text ?? '')
      : (v?.text ?? '');
    out.push({ name, value, line: a.startPosition.row + 1 });
  }
  return out;
}

/** Template facts for one file; empty for a file no supported engine reads. */
export async function deriveTemplateFacts(code: string, filePath: string): Promise<TemplateFact[]> {
  const engine = templateEngineOf(filePath, code);
  if (!engine) return [];
  const tree = await parse(code, 'html');
  try {
    const out: TemplateFact[] = [];
    const push = (f: Omit<TemplateFact, 'file' | 'engine' | 'names'>): void => {
      const names = expressionNames(f.expression);
      if (names.length > 0) out.push({ file: filePath, engine, names, ...f });
    };
    const walk = (n: Node): void => {
      if (n.type === 'start_tag' || n.type === 'self_closing_tag') {
        const tagName = n.namedChildren.find(c => c?.type === 'tag_name')?.text ?? '';
        const attrs = attributesOf(n);
        const others = (skip: string): Record<string, string> =>
          Object.fromEntries(attrs.filter(a => a.name !== skip).map(a => [a.name, a.value]));
        const custom = engine === 'jsp' && tagName.includes(':');
        if (custom && attrs.some(a => /[$*]\{/.test(a.value))) {
          const exprs = attrs.filter(a => /[$*]\{/.test(a.value));
          push({ line: n.startPosition.row + 1, construct: tagName, element: tagName, attributes: others(''), expression: exprs.map(a => a.value).join(' ') });
        } else {
          for (const a of attrs) {
            if (!/[$*]\{/.test(a.value)) continue;
            if (engine === 'thymeleaf' && /^(?:th:|data-th-)/.test(a.name)) {
              push({ line: a.line, construct: a.name.replace(/^data-th-/, 'th:'), element: tagName, attributes: others(a.name), expression: a.value });
            } else if (engine === 'jsp') {
              push({ line: a.line, construct: '${}', element: tagName, inAttribute: a.name, attributes: others(a.name), expression: a.value });
            }
          }
        }
      } else if (n.type === 'text') {
        const text = n.text;
        if (engine === 'jsp' && /\$\{/.test(text)) {
          for (const m of text.matchAll(/\$\{[^}]*\}/g)) {
            const line = n.startPosition.row + 1 + text.slice(0, m.index).split('\n').length - 1;
            push({ line, construct: '${}', attributes: {}, expression: m[0] });
          }
        } else if (engine === 'thymeleaf') {
          for (const m of text.matchAll(/\[\[([^\]]*)\]\]|\[\(([^)]*\)?[^\]]*)\)\]/g)) {
            const line = n.startPosition.row + 1 + text.slice(0, m.index).split('\n').length - 1;
            push({ line, construct: m[0].startsWith('[[') ? '[[…]]' : '[(…)]', attributes: {}, expression: m[0] });
          }
        }
      }
      for (const c of n.namedChildren) if (c) walk(c);
    };
    walk(tree.rootNode);
    return out.sort((a, b) => a.line - b.line || a.construct.localeCompare(b.construct));
  } finally {
    disposeTree(tree);
  }
}
