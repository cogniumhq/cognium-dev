/**
 * HTML Content Extractor
 *
 * Extracts JavaScript content from HTML files for analysis:
 * - Inline <script> blocks with line offset tracking
 * - Inline event handler attributes (onclick, onerror, etc.)
 * - External script src references (informational)
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';

/**
 * Represents an extracted <script> block from HTML.
 */
export interface HtmlScriptBlock {
  /** The raw JS source code inside the <script> tags */
  code: string;
  /** 1-based line offset of the first line of JS within the HTML file */
  lineOffset: number;
  /** Whether this is an inline <script> or an external src= reference */
  kind: 'inline' | 'external-src';
  /** The src URL if kind === 'external-src' (informational only) */
  src?: string;
  /** The script type/lang attribute value, if present */
  scriptType?: string;
}

/**
 * Represents an inline event handler attribute extracted from HTML.
 */
export interface HtmlEventHandler {
  /** The JS expression from the event handler attribute value */
  code: string;
  /** Attribute name, e.g. "onclick", "onerror" */
  eventName: string;
  /** 1-based line of the attribute in the HTML file */
  line: number;
  /** The element tag name, e.g. "img", "div" */
  element: string;
}

/**
 * Result of extracting JS content from an HTML file.
 */
export interface HtmlExtractionResult {
  scriptBlocks: HtmlScriptBlock[];
  eventHandlers: HtmlEventHandler[];
}

/** Known inline event handler attribute names */
const EVENT_HANDLER_ATTRS = new Set([
  'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover',
  'onmousemove', 'onmouseout', 'onmouseenter', 'onmouseleave',
  'onkeydown', 'onkeyup', 'onkeypress',
  'onfocus', 'onblur', 'onchange', 'oninput', 'onsubmit', 'onreset',
  'onload', 'onerror', 'onabort', 'onresize', 'onscroll',
  'oncontextmenu', 'ondrag', 'ondrop', 'oncopy', 'onpaste', 'oncut',
  'ontouchstart', 'ontouchend', 'ontouchmove',
  'onanimationend', 'onanimationstart', 'ontransitionend',
]);

/**
 * Extract JavaScript content from an HTML AST.
 *
 * Walks the tree-sitter-html AST to find:
 * 1. <script> elements — extracts inline code or notes external src
 * 2. Elements with on* event handler attributes
 */
export function extractHtmlContent(rootNode: SyntaxNode): HtmlExtractionResult {
  const scriptBlocks: HtmlScriptBlock[] = [];
  const eventHandlers: HtmlEventHandler[] = [];

  walkNode(rootNode, scriptBlocks, eventHandlers);

  return { scriptBlocks, eventHandlers };
}

function walkNode(
  node: SyntaxNode,
  scriptBlocks: HtmlScriptBlock[],
  eventHandlers: HtmlEventHandler[],
): void {
  // Iterative DFS — guards against stack overflow on pathological HTML
  // (deeply nested elements / huge generated documents). Visits parent
  // before children, children left-to-right.
  const stack: SyntaxNode[] = [node];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.type === 'script_element') {
      extractScriptBlock(current, scriptBlocks);
    }
    if (current.type === 'element' || current.type === 'self_closing_tag') {
      extractEventHandlers(current, eventHandlers);
    }
    for (let i = current.childCount - 1; i >= 0; i--) {
      const child = current.child(i);
      if (child) stack.push(child);
    }
  }
}

/**
 * Extract a <script> block — either inline code or external src reference.
 */
function extractScriptBlock(
  scriptNode: SyntaxNode,
  scriptBlocks: HtmlScriptBlock[],
): void {
  const startTag = scriptNode.childForFieldName('start_tag') ?? findChildByType(scriptNode, 'start_tag');

  // Check for src attribute (external script)
  const src = getAttributeValue(startTag, 'src');
  if (src) {
    scriptBlocks.push({
      code: '',
      lineOffset: scriptNode.startPosition.row + 1,
      kind: 'external-src',
      src,
      scriptType: getAttributeValue(startTag, 'type') ?? getAttributeValue(startTag, 'lang'),
    });
    return;
  }

  // Look for inline script content (raw_text child)
  const rawText = findChildByType(scriptNode, 'raw_text');
  if (rawText && rawText.text.trim()) {
    scriptBlocks.push({
      code: rawText.text,
      lineOffset: rawText.startPosition.row + 1,
      kind: 'inline',
      scriptType: getAttributeValue(startTag, 'type') ?? getAttributeValue(startTag, 'lang'),
    });
  }
}

/**
 * Extract inline event handler attributes from an element.
 */
function extractEventHandlers(
  elementNode: SyntaxNode,
  eventHandlers: HtmlEventHandler[],
): void {
  // Get the element's tag name
  const tagName = getTagName(elementNode);

  // Find the start_tag (or the self_closing_tag itself)
  const tag = elementNode.type === 'self_closing_tag'
    ? elementNode
    : findChildByType(elementNode, 'start_tag');
  if (!tag) return;

  // Iterate attributes looking for event handlers
  for (let i = 0; i < tag.childCount; i++) {
    const child = tag.child(i);
    if (!child || child.type !== 'attribute') continue;

    const nameNode = findChildByType(child, 'attribute_name');
    if (!nameNode) continue;

    const attrName = nameNode.text.toLowerCase();
    if (!EVENT_HANDLER_ATTRS.has(attrName)) continue;

    const valueNode = findChildByType(child, 'quoted_attribute_value') ?? findChildByType(child, 'attribute_value');
    if (!valueNode) continue;

    const code = stripQuotes(valueNode.text);
    if (code) {
      eventHandlers.push({
        code,
        eventName: attrName,
        line: child.startPosition.row + 1,
        element: tagName,
      });
    }
  }
}

/**
 * Get the tag name from an element or self-closing tag node.
 */
function getTagName(node: SyntaxNode): string {
  if (node.type === 'self_closing_tag') {
    const tagNameNode = findChildByType(node, 'tag_name');
    return tagNameNode?.text ?? 'unknown';
  }

  const startTag = findChildByType(node, 'start_tag');
  if (startTag) {
    const tagNameNode = findChildByType(startTag, 'tag_name');
    return tagNameNode?.text ?? 'unknown';
  }

  return 'unknown';
}

/**
 * Get the value of a named attribute from a start_tag or self_closing_tag.
 */
function getAttributeValue(tag: SyntaxNode | null, name: string): string | undefined {
  if (!tag) return undefined;

  for (let i = 0; i < tag.childCount; i++) {
    const child = tag.child(i);
    if (!child || child.type !== 'attribute') continue;

    const nameNode = findChildByType(child, 'attribute_name');
    if (nameNode?.text.toLowerCase() === name) {
      const valueNode = findChildByType(child, 'quoted_attribute_value') ?? findChildByType(child, 'attribute_value');
      return valueNode ? stripQuotes(valueNode.text) : '';
    }
  }

  return undefined;
}

/**
 * Find the first child node of a given type.
 */
function findChildByType(node: SyntaxNode, type: string): SyntaxNode | null {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === type) return child;
  }
  return null;
}

/**
 * Strip surrounding quotes from an attribute value.
 */
function stripQuotes(text: string): string {
  if ((text.startsWith('"') && text.endsWith('"')) ||
      (text.startsWith("'") && text.endsWith("'"))) {
    return text.slice(1, -1);
  }
  return text;
}

// Re-export getAttributeValue and getTagName for use by security pass
export { getAttributeValue, getTagName, findChildByType, stripQuotes };
