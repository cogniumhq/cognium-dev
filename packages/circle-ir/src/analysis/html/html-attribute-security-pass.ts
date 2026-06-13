/**
 * HTML Attribute Security Pass
 *
 * Runs attribute-level security checks directly on the HTML AST.
 * These rules do not require IR — they operate on element attributes.
 *
 * Rules:
 *   H1: html-missing-noopener   (CWE-1022) — <a target="_blank"> without rel="noopener"
 *   H2: html-javascript-uri     (CWE-79)   — javascript: in href/src/action
 *   H3: html-missing-sandbox    (CWE-1021) — <iframe> without sandbox
 *   H4: html-mixed-content      (CWE-319)  — http:// resource in script/link/img/iframe
 *   H5: html-missing-sri        (CWE-353)  — CDN script/stylesheet without integrity
 *   H6: html-autocomplete-sensitive (CWE-525) — sensitive input without autocomplete="off"
 *   H7: html-inline-event-handler (CWE-79) — inline on* handler (CSP incompatible)
 *   H8: html-form-action-javascript (CWE-79) — <form action="javascript:...">
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { SastFinding } from '../../types/index.js';
import { getAttributeValue, getTagName, findChildByType } from './html-extractor.js';

/**
 * Run all HTML attribute security checks.
 */
export function runHtmlAttributeSecurityChecks(
  rootNode: SyntaxNode,
  filePath: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  walkForSecurityChecks(rootNode, filePath, findings);
  return findings;
}

function walkForSecurityChecks(
  node: SyntaxNode,
  filePath: string,
  findings: SastFinding[],
): void {
  // Iterative DFS — guards against stack overflow on pathological HTML.
  // Visits parent before children, children left-to-right.
  const stack: SyntaxNode[] = [node];
  while (stack.length > 0) {
    const current = stack.pop()!;
    // tree-sitter-html uses special node types for <script> and <style>
    if (current.type === 'element' || current.type === 'self_closing_tag' ||
        current.type === 'script_element' || current.type === 'style_element') {
      checkElement(current, filePath, findings);
    }
    for (let i = current.childCount - 1; i >= 0; i--) {
      const child = current.child(i);
      if (child) stack.push(child);
    }
  }
}

function checkElement(
  node: SyntaxNode,
  filePath: string,
  findings: SastFinding[],
): void {
  const tagName = getTagName(node).toLowerCase();
  const tag = node.type === 'self_closing_tag'
    ? node
    : findChildByType(node, 'start_tag');
  if (!tag) return;

  const line = tag.startPosition.row + 1;
  const snippet = tag.text.length > 120 ? tag.text.slice(0, 120) + '...' : tag.text;

  // H1: Missing noopener on target="_blank" links
  if (tagName === 'a') {
    checkMissingNoopener(tag, filePath, line, snippet, findings);
  }

  // H2: javascript: URI in href/src/action
  checkJavascriptUri(tag, filePath, line, snippet, findings);

  // H3: Missing sandbox on iframe
  if (tagName === 'iframe') {
    checkMissingSandbox(tag, filePath, line, snippet, findings);
  }

  // H4: Mixed content (http:// resources)
  if (['script', 'link', 'img', 'iframe', 'video', 'audio', 'source', 'object', 'embed'].includes(tagName)) {
    checkMixedContent(tag, tagName, filePath, line, snippet, findings);
  }

  // H5: Missing SRI on CDN resources
  if (tagName === 'script' || tagName === 'link') {
    checkMissingSri(tag, tagName, filePath, line, snippet, findings);
  }

  // H6: Autocomplete on sensitive inputs
  if (tagName === 'input') {
    checkAutocompleteSensitive(tag, filePath, line, snippet, findings);
  }

  // H7: Inline event handlers
  checkInlineEventHandlers(tag, filePath, line, findings);

  // H8: Form action javascript:
  if (tagName === 'form') {
    checkFormActionJavascript(tag, filePath, line, snippet, findings);
  }
}

/** H1: <a target="_blank"> without rel="noopener" or rel="noreferrer" */
function checkMissingNoopener(
  tag: SyntaxNode,
  filePath: string,
  line: number,
  snippet: string,
  findings: SastFinding[],
): void {
  const target = getAttributeValue(tag, 'target');
  if (target !== '_blank') return;

  const rel = getAttributeValue(tag, 'rel')?.toLowerCase() ?? '';
  if (rel.includes('noopener') || rel.includes('noreferrer')) return;

  findings.push({
    id: `html-missing-noopener-${filePath}-${line}`,
    pass: 'html-missing-noopener',
    category: 'security',
    rule_id: 'html-missing-noopener',
    cwe: 'CWE-1022',
    severity: 'medium',
    level: 'warning',
    message: '<a target="_blank"> is missing rel="noopener" — may allow reverse tabnapping',
    file: filePath,
    line,
    snippet,
  });
}

/** H2: javascript: URI in href, src, or action */
function checkJavascriptUri(
  tag: SyntaxNode,
  filePath: string,
  line: number,
  snippet: string,
  findings: SastFinding[],
): void {
  for (const attr of ['href', 'src', 'action']) {
    const value = getAttributeValue(tag, attr);
    if (value && value.trim().toLowerCase().startsWith('javascript:')) {
      findings.push({
        id: `html-javascript-uri-${filePath}-${line}-${attr}`,
        pass: 'html-javascript-uri',
        category: 'security',
        rule_id: 'html-javascript-uri',
        cwe: 'CWE-79',
        severity: 'high',
        level: 'error',
        message: `${attr}="javascript:..." is an XSS vector — use event listeners instead`,
        file: filePath,
        line,
        snippet,
      });
    }
  }
}

/** H3: <iframe> without sandbox attribute */
function checkMissingSandbox(
  tag: SyntaxNode,
  filePath: string,
  line: number,
  snippet: string,
  findings: SastFinding[],
): void {
  const sandbox = getAttributeValue(tag, 'sandbox');
  if (sandbox !== undefined) return; // Present (even empty string is fine)

  findings.push({
    id: `html-missing-sandbox-${filePath}-${line}`,
    pass: 'html-missing-sandbox',
    category: 'security',
    rule_id: 'html-missing-sandbox',
    cwe: 'CWE-1021',
    severity: 'medium',
    level: 'warning',
    message: '<iframe> without sandbox attribute — embedded content has full privileges',
    file: filePath,
    line,
    snippet,
  });
}

/** H4: HTTP resource loaded (mixed content) */
function checkMixedContent(
  tag: SyntaxNode,
  tagName: string,
  filePath: string,
  line: number,
  snippet: string,
  findings: SastFinding[],
): void {
  const attrName = tagName === 'link' ? 'href' : 'src';
  const value = getAttributeValue(tag, attrName);
  if (!value || !value.startsWith('http://')) return;

  findings.push({
    id: `html-mixed-content-${filePath}-${line}`,
    pass: 'html-mixed-content',
    category: 'security',
    rule_id: 'html-mixed-content',
    cwe: 'CWE-319',
    severity: 'medium',
    level: 'warning',
    message: `Loading resource over HTTP (${attrName}="${truncate(value, 60)}") — use HTTPS to prevent MITM`,
    file: filePath,
    line,
    snippet,
  });
}

/** H5: External CDN script/stylesheet without integrity (SRI) */
function checkMissingSri(
  tag: SyntaxNode,
  tagName: string,
  filePath: string,
  line: number,
  snippet: string,
  findings: SastFinding[],
): void {
  // Determine the URL attribute
  const url = tagName === 'script'
    ? getAttributeValue(tag, 'src')
    : getAttributeValue(tag, 'href');
  if (!url) return;

  // Only flag external resources (starts with http:// or https:// or //)
  if (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('//')) return;

  // For <link>, only flag stylesheets
  if (tagName === 'link') {
    const rel = getAttributeValue(tag, 'rel')?.toLowerCase();
    if (rel !== 'stylesheet') return;
  }

  // Check for integrity attribute
  const integrity = getAttributeValue(tag, 'integrity');
  if (integrity) return;

  findings.push({
    id: `html-missing-sri-${filePath}-${line}`,
    pass: 'html-missing-sri',
    category: 'security',
    rule_id: 'html-missing-sri',
    cwe: 'CWE-353',
    severity: 'medium',
    level: 'warning',
    message: `External ${tagName === 'script' ? 'script' : 'stylesheet'} without integrity attribute — vulnerable to CDN compromise`,
    file: filePath,
    line,
    snippet,
  });
}

/** H6: Sensitive input without autocomplete="off" */
function checkAutocompleteSensitive(
  tag: SyntaxNode,
  filePath: string,
  line: number,
  snippet: string,
  findings: SastFinding[],
): void {
  const type = getAttributeValue(tag, 'type')?.toLowerCase();
  const name = getAttributeValue(tag, 'name')?.toLowerCase() ?? '';

  const isSensitive =
    type === 'password' ||
    /\b(ssn|social.?security|credit.?card|card.?number|cvv|cvc|ccv)\b/.test(name);

  if (!isSensitive) return;

  const autocomplete = getAttributeValue(tag, 'autocomplete')?.toLowerCase();
  if (autocomplete === 'off' || autocomplete === 'new-password') return;

  findings.push({
    id: `html-autocomplete-sensitive-${filePath}-${line}`,
    pass: 'html-autocomplete-sensitive',
    category: 'security',
    rule_id: 'html-autocomplete-sensitive',
    cwe: 'CWE-525',
    severity: 'low',
    level: 'note',
    message: 'Sensitive input field without autocomplete="off" — browser may cache sensitive data',
    file: filePath,
    line,
    snippet,
  });
}

/** H7: Inline event handler attributes (on*) */
function checkInlineEventHandlers(
  tag: SyntaxNode,
  filePath: string,
  line: number,
  findings: SastFinding[],
): void {
  for (let i = 0; i < tag.childCount; i++) {
    const child = tag.child(i);
    if (!child || child.type !== 'attribute') continue;

    const nameNode = findChildByType(child, 'attribute_name');
    if (!nameNode) continue;

    const attrName = nameNode.text.toLowerCase();
    if (attrName.startsWith('on') && attrName.length > 2) {
      const attrLine = child.startPosition.row + 1;
      findings.push({
        id: `html-inline-event-handler-${filePath}-${attrLine}-${attrName}`,
        pass: 'html-inline-event-handler',
        category: 'security',
        rule_id: 'html-inline-event-handler',
        cwe: 'CWE-79',
        severity: 'low',
        level: 'note',
        message: `Inline ${attrName} handler — incompatible with strict Content Security Policy; use addEventListener() instead`,
        file: filePath,
        line: attrLine,
        snippet: child.text,
      });
    }
  }
}

/** H8: <form action="javascript:..."> */
function checkFormActionJavascript(
  tag: SyntaxNode,
  filePath: string,
  line: number,
  snippet: string,
  findings: SastFinding[],
): void {
  const action = getAttributeValue(tag, 'action');
  if (!action || !action.trim().toLowerCase().startsWith('javascript:')) return;

  findings.push({
    id: `html-form-action-javascript-${filePath}-${line}`,
    pass: 'html-form-action-javascript',
    category: 'security',
    rule_id: 'html-form-action-javascript',
    cwe: 'CWE-79',
    severity: 'high',
    level: 'error',
    message: '<form action="javascript:..."> is an XSS vector — use proper form submission',
    file: filePath,
    line,
    snippet,
  });
}

function truncate(s: string, maxLen: number): string {
  return s.length > maxLen ? s.slice(0, maxLen) + '...' : s;
}
