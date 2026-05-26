/**
 * Meta extractor - extracts file metadata
 */

import type { Tree } from 'web-tree-sitter';
import type { Meta } from '../../types/index.js';
import type { SupportedLanguage } from '../parser.js';
import { findNodes } from '../parser.js';

/**
 * Extract metadata from source code.
 */
export function extractMeta(
  code: string,
  tree: Tree,
  filePath: string,
  language: SupportedLanguage
): Meta {
  const loc = countLinesOfCode(code);
  const hash = computeHash(code);
  const pkg = extractPackage(tree, language);

  return {
    circle_ir: '3.0',
    file: filePath,
    language,
    loc,
    hash,
    ...(pkg && { package: pkg }),
  };
}

/**
 * Count lines of code (non-empty, non-comment lines).
 */
function countLinesOfCode(code: string): number {
  const lines = code.split('\n');
  let count = 0;
  let inBlockComment = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Handle block comments
    if (inBlockComment) {
      if (trimmed.includes('*/')) {
        inBlockComment = false;
        // Check if there's code after the comment ends
        const afterComment = trimmed.substring(trimmed.indexOf('*/') + 2).trim();
        if (afterComment && !afterComment.startsWith('//')) {
          count++;
        }
      }
      continue;
    }

    // Skip empty lines
    if (!trimmed) {
      continue;
    }

    // Skip single-line comments
    if (trimmed.startsWith('//')) {
      continue;
    }

    // Handle start of block comment
    if (trimmed.startsWith('/*')) {
      if (!trimmed.includes('*/')) {
        inBlockComment = true;
      }
      continue;
    }

    // Check for inline block comment at start
    if (trimmed.startsWith('*')) {
      continue;
    }

    count++;
  }

  return count;
}

/**
 * Compute SHA256 hash prefix (16 chars) of the code.
 * Uses a simple hash for universal compatibility.
 */
function computeHash(code: string): string {
  // Simple hash implementation for universal compatibility
  // In production, use SubtleCrypto when available
  let hash = 0;
  const len = code.length;
  for (let i = 0; i < len; i++) {
    const char = code.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }

  // Convert to hex and pad to ensure consistent length
  const hashHex = Math.abs(hash).toString(16).padStart(8, '0');

  // Repeat to get 16 chars (simplified, not actual SHA256)
  return (hashHex + hashHex).substring(0, 16);
}

/**
 * Extract package declaration from the tree.
 */
function extractPackage(tree: Tree, language: SupportedLanguage): string | null {
  if (language !== 'java') {
    return null;
  }

  const packageDecls = findNodes(tree.rootNode, 'package_declaration');
  if (packageDecls.length === 0) {
    return null;
  }

  const packageDecl = packageDecls[0];

  // Try field name first
  const nameField = packageDecl.childForFieldName('name');
  if (nameField) {
    return nameField.text;
  }

  // Fall back to finding scoped_identifier or identifier
  for (let i = 0; i < packageDecl.childCount; i++) {
    const child = packageDecl.child(i);
    if (child && (child.type === 'scoped_identifier' || child.type === 'identifier')) {
      return child.text;
    }
  }

  return null;
}
