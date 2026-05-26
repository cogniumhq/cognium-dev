/**
 * AST utility functions for constant propagation.
 */

import type { Node } from 'web-tree-sitter';
import type { ConstantValue, ConstantType } from './types.js';

/**
 * Check if a constant value is known (not unknown).
 */
export function isKnown(cv: ConstantValue): boolean {
  return cv.type !== 'unknown';
}

/**
 * Create an unknown constant value.
 */
export function createUnknown(line: number): ConstantValue {
  return { value: null, type: 'unknown', sourceLine: line };
}

/**
 * Create a constant value.
 */
export function createConstant(
  value: string | number | boolean | null,
  type: ConstantType,
  line: number
): ConstantValue {
  return { value, type, sourceLine: line };
}

/**
 * Get text content of an AST node.
 */
export function getNodeText(node: Node, source: string): string {
  return source.substring(node.startIndex, node.endIndex);
}

/**
 * Get 1-based line number of an AST node.
 */
export function getNodeLine(node: Node): number {
  return node.startPosition.row + 1;
}
