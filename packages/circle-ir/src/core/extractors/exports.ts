/**
 * Export extractor - extracts public symbols from Java files
 *
 * In Java, exports are determined by visibility modifiers:
 * - public: accessible from anywhere
 * - protected: accessible from same package and subclasses
 * - package-private (default): accessible from same package only
 */

import type { Tree } from 'web-tree-sitter';
import type { ExportInfo, TypeInfo } from '../../types/index.js';

/**
 * Extract exports from types.
 * In Java, public/protected classes, methods, and fields are considered exports.
 */
export function extractExports(types: TypeInfo[]): ExportInfo[] {
  const exports: ExportInfo[] = [];

  for (const type of types) {
    // Check if the type itself is exported (public or protected)
    const typeVisibility = getTypeVisibility(type);
    if (typeVisibility !== 'private') {
      exports.push({
        symbol: type.name,
        kind: type.kind === 'enum' ? 'class' : type.kind,
        visibility: typeVisibility,
      });
    }

    // Only export members if the type is accessible
    if (typeVisibility === 'private') {
      continue;
    }

    // Extract exported methods
    for (const method of type.methods) {
      const methodVisibility = getVisibilityFromModifiers(method.modifiers);
      if (methodVisibility !== 'private') {
        exports.push({
          symbol: `${type.name}.${method.name}`,
          kind: 'method',
          visibility: methodVisibility,
        });
      }
    }

    // Extract exported fields
    for (const field of type.fields) {
      const fieldVisibility = getVisibilityFromModifiers(field.modifiers);
      if (fieldVisibility !== 'private') {
        exports.push({
          symbol: `${type.name}.${field.name}`,
          kind: 'field',
          visibility: fieldVisibility,
        });
      }
    }
  }

  return exports;
}

/**
 * Determine visibility of a type based on common patterns.
 * Types without explicit modifiers in the TypeInfo are assumed public
 * (since we extract from annotations which don't include visibility).
 */
function getTypeVisibility(type: TypeInfo): 'public' | 'protected' | 'package' | 'private' {
  // Check annotations for visibility indicators (some frameworks use them)
  // Default to public for top-level types since Java allows one public class per file
  return 'public';
}

/**
 * Get visibility from modifier list.
 */
function getVisibilityFromModifiers(modifiers: string[]): 'public' | 'protected' | 'package' | 'private' {
  if (modifiers.includes('public')) {
    return 'public';
  }
  if (modifiers.includes('protected')) {
    return 'protected';
  }
  if (modifiers.includes('private')) {
    return 'private';
  }
  // Default is package-private in Java
  return 'package';
}
