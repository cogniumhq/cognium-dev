/**
 * Import extractor - extracts import declarations
 */

import type { Node, Tree } from 'web-tree-sitter';
import type { ImportInfo, SupportedLanguage } from '../../types/index.js';
import { findNodes, getNodeText } from '../parser.js';

/**
 * Detect language from tree structure.
 */
function detectLanguage(tree: Tree): 'javascript' | 'java' | 'python' | 'rust' {
  const root = tree.rootNode;

  // Check for JavaScript-specific nodes
  const jsNodeTypes = new Set([
    'arrow_function', 'lexical_declaration', 'function_declaration',
    'export_statement', 'import_statement'
  ]);

  // Check for Java-specific nodes
  const javaNodeTypes = new Set([
    'package_declaration', 'import_declaration', 'class_declaration',
    'method_declaration', 'annotation'
  ]);

  // Check for Python-specific nodes
  const pythonNodeTypes = new Set([
    'class_definition', 'function_definition', 'decorated_definition',
    'import_from_statement'
  ]);

  // Check for Rust-specific nodes
  const rustNodeTypes = new Set([
    'struct_item', 'impl_item', 'function_item', 'use_declaration',
    'mod_item', 'trait_item', 'enum_item'
  ]);

  let jsScore = 0;
  let javaScore = 0;
  let pythonScore = 0;
  let rustScore = 0;

  for (let i = 0; i < Math.min(root.childCount, 20); i++) {
    const child = root.child(i);
    if (!child) continue;

    if (jsNodeTypes.has(child.type)) jsScore++;
    if (javaNodeTypes.has(child.type)) javaScore++;
    if (pythonNodeTypes.has(child.type)) pythonScore++;
    if (rustNodeTypes.has(child.type)) rustScore++;
  }

  if (rustScore > jsScore && rustScore > javaScore && rustScore > pythonScore) return 'rust';
  if (pythonScore > jsScore && pythonScore > javaScore) return 'python';
  return jsScore > javaScore ? 'javascript' : 'java';
}

/**
 * Extract all imports from the tree.
 */
export function extractImports(tree: Tree, language?: SupportedLanguage): ImportInfo[] {
  const effectiveLanguage = language ?? detectLanguage(tree);
  const isJavaScript = effectiveLanguage === 'javascript' || effectiveLanguage === 'typescript';
  const isPython = effectiveLanguage === 'python';
  const isRust = effectiveLanguage === 'rust';

  if (effectiveLanguage === 'go') {
    return extractGoImports(tree);
  }
  if (isRust) {
    return extractRustImports(tree);
  }
  if (isPython) {
    return extractPythonImports(tree);
  }
  if (isJavaScript) {
    return extractJavaScriptImports(tree);
  }
  return extractJavaImports(tree);
}

/**
 * Extract JavaScript/TypeScript imports.
 */
function extractJavaScriptImports(tree: Tree): ImportInfo[] {
  const imports: ImportInfo[] = [];

  // Find all ES6 import statements
  const importStatements = findNodes(tree.rootNode, 'import_statement');

  for (const importStmt of importStatements) {
    const importInfos = extractJSImportInfo(importStmt);
    imports.push(...importInfos);
  }

  // Find re-export statements: `export { X } from './file'`
  // These create an implicit import dependency that must be tracked by ImportGraph.
  const exportStatements = findNodes(tree.rootNode, 'export_statement');
  for (const exportStmt of exportStatements) {
    const sourceNode = exportStmt.childForFieldName('source');
    if (!sourceNode) continue; // no `from '...'` clause — not a re-export
    const fromPackage = getNodeText(sourceNode).replace(/['"]/g, '');
    if (!fromPackage) continue;
    imports.push({
      imported_name: '*',
      from_package: fromPackage,
      alias: null,
      is_wildcard: true,
      line_number: exportStmt.startPosition.row + 1,
    });
  }

  // Find CommonJS require calls
  const requireCalls = findRequireCalls(tree);
  imports.push(...requireCalls);

  return imports;
}

/**
 * Extract Java imports.
 */
function extractJavaImports(tree: Tree): ImportInfo[] {
  const imports: ImportInfo[] = [];

  // Find all import declarations
  const importDecls = findNodes(tree.rootNode, 'import_declaration');

  for (const importDecl of importDecls) {
    const importInfo = extractJavaImportInfo(importDecl);
    if (importInfo) {
      imports.push(importInfo);
    }
  }

  return imports;
}

/**
 * Extract import information from a JavaScript import_statement node.
 */
function extractJSImportInfo(node: Node): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lineNumber = node.startPosition.row + 1;

  // Get the module source (from 'module')
  const sourceNode = node.childForFieldName('source');
  const fromPackage = sourceNode ? getNodeText(sourceNode).replace(/['"]/g, '') : null;

  // Side-effect import: import 'module'
  if (!node.childForFieldName('import_clause') && !node.childForFieldName('namespace_import')) {
    // Check for named imports directly in the node
    let hasImportClause = false;
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && (child.type === 'import_clause' || child.type === 'namespace_import' ||
                    child.type === 'named_imports' || child.type === 'identifier')) {
        hasImportClause = true;
        break;
      }
    }
    if (!hasImportClause && fromPackage) {
      imports.push({
        imported_name: '*',
        from_package: fromPackage,
        alias: null,
        is_wildcard: true,
        line_number: lineNumber,
      });
      return imports;
    }
  }

  // Look through all children for import components
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    // Default import: import foo from 'module'
    if (child.type === 'identifier') {
      const name = getNodeText(child);
      // Skip 'import' keyword and module source
      if (name !== 'import' && name !== 'from') {
        imports.push({
          imported_name: 'default',
          from_package: fromPackage,
          alias: name,
          is_wildcard: false,
          line_number: lineNumber,
        });
      }
    }

    // Namespace import: import * as ns from 'module'
    if (child.type === 'namespace_import') {
      // Try field name first, then look for identifier child
      let aliasNode = child.childForFieldName('alias');
      if (!aliasNode) {
        // In tree-sitter-javascript, the alias is just an identifier child
        for (let j = 0; j < child.childCount; j++) {
          const subChild = child.child(j);
          if (subChild && subChild.type === 'identifier') {
            aliasNode = subChild;
            break;
          }
        }
      }
      const alias = aliasNode ? getNodeText(aliasNode) : null;
      imports.push({
        imported_name: '*',
        from_package: fromPackage,
        alias,
        is_wildcard: true,
        line_number: lineNumber,
      });
    }

    // Named imports: import { foo, bar as baz } from 'module'
    if (child.type === 'named_imports') {
      for (let j = 0; j < child.namedChildCount; j++) {
        const specifier = child.namedChild(j);
        if (!specifier) continue;

        if (specifier.type === 'import_specifier') {
          const nameNode = specifier.childForFieldName('name');
          const aliasNode = specifier.childForFieldName('alias');

          const importedName = nameNode ? getNodeText(nameNode) : null;
          const alias = aliasNode ? getNodeText(aliasNode) : null;

          if (importedName) {
            imports.push({
              imported_name: importedName,
              from_package: fromPackage,
              alias,
              is_wildcard: false,
              line_number: lineNumber,
            });
          }
        }
      }
    }

    // Import clause might contain default + named imports
    if (child.type === 'import_clause') {
      for (let j = 0; j < child.childCount; j++) {
        const subChild = child.child(j);
        if (!subChild) continue;

        if (subChild.type === 'identifier') {
          const name = getNodeText(subChild);
          imports.push({
            imported_name: 'default',
            from_package: fromPackage,
            alias: name,
            is_wildcard: false,
            line_number: lineNumber,
          });
        }

        if (subChild.type === 'namespace_import') {
          let aliasNode = subChild.childForFieldName('alias');
          if (!aliasNode) {
            for (let k = 0; k < subChild.childCount; k++) {
              const nsChild = subChild.child(k);
              if (nsChild && nsChild.type === 'identifier') {
                aliasNode = nsChild;
                break;
              }
            }
          }
          const alias = aliasNode ? getNodeText(aliasNode) : null;
          imports.push({
            imported_name: '*',
            from_package: fromPackage,
            alias,
            is_wildcard: true,
            line_number: lineNumber,
          });
        }

        if (subChild.type === 'named_imports') {
          for (let k = 0; k < subChild.namedChildCount; k++) {
            const specifier = subChild.namedChild(k);
            if (!specifier || specifier.type !== 'import_specifier') continue;

            const nameNode = specifier.childForFieldName('name');
            const aliasNode = specifier.childForFieldName('alias');

            const importedName = nameNode ? getNodeText(nameNode) : null;
            const alias = aliasNode ? getNodeText(aliasNode) : null;

            if (importedName) {
              imports.push({
                imported_name: importedName,
                from_package: fromPackage,
                alias,
                is_wildcard: false,
                line_number: lineNumber,
              });
            }
          }
        }
      }
    }
  }

  return imports;
}

/**
 * Find CommonJS require calls: const x = require('module')
 */
function findRequireCalls(tree: Tree): ImportInfo[] {
  const imports: ImportInfo[] = [];

  // Find all call expressions
  const callExpressions = findNodes(tree.rootNode, 'call_expression');

  for (const call of callExpressions) {
    const funcNode = call.childForFieldName('function');
    if (!funcNode || getNodeText(funcNode) !== 'require') continue;

    const argsNode = call.childForFieldName('arguments');
    if (!argsNode) continue;

    // Get the module path from first argument
    const firstArg = argsNode.namedChild(0);
    if (!firstArg || (firstArg.type !== 'string' && firstArg.type !== 'template_string')) continue;

    const fromPackage = getNodeText(firstArg).replace(/['"]/g, '');
    const lineNumber = call.startPosition.row + 1;

    // Try to find the variable being assigned
    let alias: string | null = null;
    const parent = call.parent;

    if (parent?.type === 'variable_declarator') {
      const nameNode = parent.childForFieldName('name');
      if (nameNode) {
        if (nameNode.type === 'identifier') {
          alias = getNodeText(nameNode);
        } else if (nameNode.type === 'object_pattern') {
          // Destructuring: const { foo, bar } = require('module')
          for (let i = 0; i < nameNode.namedChildCount; i++) {
            const prop = nameNode.namedChild(i);
            if (!prop) continue;

            if (prop.type === 'shorthand_property_identifier_pattern') {
              const name = getNodeText(prop);
              imports.push({
                imported_name: name,
                from_package: fromPackage,
                alias: null,
                is_wildcard: false,
                line_number: lineNumber,
              });
            } else if (prop.type === 'pair_pattern') {
              const keyNode = prop.childForFieldName('key');
              const valueNode = prop.childForFieldName('value');
              const importedName = keyNode ? getNodeText(keyNode) : null;
              const propAlias = valueNode && valueNode.type === 'identifier' ? getNodeText(valueNode) : null;

              if (importedName) {
                imports.push({
                  imported_name: importedName,
                  from_package: fromPackage,
                  alias: propAlias,
                  is_wildcard: false,
                  line_number: lineNumber,
                });
              }
            }
          }
          continue; // Continue to next call expression instead of returning
        }
      }
    }

    imports.push({
      imported_name: '*',
      from_package: fromPackage,
      alias,
      is_wildcard: true,
      line_number: lineNumber,
    });
  }

  return imports;
}

/**
 * Extract import information from a Java import_declaration node.
 */
function extractJavaImportInfo(node: Node): ImportInfo | null {
  // Note: Static imports (import static ...) are parsed the same way.
  // The hasStaticModifier() helper exists if we need to distinguish them later.

  // Get the full import path
  const scopedId = findScopedIdentifier(node);
  if (!scopedId) return null;

  const fullPath = getNodeText(scopedId);

  // Check for wildcard import
  const isWildcard = fullPath.endsWith('.*') || hasWildcard(node);

  // Parse the import path
  const { importedName, fromPackage } = parseImportPath(fullPath, isWildcard);

  return {
    imported_name: importedName,
    from_package: fromPackage,
    alias: null, // Java doesn't support import aliases
    is_wildcard: isWildcard,
    line_number: node.startPosition.row + 1,
  };
}

/**
 * Check if the import has the static modifier.
 */
function hasStaticModifier(node: Node): boolean {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child && child.type === 'static') {
      return true;
    }
  }
  return false;
}

/**
 * Check if the import has a wildcard asterisk.
 */
function hasWildcard(node: Node): boolean {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child && child.type === 'asterisk') {
      return true;
    }
  }
  return false;
}

/**
 * Find the scoped identifier in an import declaration.
 */
function findScopedIdentifier(node: Node): Node | null {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === 'scoped_identifier' || child.type === 'identifier') {
      return child;
    }
  }
  return null;
}

/**
 * Parse an import path into imported name and package.
 */
function parseImportPath(fullPath: string, isWildcard: boolean): { importedName: string; fromPackage: string | null } {
  if (isWildcard) {
    // For "java.util.*", package is "java.util", name is "*"
    const cleanPath = fullPath.replace('.*', '').replace('*', '');
    return {
      importedName: '*',
      fromPackage: cleanPath || null,
    };
  }

  // For "java.util.ArrayList", package is "java.util", name is "ArrayList"
  const lastDot = fullPath.lastIndexOf('.');
  if (lastDot === -1) {
    return {
      importedName: fullPath,
      fromPackage: null,
    };
  }

  return {
    importedName: fullPath.substring(lastDot + 1),
    fromPackage: fullPath.substring(0, lastDot),
  };
}

// =============================================================================
// Python Import Extraction
// =============================================================================

/**
 * Extract Python imports.
 */
function extractPythonImports(tree: Tree): ImportInfo[] {
  const imports: ImportInfo[] = [];

  // Find all import statements: import os, sys
  const importStatements = findNodes(tree.rootNode, 'import_statement');
  for (const stmt of importStatements) {
    const importInfos = extractPythonImportStatement(stmt);
    imports.push(...importInfos);
  }

  // Find all from-import statements: from os import path
  const importFromStatements = findNodes(tree.rootNode, 'import_from_statement');
  for (const stmt of importFromStatements) {
    const importInfos = extractPythonFromImportStatement(stmt);
    imports.push(...importInfos);
  }

  return imports;
}

/**
 * Extract import information from a Python import_statement node.
 * Handles: import os, import os.path, import os as operating_system
 */
function extractPythonImportStatement(node: Node): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lineNumber = node.startPosition.row + 1;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === 'dotted_name') {
      const fullName = getNodeText(child);
      const parts = fullName.split('.');
      imports.push({
        imported_name: parts[parts.length - 1],
        from_package: parts.length > 1 ? parts.slice(0, -1).join('.') : null,
        alias: null,
        is_wildcard: false,
        line_number: lineNumber,
      });
    } else if (child.type === 'aliased_import') {
      const nameNode = child.childForFieldName('name');
      const aliasNode = child.childForFieldName('alias');
      if (nameNode) {
        const fullName = getNodeText(nameNode);
        const parts = fullName.split('.');
        imports.push({
          imported_name: parts[parts.length - 1],
          from_package: parts.length > 1 ? parts.slice(0, -1).join('.') : null,
          alias: aliasNode ? getNodeText(aliasNode) : null,
          is_wildcard: false,
          line_number: lineNumber,
        });
      }
    }
  }

  return imports;
}

/**
 * Extract import information from a Python import_from_statement node.
 * Handles: from os import path, from os import path as p, from os import *
 */
function extractPythonFromImportStatement(node: Node): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lineNumber = node.startPosition.row + 1;

  // Get the module name
  const moduleNode = node.childForFieldName('module_name');
  let fromPackage = moduleNode ? getNodeText(moduleNode) : null;

  // Handle relative imports: from . import x, from .. import x
  if (!fromPackage) {
    // Check for relative import dots
    let relativeDots = '';
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type === 'relative_import') {
        relativeDots = getNodeText(child);
        break;
      }
    }
    if (relativeDots) {
      fromPackage = relativeDots;
    }
  }

  // Extract imported names
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    // Wildcard import: from os import *
    if (child.type === 'wildcard_import') {
      imports.push({
        imported_name: '*',
        from_package: fromPackage,
        alias: null,
        is_wildcard: true,
        line_number: lineNumber,
      });
    }
    // Simple name: from os import path
    else if (child.type === 'dotted_name' && child !== moduleNode) {
      imports.push({
        imported_name: getNodeText(child),
        from_package: fromPackage,
        alias: null,
        is_wildcard: false,
        line_number: lineNumber,
      });
    }
    // Aliased import: from os import path as p
    else if (child.type === 'aliased_import') {
      const nameNode = child.childForFieldName('name');
      const aliasNode = child.childForFieldName('alias');
      if (nameNode) {
        imports.push({
          imported_name: getNodeText(nameNode),
          from_package: fromPackage,
          alias: aliasNode ? getNodeText(aliasNode) : null,
          is_wildcard: false,
          line_number: lineNumber,
        });
      }
    }
  }

  return imports;
}

// =============================================================================
// Rust Import Extraction
// =============================================================================

/**
 * Extract Rust use declarations.
 */
function extractRustImports(tree: Tree): ImportInfo[] {
  const imports: ImportInfo[] = [];

  // Find all use declarations
  const useDecls = findNodes(tree.rootNode, 'use_declaration');

  for (const useDecl of useDecls) {
    const useImports = extractRustUseDecl(useDecl);
    imports.push(...useImports);
  }

  return imports;
}

/**
 * Extract imports from a Rust use declaration.
 * Handles various forms:
 * - use std::io;
 * - use std::collections::HashMap;
 * - use actix_web::{web, App, HttpServer};
 * - use foo::bar::*;
 * - use crate::module::Type as Alias;
 */
function extractRustUseDecl(node: Node): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lineNumber = node.startPosition.row + 1;
  const text = getNodeText(node);

  // Find the use_list or scoped_identifier or identifier inside
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === 'scoped_identifier') {
      // Simple use: use std::io;
      const parts = getNodeText(child).split('::');
      const importedName = parts.pop() || '';
      const fromPackage = parts.join('::');

      imports.push({
        imported_name: importedName,
        from_package: fromPackage || null,
        alias: null,
        is_wildcard: importedName === '*',
        line_number: lineNumber,
      });
    } else if (child.type === 'scoped_use_list') {
      // Grouped use: use foo::{Bar, Baz};
      const scopedImports = extractRustScopedUseList(child, lineNumber);
      imports.push(...scopedImports);
    } else if (child.type === 'use_as_clause') {
      // Aliased import: use foo::Bar as B;
      const pathNode = child.childForFieldName('path');
      const aliasNode = child.childForFieldName('alias');

      if (pathNode) {
        const parts = getNodeText(pathNode).split('::');
        const importedName = parts.pop() || '';
        const fromPackage = parts.join('::');

        imports.push({
          imported_name: importedName,
          from_package: fromPackage || null,
          alias: aliasNode ? getNodeText(aliasNode) : null,
          is_wildcard: false,
          line_number: lineNumber,
        });
      }
    } else if (child.type === 'use_wildcard') {
      // Wildcard: use foo::*;
      const pathNode = child.childForFieldName('path');
      const fromPackage = pathNode ? getNodeText(pathNode) : null;

      imports.push({
        imported_name: '*',
        from_package: fromPackage,
        alias: null,
        is_wildcard: true,
        line_number: lineNumber,
      });
    } else if (child.type === 'identifier') {
      // Single identifier: use std; (rare)
      imports.push({
        imported_name: getNodeText(child),
        from_package: null,
        alias: null,
        is_wildcard: false,
        line_number: lineNumber,
      });
    }
  }

  return imports;
}

/**
 * Extract imports from a Rust scoped_use_list.
 * e.g., use actix_web::{web, App, HttpServer};
 */
function extractRustScopedUseList(node: Node, lineNumber: number): ImportInfo[] {
  const imports: ImportInfo[] = [];

  // Find the base path (before the {})
  let basePath = '';
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === 'scoped_identifier' || child.type === 'identifier') {
      basePath = getNodeText(child);
      break;
    }
  }

  // Find the use_list (inside {})
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child || child.type !== 'use_list') continue;

    // Extract each item in the use list
    for (let j = 0; j < child.childCount; j++) {
      const item = child.child(j);
      if (!item) continue;

      if (item.type === 'identifier') {
        imports.push({
          imported_name: getNodeText(item),
          from_package: basePath || null,
          alias: null,
          is_wildcard: false,
          line_number: lineNumber,
        });
      } else if (item.type === 'scoped_identifier') {
        // Nested path in use list
        const parts = getNodeText(item).split('::');
        const importedName = parts.pop() || '';
        const nestedPath = parts.join('::');
        const fullPath = basePath ? `${basePath}::${nestedPath}` : nestedPath;

        imports.push({
          imported_name: importedName,
          from_package: fullPath || null,
          alias: null,
          is_wildcard: false,
          line_number: lineNumber,
        });
      } else if (item.type === 'use_as_clause') {
        const pathNode = item.childForFieldName('path');
        const aliasNode = item.childForFieldName('alias');

        if (pathNode) {
          const pathText = getNodeText(pathNode);
          // Handle both simple identifier and scoped path
          if (pathText.includes('::')) {
            const parts = pathText.split('::');
            const importedName = parts.pop() || '';
            const nestedPath = parts.join('::');
            const fullPath = basePath ? `${basePath}::${nestedPath}` : nestedPath;

            imports.push({
              imported_name: importedName,
              from_package: fullPath || null,
              alias: aliasNode ? getNodeText(aliasNode) : null,
              is_wildcard: false,
              line_number: lineNumber,
            });
          } else {
            imports.push({
              imported_name: pathText,
              from_package: basePath || null,
              alias: aliasNode ? getNodeText(aliasNode) : null,
              is_wildcard: false,
              line_number: lineNumber,
            });
          }
        }
      } else if (item.type === 'self') {
        // use foo::{self}; imports the module itself
        imports.push({
          imported_name: 'self',
          from_package: basePath || null,
          alias: null,
          is_wildcard: false,
          line_number: lineNumber,
        });
      }
    }
  }

  return imports;
}

// =============================================================================
// Go Import Extraction
// =============================================================================

/**
 * Extract Go imports.
 */
function extractGoImports(tree: Tree): ImportInfo[] {
  const imports: ImportInfo[] = [];

  const importDecls = findNodes(tree.rootNode, 'import_declaration');
  for (const decl of importDecls) {
    // Single import: import "fmt"
    const singleSpec = findGoChildByType(decl, 'import_spec');
    if (singleSpec) {
      const parsed = parseGoImportSpec(singleSpec);
      if (parsed) imports.push(parsed);
      continue;
    }

    // Grouped imports: import ( "fmt"; "net/http" )
    const specList = findGoChildByType(decl, 'import_spec_list');
    if (specList) {
      for (let i = 0; i < specList.childCount; i++) {
        const spec = specList.child(i);
        if (!spec || spec.type !== 'import_spec') continue;
        const parsed = parseGoImportSpec(spec);
        if (parsed) imports.push(parsed);
      }
    }
  }

  return imports;
}

/**
 * Parse a single Go import_spec node.
 */
function parseGoImportSpec(spec: Node): ImportInfo | null {
  let alias: string | null = null;
  let path: string | undefined;

  for (let i = 0; i < spec.childCount; i++) {
    const child = spec.child(i);
    if (!child) continue;
    if (child.type === 'package_identifier' || child.type === 'blank_identifier' || child.type === 'dot') {
      alias = getNodeText(child);
    }
    if (child.type === 'interpreted_string_literal') {
      const text = getNodeText(child);
      path = text.slice(1, -1); // Remove quotes
    }
  }

  if (!path) return null;

  // Extract short name from path (e.g., "net/http" → "http")
  const shortName = alias || path.split('/').pop() || path;

  return {
    imported_name: shortName,
    from_package: path,
    alias,
    is_wildcard: alias === '.',
    line_number: spec.startPosition.row + 1,
  };
}

/**
 * Find child node by type (Go-specific helper to avoid naming conflicts).
 */
function findGoChildByType(node: Node, type: string): Node | null {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === type) {
      return child;
    }
  }
  return null;
}
