/**
 * Type extractor - extracts classes, interfaces, enums, methods, and fields
 */

import type { Node, Tree } from 'web-tree-sitter';
import type { TypeInfo, MethodInfo, ParameterInfo, FieldInfo, SupportedLanguage } from '../../types/index.js';
import { findNodes, getNodeText, getNodesFromCache, type NodeCache } from '../parser.js';

/**
 * Detect language from tree structure.
 */
function detectLanguage(tree: Tree): 'javascript' | 'java' | 'python' | 'rust' {
  const root = tree.rootNode;

  const jsNodeTypes = new Set([
    'arrow_function', 'lexical_declaration', 'function_declaration',
    'export_statement', 'import_statement'
  ]);

  const javaNodeTypes = new Set([
    'package_declaration', 'import_declaration', 'method_declaration',
    'annotation'
  ]);

  const pythonNodeTypes = new Set([
    'class_definition', 'function_definition', 'decorated_definition',
    'import_from_statement', 'import_statement'
  ]);

  const rustNodeTypes = new Set([
    'struct_item', 'impl_item', 'function_item', 'use_declaration',
    'mod_item', 'trait_item', 'enum_item', 'macro_invocation'
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
 * Extract all type definitions from the tree.
 */
export function extractTypes(tree: Tree, cache?: NodeCache, language?: SupportedLanguage): TypeInfo[] {
  const effectiveLanguage = language ?? detectLanguage(tree);
  const isJavaScript = effectiveLanguage === 'javascript' || effectiveLanguage === 'typescript';
  const isPython = effectiveLanguage === 'python';
  const isRust = effectiveLanguage === 'rust';

  if (effectiveLanguage === 'go') {
    return extractGoTypes(tree, cache);
  }
  if (isRust) {
    return extractRustTypes(tree, cache);
  }
  if (isPython) {
    return extractPythonTypes(tree, cache);
  }
  if (isJavaScript) {
    return extractJavaScriptTypes(tree, cache);
  }
  return extractJavaTypes(tree, cache);
}

/**
 * Extract Java types.
 */
function extractJavaTypes(tree: Tree, cache?: NodeCache): TypeInfo[] {
  const types: TypeInfo[] = [];

  // Extract classes
  const classes = getNodesFromCache(tree.rootNode, 'class_declaration', cache);
  for (const cls of classes) {
    types.push(extractClassInfo(cls));
  }

  // Extract interfaces
  const interfaces = getNodesFromCache(tree.rootNode, 'interface_declaration', cache);
  for (const iface of interfaces) {
    types.push(extractInterfaceInfo(iface));
  }

  // Extract enums
  const enums = getNodesFromCache(tree.rootNode, 'enum_declaration', cache);
  for (const enumDecl of enums) {
    types.push(extractEnumInfo(enumDecl));
  }

  return types;
}

/**
 * Extract JavaScript/TypeScript types.
 */
function extractJavaScriptTypes(tree: Tree, cache?: NodeCache): TypeInfo[] {
  const types: TypeInfo[] = [];

  // Extract classes
  const classes = getNodesFromCache(tree.rootNode, 'class_declaration', cache);
  for (const cls of classes) {
    types.push(extractJSClassInfo(cls));
  }

  // Extract standalone functions as a module-like type
  const functions = getNodesFromCache(tree.rootNode, 'function_declaration', cache);
  if (functions.length > 0) {
    const moduleFunctions: MethodInfo[] = [];
    for (const func of functions) {
      moduleFunctions.push(extractJSFunctionInfo(func));
    }

    // Create a synthetic module type for standalone functions
    if (moduleFunctions.length > 0) {
      types.push({
        name: '<module>',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: moduleFunctions,
        fields: [],
        start_line: 1,
        end_line: tree.rootNode.endPosition.row + 1,
      });
    }
  }

  // Extract arrow functions assigned to const/let
  const arrowFuncs = extractNamedArrowFunctions(tree, cache);
  if (arrowFuncs.length > 0) {
    // Add to existing module or create one
    const moduleType = types.find(t => t.name === '<module>');
    if (moduleType) {
      moduleType.methods.push(...arrowFuncs);
    } else {
      types.push({
        name: '<module>',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: arrowFuncs,
        fields: [],
        start_line: 1,
        end_line: tree.rootNode.endPosition.row + 1,
      });
    }
  }

  return types;
}

/**
 * Extract Python types.
 */
function extractPythonTypes(tree: Tree, cache?: NodeCache): TypeInfo[] {
  const types: TypeInfo[] = [];

  // Extract classes (including decorated classes)
  const classes = getNodesFromCache(tree.rootNode, 'class_definition', cache);
  for (const cls of classes) {
    types.push(extractPythonClassInfo(cls));
  }

  // Extract standalone functions as a module-like type
  const functions = getNodesFromCache(tree.rootNode, 'function_definition', cache);
  const topLevelFunctions: MethodInfo[] = [];

  for (const func of functions) {
    // Only include top-level functions (not methods inside classes)
    if (func.parent?.type === 'module' || func.parent?.type === 'decorated_definition') {
      // Check if this is inside a class (nested in decorated_definition that's in a class)
      let parent: Node | null = func.parent;
      let isInsideClass = false;
      while (parent) {
        if (parent.type === 'class_definition') {
          isInsideClass = true;
          break;
        }
        if (parent.type === 'module') break;
        parent = parent.parent;
      }
      if (!isInsideClass) {
        topLevelFunctions.push(extractPythonFunctionInfo(func));
      }
    }
  }

  // Create a synthetic module type for standalone functions
  if (topLevelFunctions.length > 0 || types.length === 0) {
    const moduleType = types.find(t => t.name === '<module>');
    if (moduleType) {
      moduleType.methods.push(...topLevelFunctions);
    } else {
      types.push({
        name: '<module>',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: topLevelFunctions,
        fields: [],
        start_line: 1,
        end_line: tree.rootNode.endPosition.row + 1,
      });
    }
  }

  return types;
}

/**
 * Extract Python class information.
 */
function extractPythonClassInfo(node: Node): TypeInfo {
  const nameNode = node.childForFieldName('name');
  const name = nameNode ? getNodeText(nameNode) : 'Anonymous';

  // Extract base classes (Python supports multiple inheritance)
  let extendsType: string | null = null;
  const implementsList: string[] = [];

  const superclassNode = node.childForFieldName('superclasses');
  if (superclassNode) {
    const baseClasses = extractPythonBaseClasses(superclassNode);
    if (baseClasses.length > 0) {
      extendsType = baseClasses[0];
      implementsList.push(...baseClasses.slice(1));
    }
  }

  // Extract decorators as annotations
  const annotations = extractPythonDecorators(node);

  // Extract body
  const body = node.childForFieldName('body');
  const methods = body ? extractPythonMethods(body) : [];
  const fields = body ? extractPythonFields(body, methods) : [];

  return {
    name,
    kind: 'class',
    package: null, // Python uses module paths, not package declarations
    extends: extendsType,
    implements: implementsList,
    annotations,
    methods,
    fields,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract base classes from Python superclasses node.
 */
function extractPythonBaseClasses(node: Node): string[] {
  const bases: string[] = [];

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    // Skip punctuation
    if (child.type === ',' || child.type === '(' || child.type === ')') continue;

    if (child.type === 'identifier' || child.type === 'attribute') {
      bases.push(getNodeText(child));
    } else if (child.type === 'argument_list') {
      // For class Foo(Base1, Base2):
      for (let j = 0; j < child.childCount; j++) {
        const arg = child.child(j);
        if (arg && (arg.type === 'identifier' || arg.type === 'attribute')) {
          bases.push(getNodeText(arg));
        }
      }
    }
  }

  return bases;
}

/**
 * Extract decorators from a Python class or function.
 */
function extractPythonDecorators(node: Node): string[] {
  const decorators: string[] = [];

  // Check if this node is wrapped in a decorated_definition
  const parent = node.parent;
  if (parent?.type === 'decorated_definition') {
    for (let i = 0; i < parent.childCount; i++) {
      const child = parent.child(i);
      if (child?.type === 'decorator') {
        let text = getNodeText(child);
        // Remove the @ prefix
        if (text.startsWith('@')) {
          text = text.substring(1);
        }
        decorators.push(text);
      }
    }
  }

  return decorators;
}

/**
 * Extract methods from a Python class body.
 */
function extractPythonMethods(body: Node): MethodInfo[] {
  const methods: MethodInfo[] = [];

  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    if (child.type === 'function_definition') {
      methods.push(extractPythonMethodInfo(child));
    } else if (child.type === 'decorated_definition') {
      // Find the function inside the decorated definition
      for (let j = 0; j < child.childCount; j++) {
        const inner = child.child(j);
        if (inner?.type === 'function_definition') {
          methods.push(extractPythonMethodInfo(inner));
          break;
        }
      }
    }
  }

  return methods;
}

/**
 * Extract Python method information.
 */
function extractPythonMethodInfo(node: Node): MethodInfo {
  const nameNode = node.childForFieldName('name');
  const name = nameNode ? getNodeText(nameNode) : 'anonymous';

  // Extract parameters
  const params = node.childForFieldName('parameters');
  const parameters = params ? extractPythonParameters(params) : [];

  // Extract return type annotation
  const returnTypeNode = node.childForFieldName('return_type');
  const returnType = returnTypeNode ? getNodeText(returnTypeNode) : null;

  // Extract decorators as annotations
  const annotations = extractPythonDecorators(node);

  // Determine modifiers from decorators and method name
  const modifiers: string[] = [];
  if (annotations.includes('staticmethod')) modifiers.push('static');
  if (annotations.includes('classmethod')) modifiers.push('classmethod');
  if (annotations.includes('property')) modifiers.push('property');

  // Check for async
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === 'async') {
      modifiers.push('async');
      break;
    }
  }

  return {
    name,
    return_type: returnType,
    parameters,
    annotations,
    modifiers,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract Python function information (standalone function).
 */
function extractPythonFunctionInfo(node: Node): MethodInfo {
  // Same as method info extraction
  return extractPythonMethodInfo(node);
}

/**
 * Extract Python parameters.
 */
function extractPythonParameters(params: Node): ParameterInfo[] {
  const parameters: ParameterInfo[] = [];

  for (let i = 0; i < params.childCount; i++) {
    const child = params.child(i);
    if (!child) continue;

    // Skip punctuation
    if (child.type === ',' || child.type === '(' || child.type === ')' || child.type === ':') continue;

    if (child.type === 'identifier') {
      parameters.push({
        name: getNodeText(child),
        type: null,
        annotations: [],
        line: child.startPosition.row + 1,
      });
    } else if (child.type === 'typed_parameter') {
      const nameNode = child.namedChild(0);
      const typeNode = child.childForFieldName('type');
      parameters.push({
        name: nameNode ? getNodeText(nameNode) : 'arg',
        type: typeNode ? getNodeText(typeNode) : null,
        annotations: [],
        line: child.startPosition.row + 1,
      });
    } else if (child.type === 'default_parameter' || child.type === 'typed_default_parameter') {
      const nameNode = child.childForFieldName('name');
      const typeNode = child.childForFieldName('type');
      parameters.push({
        name: nameNode ? getNodeText(nameNode) : 'arg',
        type: typeNode ? getNodeText(typeNode) : null,
        annotations: [],
        line: child.startPosition.row + 1,
      });
    } else if (child.type === 'list_splat_pattern' || child.type === 'dictionary_splat_pattern') {
      // *args or **kwargs
      const nameNode = child.namedChild(0);
      const prefix = child.type === 'dictionary_splat_pattern' ? '**' : '*';
      parameters.push({
        name: prefix + (nameNode ? getNodeText(nameNode) : 'args'),
        type: null,
        annotations: [],
        line: child.startPosition.row + 1,
      });
    }
  }

  return parameters;
}

/**
 * Extract Python class fields from assignments in the class body.
 */
function extractPythonFields(body: Node, methods: MethodInfo[]): FieldInfo[] {
  const fields: FieldInfo[] = [];
  const fieldNames = new Set<string>();

  // Look for class-level assignments
  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    if (child.type === 'expression_statement') {
      const expr = child.namedChild(0);
      if (expr?.type === 'assignment') {
        const left = expr.childForFieldName('left');
        if (left?.type === 'identifier') {
          const name = getNodeText(left);
          if (!fieldNames.has(name)) {
            fieldNames.add(name);
            fields.push({
              name,
              type: null,
              modifiers: [],
              annotations: [],
            });
          }
        }
      }
    }
  }

  // Also extract self.field assignments from __init__ method
  const initMethod = methods.find(m => m.name === '__init__');
  if (initMethod) {
    // We need to look at the actual __init__ body for self.x = ... assignments
    // This requires re-finding the __init__ method node
    for (let i = 0; i < body.childCount; i++) {
      const child = body.child(i);
      if (!child) continue;

      let funcNode: Node | null = null;
      if (child.type === 'function_definition') {
        funcNode = child;
      } else if (child.type === 'decorated_definition') {
        for (let j = 0; j < child.childCount; j++) {
          const inner = child.child(j);
          if (inner?.type === 'function_definition') {
            funcNode = inner;
            break;
          }
        }
      }

      if (funcNode) {
        const nameNode = funcNode.childForFieldName('name');
        if (nameNode && getNodeText(nameNode) === '__init__') {
          const funcBody = funcNode.childForFieldName('body');
          if (funcBody) {
            extractSelfAssignments(funcBody, fields, fieldNames);
          }
          break;
        }
      }
    }
  }

  return fields;
}

/**
 * Extract self.field assignments from a function body.
 */
function extractSelfAssignments(body: Node, fields: FieldInfo[], fieldNames: Set<string>): void {
  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    if (child.type === 'expression_statement') {
      const expr = child.namedChild(0);
      if (expr?.type === 'assignment') {
        const left = expr.childForFieldName('left');
        if (left?.type === 'attribute') {
          const obj = left.childForFieldName('object');
          const attr = left.childForFieldName('attribute');
          if (obj && getNodeText(obj) === 'self' && attr) {
            const name = getNodeText(attr);
            if (!fieldNames.has(name)) {
              fieldNames.add(name);
              fields.push({
                name,
                type: null,
                modifiers: [],
                annotations: [],
              });
            }
          }
        }
      }
    }
  }
}

/**
 * Extract JavaScript class information.
 */
function extractJSClassInfo(node: Node): TypeInfo {
  const name = getIdentifier(node, 'name') ?? 'Anonymous';

  // Extract superclass (extends)
  let extendsType: string | null = null;

  // Try to find class_heritage or heritage node
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    // In tree-sitter-javascript, extends is a class_heritage node
    if (child.type === 'class_heritage') {
      // Find the identifier inside class_heritage
      for (let j = 0; j < child.childCount; j++) {
        const grandChild = child.child(j);
        if (grandChild && grandChild.type === 'identifier') {
          extendsType = getNodeText(grandChild);
          break;
        }
        // Also check for member_expression (e.g., Module.Class)
        if (grandChild && grandChild.type === 'member_expression') {
          extendsType = getNodeText(grandChild);
          break;
        }
      }
      break;
    }
  }

  // Extract body
  const body = node.childForFieldName('body');
  const methods = body ? extractJSMethods(body) : [];
  const fields = body ? extractJSFields(body) : [];

  return {
    name,
    kind: 'class',
    package: null,
    extends: extendsType,
    implements: [],
    annotations: [],
    methods,
    fields,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract the name of a `decorator` node (TypeScript / NestJS / Angular etc).
 *
 * The grammar permits three shapes:
 *   @Foo            → decorator > identifier
 *   @Foo('bar')     → decorator > call_expression > identifier
 *   @ns.Foo         → decorator > member_expression (use .property)
 *   @ns.Foo('bar')  → decorator > call_expression > member_expression
 */
function extractDecoratorName(node: Node): string | null {
  // tree-sitter-typescript stores the decorator expression as namedChild(0)
  const child = node.namedChildCount > 0 ? node.namedChild(0) : null;
  if (!child) return null;
  if (child.type === 'identifier') return getNodeText(child);
  if (child.type === 'call_expression') {
    const fn = child.childForFieldName('function');
    if (fn) {
      if (fn.type === 'identifier') return getNodeText(fn);
      if (fn.type === 'member_expression') {
        const propNode = fn.childForFieldName('property');
        if (propNode) return getNodeText(propNode);
      }
    }
  }
  if (child.type === 'member_expression') {
    const propNode = child.childForFieldName('property');
    if (propNode) return getNodeText(propNode);
  }
  return null;
}

/**
 * Extract JavaScript methods from a class body.
 *
 * Method-level decorators (TS / NestJS / Angular) appear as preceding
 * `decorator` siblings of `method_definition` inside `class_body`. We accumulate
 * them as we walk children and attach to the very next `method_definition`.
 *
 * IMPORTANT: `pendingDecorators` is reset on ANY non-decorator class member
 * (field, accessor, abstract signature, …), not just method_definition. A
 * decorator preceding a field like
 *
 *   @Inject('USER_REPO') private repo: Repository<User>;
 *   @Get('search') async search(...) { ... }
 *
 * belongs to the field, not the method below. Failing to reset after the
 * field_definition would silently transfer `Inject` onto `search.annotations`,
 * polluting the IR consumed by taint-matcher.ts (`matchesAnnotation` against
 * `pattern.method_annotation`).
 */
function extractJSMethods(body: Node): MethodInfo[] {
  const methods: MethodInfo[] = [];
  let pendingDecorators: string[] = [];

  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    if (child.type === 'decorator') {
      const name = extractDecoratorName(child);
      if (name) pendingDecorators.push(name);
      continue;
    }

    // Tree-sitter emits comments as anonymous children of `class_body`.
    // A `// note` line between a decorator and its method must NOT clear
    // the pending decorator list — skip without resetting.
    if (child.type === 'comment') continue;

    if (child.type === 'method_definition') {
      const m = extractJSMethodInfo(child);
      if (pendingDecorators.length > 0) {
        m.annotations = pendingDecorators;
      }
      methods.push(m);
    }

    // Reset pending decorators on ANY non-decorator, non-comment child
    // (method, field, accessor, abstract_method_signature,
    // public_field_definition, …). Decorators only ever apply to the
    // immediately-following member.
    pendingDecorators = [];
  }

  return methods;
}

/**
 * Extract JavaScript method information.
 */
function extractJSMethodInfo(node: Node): MethodInfo {
  const nameNode = node.childForFieldName('name');
  const name = nameNode ? getNodeText(nameNode) : 'anonymous';

  // Extract parameters
  const params = node.childForFieldName('parameters');
  const parameters = params ? extractJSParameters(params) : [];

  // Check if it's a getter/setter
  const modifiers: string[] = [];
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) {
      if (child.type === 'get') modifiers.push('getter');
      if (child.type === 'set') modifiers.push('setter');
      if (child.type === 'static') modifiers.push('static');
      if (child.type === 'async') modifiers.push('async');
    }
  }

  return {
    name,
    return_type: null, // JavaScript doesn't have explicit return types
    parameters,
    annotations: [],
    modifiers,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract JavaScript function declaration information.
 */
function extractJSFunctionInfo(node: Node): MethodInfo {
  const nameNode = node.childForFieldName('name');
  const name = nameNode ? getNodeText(nameNode) : 'anonymous';

  // Extract parameters
  const params = node.childForFieldName('parameters');
  const parameters = params ? extractJSParameters(params) : [];

  // Check for async/generator
  const modifiers: string[] = [];
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) {
      if (child.type === 'async') modifiers.push('async');
      if (child.type === '*') modifiers.push('generator');
    }
  }

  return {
    name,
    return_type: null,
    parameters,
    annotations: [],
    modifiers,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract named arrow functions (const foo = () => {})
 */
function extractNamedArrowFunctions(tree: Tree, cache?: NodeCache): MethodInfo[] {
  const functions: MethodInfo[] = [];

  // Find top-level variable declarations with arrow functions
  const declarations = [
    ...getNodesFromCache(tree.rootNode, 'lexical_declaration', cache),
    ...getNodesFromCache(tree.rootNode, 'variable_declaration', cache),
  ];

  for (const decl of declarations) {
    // Only process top-level declarations
    if (decl.parent?.type !== 'program' && decl.parent?.type !== 'export_statement') {
      continue;
    }

    const declarators = findNodes(decl, 'variable_declarator');
    for (const declarator of declarators) {
      const nameNode = declarator.childForFieldName('name');
      const valueNode = declarator.childForFieldName('value');

      if (nameNode && nameNode.type === 'identifier' &&
          valueNode && valueNode.type === 'arrow_function') {
        const name = getNodeText(nameNode);

        // Extract parameters from arrow function
        const params = valueNode.childForFieldName('parameters');
        const parameters = params ? extractJSParameters(params) : [];

        // Check for single parameter without parentheses
        if (!params) {
          const paramNode = valueNode.childForFieldName('parameter');
          if (paramNode && paramNode.type === 'identifier') {
            parameters.push({
              name: getNodeText(paramNode),
              type: null,
              annotations: [],
              line: paramNode.startPosition.row + 1,
            });
          }
        }

        const modifiers: string[] = [];
        for (let i = 0; i < valueNode.childCount; i++) {
          const child = valueNode.child(i);
          if (child && child.type === 'async') {
            modifiers.push('async');
            break;
          }
        }

        functions.push({
          name,
          return_type: null,
          parameters,
          annotations: [],
          modifiers,
          start_line: declarator.startPosition.row + 1,
          end_line: declarator.endPosition.row + 1,
        });
      }
    }
  }

  return functions;
}

/**
 * Extract JavaScript parameters.
 */
function extractJSParameters(params: Node): ParameterInfo[] {
  const parameters: ParameterInfo[] = [];

  for (let i = 0; i < params.childCount; i++) {
    const child = params.child(i);
    if (!child) continue;

    // Skip punctuation
    if (child.type === ',' || child.type === '(' || child.type === ')') continue;

    if (child.type === 'identifier') {
      parameters.push({
        name: getNodeText(child),
        type: null,
        annotations: [],
        line: child.startPosition.row + 1,
      });
    } else if (child.type === 'assignment_pattern') {
      // Default parameter: x = defaultValue
      const leftNode = child.childForFieldName('left');
      if (leftNode && leftNode.type === 'identifier') {
        parameters.push({
          name: getNodeText(leftNode),
          type: null,
          annotations: [],
          line: child.startPosition.row + 1,
        });
      }
    } else if (child.type === 'rest_pattern' || child.type === 'rest_element') {
      // Rest parameter: ...args
      const nameNode = child.namedChildCount > 0 ? child.namedChild(0) : null;
      if (nameNode && nameNode.type === 'identifier') {
        parameters.push({
          name: '...' + getNodeText(nameNode),
          type: null,
          annotations: [],
          line: child.startPosition.row + 1,
        });
      }
    } else if (child.type === 'object_pattern' || child.type === 'array_pattern') {
      // Destructuring parameter
      parameters.push({
        name: getNodeText(child),
        type: null,
        annotations: [],
        line: child.startPosition.row + 1,
      });
    } else if (child.type === 'required_parameter' || child.type === 'optional_parameter') {
      // TypeScript-grammar parameter: pattern (identifier or destructuring) + optional type_annotation
      const patternNode = child.childForFieldName('pattern');
      if (!patternNode) continue;

      let paramName: string;
      if (patternNode.type === 'identifier') {
        paramName = getNodeText(patternNode);
      } else if (patternNode.type === 'rest_pattern' || patternNode.type === 'rest_element') {
        const inner = patternNode.namedChildCount > 0 ? patternNode.namedChild(0) : null;
        if (!inner) continue;
        paramName = '...' + getNodeText(inner);
      } else {
        // object_pattern, array_pattern, or assignment_pattern with default
        paramName = getNodeText(patternNode);
      }

      const typeNode = child.childForFieldName('type');
      let paramType: string | null = null;
      if (typeNode) {
        // type_annotation includes the leading ':'; strip it for storage parity with other languages
        paramType = getNodeText(typeNode).replace(/^:\s*/, '');
      }

      // Parameter decorators (NestJS @Query/@Param/@Body, Angular @Inject, etc.)
      // appear as `decorator` children of the required_parameter node itself.
      const decorators: string[] = [];
      for (let j = 0; j < child.childCount; j++) {
        const c = child.child(j);
        if (c && c.type === 'decorator') {
          const name = extractDecoratorName(c);
          if (name) decorators.push(name);
        }
      }

      parameters.push({
        name: paramName,
        type: paramType,
        annotations: decorators,
        line: child.startPosition.row + 1,
      });
    }
  }

  return parameters;
}

/**
 * Extract JavaScript class fields.
 */
function extractJSFields(body: Node): FieldInfo[] {
  const fields: FieldInfo[] = [];

  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    if (child.type === 'public_field_definition' || child.type === 'field_definition') {
      const nameNode = child.childForFieldName('name');
      const name = nameNode ? getNodeText(nameNode) : 'unknown';

      const modifiers: string[] = [];
      for (let j = 0; j < child.childCount; j++) {
        const modifier = child.child(j);
        if (modifier && modifier.type === 'static') {
          modifiers.push('static');
        }
      }

      fields.push({
        name,
        type: null,
        modifiers,
        annotations: [],
      });
    }
  }

  return fields;
}

/**
 * Extract class information.
 */
function extractClassInfo(node: Node): TypeInfo {
  const name = getIdentifier(node, 'name') ?? 'Unknown';
  const annotations = extractAnnotations(node);
  const modifiers = extractModifiers(node);

  // Extract superclass
  const superclass = node.childForFieldName('superclass');
  const extendsType = superclass ? extractTypeName(superclass) : null;

  // Extract interfaces - search for super_interfaces node
  const implementsList = extractImplementsList(node);

  // Extract body
  const body = node.childForFieldName('body');
  const methods = body ? extractMethods(body) : [];
  const fields = body ? extractFields(body) : [];

  // Get package from ancestors
  const pkg = extractPackageFromAncestors(node);

  return {
    name,
    kind: 'class',
    package: pkg,
    extends: extendsType,
    implements: implementsList,
    annotations,
    methods,
    fields,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract interface information.
 */
function extractInterfaceInfo(node: Node): TypeInfo {
  const name = getIdentifier(node, 'name') ?? 'Unknown';
  const annotations = extractAnnotations(node);

  // Extract extended interfaces
  const extendsClause = node.childForFieldName('extends');
  const extendsList = extendsClause ? extractTypeList(extendsClause) : [];

  // Extract body
  const body = node.childForFieldName('body');
  const methods = body ? extractMethods(body) : [];
  const fields = body ? extractFields(body) : [];

  const pkg = extractPackageFromAncestors(node);

  return {
    name,
    kind: 'interface',
    package: pkg,
    extends: extendsList.length > 0 ? extendsList[0] : null,
    implements: extendsList.slice(1),
    annotations,
    methods,
    fields,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract enum information.
 */
function extractEnumInfo(node: Node): TypeInfo {
  const name = getIdentifier(node, 'name') ?? 'Unknown';
  const annotations = extractAnnotations(node);

  // Extract interfaces
  const implementsList = extractImplementsList(node);

  // Extract body
  const body = node.childForFieldName('body');
  const methods = body ? extractMethods(body) : [];
  const fields = body ? extractFields(body) : [];

  const pkg = extractPackageFromAncestors(node);

  return {
    name,
    kind: 'enum',
    package: pkg,
    extends: null,
    implements: implementsList,
    annotations,
    methods,
    fields,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract methods from a class/interface body.
 */
function extractMethods(body: Node): MethodInfo[] {
  const methods: MethodInfo[] = [];
  let precedingComment: Node | null = null;

  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    // Track block comments (Javadoc)
    if (child.type === 'block_comment') {
      precedingComment = child;
      continue;
    }

    if (child.type === 'method_declaration' || child.type === 'constructor_declaration') {
      methods.push(extractMethodInfo(child, precedingComment));
      precedingComment = null; // Reset after using
    } else {
      // Non-method, non-comment node - reset preceding comment
      precedingComment = null;
    }
  }

  return methods;
}

/**
 * Extract method information.
 */
function extractMethodInfo(node: Node, precedingComment: Node | null = null): MethodInfo {
  const isConstructor = node.type === 'constructor_declaration';
  const name = getIdentifier(node, 'name') ?? (isConstructor ? '<init>' : 'unknown');

  // Extract return type
  const returnTypeNode = node.childForFieldName('type');
  const returnType = returnTypeNode ? getNodeText(returnTypeNode) : (isConstructor ? null : 'void');

  // Extract parameters
  const params = node.childForFieldName('parameters');
  const parameters = params ? extractParameters(params) : [];

  // Extract annotations and modifiers
  const annotations = extractAnnotations(node);
  const modifiers = extractModifiers(node);

  // Check for @sanitizer in Javadoc comment
  if (precedingComment) {
    const commentText = getNodeText(precedingComment);
    if (commentText.includes('@sanitizer')) {
      annotations.push('sanitizer');
    }
  }

  return {
    name,
    return_type: returnType,
    parameters,
    annotations,
    modifiers,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract parameters from a formal_parameters node.
 */
function extractParameters(params: Node): ParameterInfo[] {
  const parameters: ParameterInfo[] = [];

  for (let i = 0; i < params.childCount; i++) {
    const child = params.child(i);
    if (!child) continue;

    if (child.type === 'formal_parameter' || child.type === 'spread_parameter') {
      const name = getIdentifier(child, 'name') ?? `arg${i}`;
      const typeNode = child.childForFieldName('type');
      const type = typeNode ? getNodeText(typeNode) : null;
      const annotations = extractAnnotations(child);
      const line = child.startPosition.row + 1;

      parameters.push({ name, type, annotations, line });
    }
  }

  return parameters;
}

/**
 * Extract fields from a class body.
 */
function extractFields(body: Node): FieldInfo[] {
  const fields: FieldInfo[] = [];

  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    if (child.type === 'field_declaration') {
      const typeNode = child.childForFieldName('type');
      const type = typeNode ? getNodeText(typeNode) : null;
      const annotations = extractAnnotations(child);
      const modifiers = extractModifiers(child);

      // Extract declarators (there can be multiple: int a, b, c;)
      const declarators = findNodes(child, 'variable_declarator');
      for (const decl of declarators) {
        const name = getIdentifier(decl, 'name') ?? 'unknown';
        fields.push({ name, type, modifiers, annotations });
      }
    }
  }

  return fields;
}

/**
 * Extract annotations from a node.
 */
function extractAnnotations(node: Node): string[] {
  const annotations: string[] = [];

  // Look for modifiers node which contains annotations
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === 'modifiers') {
      for (let j = 0; j < child.childCount; j++) {
        const modifier = child.child(j);
        if (modifier?.type === 'marker_annotation' || modifier?.type === 'annotation') {
          // Get the full annotation text without the @ symbol
          let text = getNodeText(modifier);
          if (text.startsWith('@')) {
            text = text.substring(1);
          }
          annotations.push(text);
        }
      }
    }

    // Also check direct annotation children
    if (child.type === 'marker_annotation' || child.type === 'annotation') {
      let text = getNodeText(child);
      if (text.startsWith('@')) {
        text = text.substring(1);
      }
      annotations.push(text);
    }
  }

  return annotations;
}

/**
 * Extract modifiers (public, private, static, etc.) from a node.
 */
function extractModifiers(node: Node): string[] {
  const modifiers: string[] = [];
  const modifierKeywords = new Set([
    'public', 'private', 'protected', 'static', 'final',
    'abstract', 'synchronized', 'native', 'transient', 'volatile'
  ]);

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === 'modifiers') {
      for (let j = 0; j < child.childCount; j++) {
        const modifier = child.child(j);
        if (modifier && modifierKeywords.has(modifier.type)) {
          modifiers.push(modifier.type);
        }
      }
    }

    // Direct modifier children
    if (modifierKeywords.has(child.type)) {
      modifiers.push(child.type);
    }
  }

  return modifiers;
}

/**
 * Extract implements list from a class declaration.
 */
function extractImplementsList(node: Node): string[] {
  // Try field name first - this returns super_interfaces node
  let interfaces = node.childForFieldName('interfaces');

  // Also search for super_interfaces node directly
  if (!interfaces) {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type === 'super_interfaces') {
        interfaces = child;
        break;
      }
    }
  }

  if (!interfaces) {
    return [];
  }

  // super_interfaces contains a type_list - find it
  for (let i = 0; i < interfaces.childCount; i++) {
    const child = interfaces.child(i);
    if (child && child.type === 'type_list') {
      return extractTypeList(child);
    }
  }

  // Fallback to extracting directly from super_interfaces
  return extractTypeList(interfaces);
}

/**
 * Extract a list of types from a type_list or extends clause.
 */
function extractTypeList(node: Node): string[] {
  const types: string[] = [];

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    if (child.type === 'type_identifier' || child.type === 'generic_type' || child.type === 'scoped_type_identifier') {
      types.push(getNodeText(child));
    }
  }

  return types;
}

/**
 * Get identifier from a node by field name.
 */
function getIdentifier(node: Node, fieldName: string): string | null {
  const field = node.childForFieldName(fieldName);
  if (field) {
    return getNodeText(field);
  }
  return null;
}

/**
 * Extract type name from a type node, handling various type structures.
 */
function extractTypeName(node: Node): string {
  // For type_identifier, generic_type, scoped_type_identifier - use the text
  if (node.type === 'type_identifier' ||
      node.type === 'generic_type' ||
      node.type === 'scoped_type_identifier') {
    return getNodeText(node);
  }

  // For superclass node, find the actual type inside
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child && (child.type === 'type_identifier' ||
                  child.type === 'generic_type' ||
                  child.type === 'scoped_type_identifier')) {
      return getNodeText(child);
    }
  }

  // Fallback to the node text
  return getNodeText(node);
}

/**
 * Extract package from ancestor nodes.
 */
function extractPackageFromAncestors(node: Node): string | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'program') {
      const packageDecls = findNodes(current, 'package_declaration');
      if (packageDecls.length > 0) {
        const pkgDecl = packageDecls[0];
        // Try field name first
        const pkgNode = pkgDecl.childForFieldName('name');
        if (pkgNode) {
          return getNodeText(pkgNode);
        }
        // Fall back to finding scoped_identifier or identifier
        for (let i = 0; i < pkgDecl.childCount; i++) {
          const child = pkgDecl.child(i);
          if (child && (child.type === 'scoped_identifier' || child.type === 'identifier')) {
            return getNodeText(child);
          }
        }
      }
    }
    current = current.parent;
  }
  return null;
}

// =============================================================================
// Rust Type Extraction
// =============================================================================

/**
 * Extract Rust types (structs, enums, traits, impl blocks, functions).
 */
function extractRustTypes(tree: Tree, cache?: NodeCache): TypeInfo[] {
  const types: TypeInfo[] = [];
  const root = tree.rootNode;

  // Extract structs
  const structs = getNodesFromCache(root, 'struct_item', cache);
  for (const structNode of structs) {
    types.push(extractRustStructInfo(structNode));
  }

  // Extract enums
  const enums = getNodesFromCache(root, 'enum_item', cache);
  for (const enumNode of enums) {
    types.push(extractRustEnumInfo(enumNode));
  }

  // Extract traits (as interfaces)
  const traits = getNodesFromCache(root, 'trait_item', cache);
  for (const traitNode of traits) {
    types.push(extractRustTraitInfo(traitNode));
  }

  // Extract impl blocks and merge methods into their types
  const impls = getNodesFromCache(root, 'impl_item', cache);
  for (const implNode of impls) {
    const implInfo = extractRustImplInfo(implNode);
    // Find existing type and add methods
    const existingType = types.find(t => t.name === implInfo.typeName);
    if (existingType) {
      existingType.methods.push(...implInfo.methods);
      if (implInfo.traitName) {
        existingType.implements.push(implInfo.traitName);
      }
    } else {
      // Create synthetic type for impl without struct definition
      types.push({
        name: implInfo.typeName,
        kind: 'class',
        package: null,
        extends: null,
        implements: implInfo.traitName ? [implInfo.traitName] : [],
        annotations: [],
        methods: implInfo.methods,
        fields: [],
        start_line: implNode.startPosition.row + 1,
        end_line: implNode.endPosition.row + 1,
      });
    }
  }

  // Extract standalone functions as a module-like type
  const functions = getNodesFromCache(root, 'function_item', cache);
  const topLevelFunctions: MethodInfo[] = [];

  for (const func of functions) {
    // Only include top-level functions (not inside impl blocks)
    if (func.parent?.type === 'source_file') {
      topLevelFunctions.push(extractRustFunctionInfo(func));
    }
  }

  // Create a synthetic module type for standalone functions
  if (topLevelFunctions.length > 0) {
    types.push({
      name: '<module>',
      kind: 'class',
      package: null,
      extends: null,
      implements: [],
      annotations: [],
      methods: topLevelFunctions,
      fields: [],
      start_line: 1,
      end_line: root.endPosition.row + 1,
    });
  }

  return types;
}

/**
 * Extract Rust struct information.
 */
function extractRustStructInfo(node: Node): TypeInfo {
  const nameNode = node.childForFieldName('name');
  const name = nameNode ? getNodeText(nameNode) : 'Anonymous';

  // Extract fields from field_declaration_list
  const fields: FieldInfo[] = [];
  const fieldList = findChildByType(node, 'field_declaration_list');
  if (fieldList) {
    for (let i = 0; i < fieldList.childCount; i++) {
      const child = fieldList.child(i);
      if (child?.type === 'field_declaration') {
        const fieldNameNode = child.childForFieldName('name');
        const fieldTypeNode = child.childForFieldName('type');
        const visibility = extractRustVisibility(child);

        fields.push({
          name: fieldNameNode ? getNodeText(fieldNameNode) : 'unknown',
          type: fieldTypeNode ? getNodeText(fieldTypeNode) : null,
          modifiers: visibility ? [visibility] : [],
          annotations: [],
        });
      }
    }
  }

  // Extract visibility
  const visibility = extractRustVisibility(node);
  const annotations = visibility ? [visibility] : [];

  // Extract derive macros as annotations
  const derives = extractRustDerives(node);
  annotations.push(...derives);

  return {
    name,
    kind: 'class',
    package: null,
    extends: null,
    implements: [],
    annotations,
    methods: [], // Methods are added from impl blocks
    fields,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract Rust enum information.
 */
function extractRustEnumInfo(node: Node): TypeInfo {
  const nameNode = node.childForFieldName('name');
  const name = nameNode ? getNodeText(nameNode) : 'Anonymous';

  // Extract variants as fields
  const fields: FieldInfo[] = [];
  const body = node.childForFieldName('body');
  if (body) {
    for (let i = 0; i < body.childCount; i++) {
      const child = body.child(i);
      if (child?.type === 'enum_variant') {
        const variantName = child.childForFieldName('name');
        fields.push({
          name: variantName ? getNodeText(variantName) : 'unknown',
          type: null,
          modifiers: [],
          annotations: [],
        });
      }
    }
  }

  const visibility = extractRustVisibility(node);
  const annotations = visibility ? [visibility] : [];
  const derives = extractRustDerives(node);
  annotations.push(...derives);

  return {
    name,
    kind: 'enum',
    package: null,
    extends: null,
    implements: [],
    annotations,
    methods: [],
    fields,
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract Rust trait information.
 */
function extractRustTraitInfo(node: Node): TypeInfo {
  const nameNode = node.childForFieldName('name');
  const name = nameNode ? getNodeText(nameNode) : 'Anonymous';

  // Extract methods from trait body
  const methods: MethodInfo[] = [];
  const body = node.childForFieldName('body');
  if (body) {
    for (let i = 0; i < body.childCount; i++) {
      const child = body.child(i);
      if (child?.type === 'function_signature_item' || child?.type === 'function_item') {
        methods.push(extractRustFunctionInfo(child));
      }
    }
  }

  const visibility = extractRustVisibility(node);

  return {
    name,
    kind: 'interface',
    package: null,
    extends: null,
    implements: [],
    annotations: visibility ? [visibility] : [],
    methods,
    fields: [],
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract Rust impl block information.
 */
function extractRustImplInfo(node: Node): { typeName: string; traitName: string | null; methods: MethodInfo[] } {
  // impl Trait for Type or impl Type
  let typeName = 'Unknown';
  let traitName: string | null = null;

  const typeNode = node.childForFieldName('type');
  if (typeNode) {
    typeName = getNodeText(typeNode);
  }

  // Check for trait impl (impl Trait for Type)
  const traitNode = node.childForFieldName('trait');
  if (traitNode) {
    traitName = getNodeText(traitNode);
  }

  // Extract methods
  const methods: MethodInfo[] = [];
  const body = node.childForFieldName('body');
  if (body) {
    for (let i = 0; i < body.childCount; i++) {
      const child = body.child(i);
      if (child?.type === 'function_item') {
        methods.push(extractRustFunctionInfo(child));
      }
    }
  }

  return { typeName, traitName, methods };
}

/**
 * Extract Rust function/method information.
 */
function extractRustFunctionInfo(node: Node): MethodInfo {
  const nameNode = node.childForFieldName('name');
  const name = nameNode ? getNodeText(nameNode) : 'anonymous';

  // Extract parameters
  const paramsNode = node.childForFieldName('parameters');
  const parameters = paramsNode ? extractRustParameters(paramsNode) : [];

  // Extract return type
  const returnTypeNode = node.childForFieldName('return_type');
  const returnType = returnTypeNode ? getNodeText(returnTypeNode) : null;

  // Extract visibility and async modifier
  const modifiers: string[] = [];
  const visibility = extractRustVisibility(node);
  if (visibility) modifiers.push(visibility);

  // Check for async
  const functionModifiers = findChildByType(node, 'function_modifiers');
  if (functionModifiers) {
    for (let i = 0; i < functionModifiers.childCount; i++) {
      const child = functionModifiers.child(i);
      if (child?.type === 'async') {
        modifiers.push('async');
      }
    }
  }

  // Extract body for line count
  const body = node.childForFieldName('body');

  return {
    name,
    return_type: returnType,
    parameters,
    modifiers,
    annotations: [],
    start_line: node.startPosition.row + 1,
    end_line: node.endPosition.row + 1,
  };
}

/**
 * Extract Rust function parameters.
 */
function extractRustParameters(paramsNode: Node): ParameterInfo[] {
  const parameters: ParameterInfo[] = [];

  for (let i = 0; i < paramsNode.childCount; i++) {
    const child = paramsNode.child(i);
    if (!child) continue;

    if (child.type === 'parameter') {
      const pattern = child.childForFieldName('pattern');
      const typeNode = child.childForFieldName('type');
      parameters.push({
        name: pattern ? getNodeText(pattern) : 'arg',
        type: typeNode ? getNodeText(typeNode) : null,
        annotations: [],
        line: child.startPosition.row + 1,
      });
    } else if (child.type === 'self_parameter') {
      // &self, &mut self, self
      parameters.push({
        name: getNodeText(child),
        type: 'Self',
        annotations: [],
        line: child.startPosition.row + 1,
      });
    }
  }

  return parameters;
}

/**
 * Extract Rust visibility modifier (pub, pub(crate), etc.).
 */
function extractRustVisibility(node: Node): string | null {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === 'visibility_modifier') {
      return getNodeText(child);
    }
  }
  return null;
}

/**
 * Extract derive macros from Rust struct/enum.
 */
function extractRustDerives(node: Node): string[] {
  const derives: string[] = [];

  // Check for attribute items before the struct/enum
  let prev = node.previousSibling;
  while (prev) {
    if (prev.type === 'attribute_item') {
      const text = getNodeText(prev);
      // Parse #[derive(X, Y, Z)]
      const match = text.match(/#\[derive\(([^)]+)\)\]/);
      if (match) {
        const items = match[1].split(',').map(s => s.trim());
        derives.push(...items.map(d => `derive(${d})`));
      } else {
        // Other attributes like #[serde(rename_all = "camelCase")]
        derives.push(text.replace(/^#\[/, '').replace(/\]$/, ''));
      }
    } else {
      break;
    }
    prev = prev.previousSibling;
  }

  return derives;
}

// =============================================================================
// Go Type Extraction
// =============================================================================

/**
 * Extract Go types (structs, interfaces, and functions).
 */
function extractGoTypes(tree: Tree, cache?: NodeCache): TypeInfo[] {
  const types: TypeInfo[] = [];
  const root = tree.rootNode;

  // Extract type declarations (struct and interface)
  const typeDecls = getNodesFromCache(root, 'type_declaration', cache);
  for (const decl of typeDecls) {
    for (let i = 0; i < decl.childCount; i++) {
      const spec = decl.child(i);
      if (!spec || spec.type !== 'type_spec') continue;

      const nameNode = spec.childForFieldName('name');
      const typeNode = spec.childForFieldName('type');
      if (!nameNode || !typeNode) continue;

      const name = getNodeText(nameNode);
      const isInterface = typeNode.type === 'interface_type';
      const isStruct = typeNode.type === 'struct_type';

      if (!isStruct && !isInterface) continue;

      const fields: FieldInfo[] = [];
      const methods: MethodInfo[] = [];

      if (isStruct) {
        // Extract struct fields from field_declaration_list
        const fieldList = findChildByType(typeNode, 'field_declaration_list');
        if (fieldList) {
          for (let j = 0; j < fieldList.childCount; j++) {
            const field = fieldList.child(j);
            if (!field || field.type !== 'field_declaration') continue;
            const fieldName = field.childForFieldName('name');
            const fieldType = field.childForFieldName('type');
            if (fieldName) {
              fields.push({
                name: getNodeText(fieldName),
                type: fieldType ? getNodeText(fieldType) : null,
                modifiers: [],
                annotations: [],
              });
            }
          }
        }
      }

      // Find methods declared for this type (method_declaration with matching receiver)
      const methodDecls = getNodesFromCache(root, 'method_declaration', cache);
      for (const md of methodDecls) {
        const receiver = md.childForFieldName('receiver');
        if (!receiver) continue;
        const receiverText = getNodeText(receiver);
        if (receiverText.includes(name)) {
          const methodNameNode = md.childForFieldName('name');
          const params = md.childForFieldName('parameters');
          const result = md.childForFieldName('result');
          if (methodNameNode) {
            methods.push({
              name: getNodeText(methodNameNode),
              return_type: result ? getNodeText(result) : null,
              parameters: params ? extractGoParameters(params) : [],
              annotations: [],
              modifiers: [],
              start_line: md.startPosition.row + 1,
              end_line: md.endPosition.row + 1,
            });
          }
        }
      }

      // Extract package from package_clause
      let pkg: string | null = null;
      const pkgClause = findChildByType(root, 'package_clause');
      if (pkgClause) {
        for (let j = 0; j < pkgClause.childCount; j++) {
          const child = pkgClause.child(j);
          if (child && child.type === 'package_identifier') {
            pkg = getNodeText(child);
            break;
          }
        }
      }

      types.push({
        name,
        kind: isInterface ? 'interface' : 'class',
        package: pkg,
        extends: null,
        implements: [],
        annotations: [],
        methods,
        fields,
        start_line: decl.startPosition.row + 1,
        end_line: decl.endPosition.row + 1,
      });
    }
  }

  // Extract standalone functions as a module-like type
  const functions = getNodesFromCache(root, 'function_declaration', cache);
  if (functions.length > 0) {
    const moduleFunctions: MethodInfo[] = [];
    for (const func of functions) {
      const nameNode = func.childForFieldName('name');
      const params = func.childForFieldName('parameters');
      const result = func.childForFieldName('result');
      if (nameNode) {
        moduleFunctions.push({
          name: getNodeText(nameNode),
          return_type: result ? getNodeText(result) : null,
          parameters: params ? extractGoParameters(params) : [],
          annotations: [],
          modifiers: [],
          start_line: func.startPosition.row + 1,
          end_line: func.endPosition.row + 1,
        });
      }
    }

    if (moduleFunctions.length > 0) {
      types.push({
        name: '<module>',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: moduleFunctions,
        fields: [],
        start_line: 1,
        end_line: root.endPosition.row + 1,
      });
    }
  }

  return types;
}

/**
 * Extract parameters from a Go parameter_list node.
 */
function extractGoParameters(params: Node): ParameterInfo[] {
  const parameters: ParameterInfo[] = [];

  for (let i = 0; i < params.childCount; i++) {
    const child = params.child(i);
    if (!child || child.type !== 'parameter_declaration') continue;

    const nameNode = child.childForFieldName('name');
    const typeNode = child.childForFieldName('type');

    if (nameNode) {
      parameters.push({
        name: getNodeText(nameNode),
        type: typeNode ? getNodeText(typeNode) : null,
        annotations: [],
        line: child.startPosition.row + 1,
      });
    }
  }

  return parameters;
}

/**
 * Find child node by type.
 */
function findChildByType(node: Node, type: string): Node | null {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === type) {
      return child;
    }
  }
  return null;
}
