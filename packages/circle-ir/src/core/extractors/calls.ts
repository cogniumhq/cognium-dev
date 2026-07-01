/**
 * Call extractor - extracts method invocations
 */

import type { Node, Tree } from 'web-tree-sitter';
import type { CallInfo, ArgumentInfo, CallResolution } from '../../types/index.js';
import { findNodes, findAncestor, getNodeText, getNodesFromCache, type NodeCache } from '../parser.js';

// Context for tracking types in the current file
interface ResolutionContext {
  className: string | null;
  /** Package declared by the current file (`null` if default package). */
  packageName: string | null;
  methodNames: Set<string>;
  fieldTypes: Map<string, string>;
  localVarTypes: Map<string, string>;
  /**
   * All method-parameter types in the file, flattened across methods.
   * Last-write-wins on name collisions; acceptable for v1 because Java
   * parameter names rarely collide across methods in real code, and the
   * miss falls back to the conservative `null` receiver_type.
   */
  paramTypes: Map<string, string>;
  /** Map from simple class name to fully-qualified name (from `import ...`). */
  imports: Map<string, string>;
  /** Wildcard imports like `import java.util.*;` — package prefixes only. */
  wildcardImports: string[];
}

/**
 * Detect if the tree is JavaScript/TypeScript based on specific node patterns.
 * We check for the presence of call_expression nodes (JS) vs method_invocation (Java).
 */
function detectLanguageFromTree(tree: Tree, cache?: NodeCache): 'javascript' | 'java' | 'python' | 'rust' {
  // Check for Rust-specific nodes
  const rustStructs = getNodesFromCache(tree.rootNode, 'struct_item', cache);
  const rustImpls = getNodesFromCache(tree.rootNode, 'impl_item', cache);
  const rustFunctions = getNodesFromCache(tree.rootNode, 'function_item', cache);
  const rustUseDecls = getNodesFromCache(tree.rootNode, 'use_declaration', cache);

  // Check for Python-specific nodes
  const pythonCalls = getNodesFromCache(tree.rootNode, 'call', cache);
  const pythonClasses = getNodesFromCache(tree.rootNode, 'class_definition', cache);
  const pythonFunctions = getNodesFromCache(tree.rootNode, 'function_definition', cache);

  // Check for JavaScript-specific nodes
  const callExpressions = getNodesFromCache(tree.rootNode, 'call_expression', cache);
  const arrowFunctions = getNodesFromCache(tree.rootNode, 'arrow_function', cache);

  // Check for Java-specific nodes
  const methodInvocations = getNodesFromCache(tree.rootNode, 'method_invocation', cache);
  const classDeclarations = getNodesFromCache(tree.rootNode, 'class_declaration', cache);

  // Count indicators for each language
  const rustIndicators = rustStructs.length + rustImpls.length + rustFunctions.length + rustUseDecls.length;
  const pythonIndicators = pythonCalls.length + pythonClasses.length + pythonFunctions.length;
  const jsIndicators = callExpressions.length + arrowFunctions.length;
  const javaIndicators = methodInvocations.length + classDeclarations.length;

  // Rust detection: has Rust-specific nodes
  if (rustIndicators > 0 && (rustStructs.length > 0 || rustImpls.length > 0 || rustFunctions.length > 0)) {
    return 'rust';
  }

  // Python detection: has 'call' nodes (not 'call_expression') and python class/function defs
  if (pythonCalls.length > 0 && (pythonClasses.length > 0 || pythonFunctions.length > 0) && methodInvocations.length === 0 && callExpressions.length === 0) {
    return 'python';
  }

  // If we have Java indicators and no/fewer JS indicators, it's Java
  // Java class declarations are a strong indicator
  if (classDeclarations.length > 0 && methodInvocations.length > 0) {
    return 'java';
  }

  // If we have call_expression but no method_invocation, it's JavaScript
  if (callExpressions.length > 0 && methodInvocations.length === 0) {
    return 'javascript';
  }

  // Default to Java for backwards compatibility
  return javaIndicators >= jsIndicators ? 'java' : 'javascript';
}

/**
 * Extract all method calls from the tree.
 * @param tree The parsed AST tree
 * @param cache Optional node cache for performance
 * @param language Optional language hint ('java' | 'javascript' | 'typescript' | 'python' | 'rust')
 */
export function extractCalls(tree: Tree, cache?: NodeCache, language?: string): CallInfo[] {
  const calls: CallInfo[] = [];

  // Use language hint if provided, otherwise detect from tree
  const detectedLanguage = language ?? detectLanguageFromTree(tree, cache);
  const isJavaScript = detectedLanguage === 'javascript' || detectedLanguage === 'typescript' || detectedLanguage === 'tsx';
  const isPython = detectedLanguage === 'python';
  const isRust = detectedLanguage === 'rust';

  if (detectedLanguage === 'go') {
    return extractGoCalls(tree, cache);
  }

  if (detectedLanguage === 'bash') {
    return extractBashCalls(tree, cache);
  }

  if (isRust) {
    return extractRustCalls(tree, cache);
  }

  if (isPython) {
    return extractPythonCalls(tree, cache);
  }

  if (isJavaScript) {
    return extractJavaScriptCalls(tree, cache);
  }

  // Build resolution context for Java
  const context = buildResolutionContext(tree, cache);

  // Find all method invocations
  const invocations = getNodesFromCache(tree.rootNode, 'method_invocation', cache);
  for (const inv of invocations) {
    calls.push(extractCallInfo(inv, context));
  }

  // Find object creation expressions (constructor calls)
  const objectCreations = getNodesFromCache(tree.rootNode, 'object_creation_expression', cache);
  for (const creation of objectCreations) {
    const callInfo = extractObjectCreation(creation, context);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  return calls;
}

/**
 * Extract all function/method calls from a JavaScript/TypeScript tree.
 */
function extractJavaScriptCalls(tree: Tree, cache?: NodeCache): CallInfo[] {
  const calls: CallInfo[] = [];

  // Build JS resolution context
  const context = buildJSResolutionContext(tree, cache);

  // Find all call expressions (function/method calls)
  const callExpressions = getNodesFromCache(tree.rootNode, 'call_expression', cache);
  for (const call of callExpressions) {
    const callInfo = extractJSCallInfo(call, context);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  // Find new expressions (constructor calls)
  const newExpressions = getNodesFromCache(tree.rootNode, 'new_expression', cache);
  for (const newExpr of newExpressions) {
    const callInfo = extractJSNewExpression(newExpr, context);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  // Find JSX attributes that act as XSS sinks (e.g. dangerouslySetInnerHTML).
  // The TSX/JSX grammar represents these as `jsx_attribute` nodes, not
  // `call_expression`. To let the taint matcher reuse the standard method-
  // call sink path, we emit a synthetic CallInfo per matching attribute.
  // (cognium-dev #68 — Phase D.1)
  const jsxAttributes = getNodesFromCache(tree.rootNode, 'jsx_attribute', cache);
  for (const attr of jsxAttributes) {
    const callInfo = extractJSXAttributeSink(attr);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  // Find DOM property assignments that act as XSS sinks
  // (e.g. `el.innerHTML = userInput`). Same rationale as JSX attributes:
  // emit a synthetic CallInfo so the standard taint matcher path picks them
  // up via property-named sink entries. (cognium-dev #68 — Phase D.3)
  const assignments = getNodesFromCache(tree.rootNode, 'assignment_expression', cache);
  for (const assign of assignments) {
    const callInfo = extractDomPropertyAssignmentSink(assign);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  return calls;
}

/**
 * DOM properties whose assignment is an XSS sink. Keeping this list small
 * and explicit so we don't over-flag (the YAML config in
 * `configs/sinks/javascript_dom_xss.yaml` lists more, but most of those are
 * element-conditional and would need DOM-type tracking to flag without FPs).
 */
const DOM_XSS_ASSIGNMENT_PROPERTIES = new Set([
  'innerHTML',
  'outerHTML',
]);

/**
 * Emit a synthetic CallInfo for DOM property assignments that are XSS sinks.
 *
 * Matches `<obj>.<prop> = <expr>` where `<prop>` is in
 * `DOM_XSS_ASSIGNMENT_PROPERTIES`. The synthetic call has method=`<prop>`,
 * receiver=`<obj>` text, single argument=`<expr>`.
 */
function extractDomPropertyAssignmentSink(node: Node): CallInfo | null {
  const leftNode = node.childForFieldName('left');
  const rightNode = node.childForFieldName('right');
  if (!leftNode || !rightNode) return null;
  if (leftNode.type !== 'member_expression') return null;

  const propertyNode = leftNode.childForFieldName('property');
  const objectNode = leftNode.childForFieldName('object');
  if (!propertyNode) return null;

  const propertyName = getNodeText(propertyNode);
  if (!DOM_XSS_ASSIGNMENT_PROPERTIES.has(propertyName)) return null;

  const receiver = objectNode ? getNodeText(objectNode) : null;
  const expression = getNodeText(rightNode);
  const { variable, literal } = analyzeJSArgument(rightNode);
  const enclosingFunc = findJSEnclosingFunction(node);

  return {
    method_name: propertyName,
    receiver,
    arguments: [
      {
        position: 0,
        expression,
        variable,
        literal,
      },
    ],
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    in_method: enclosingFunc,
    resolved: true,
    resolution: {
      status: 'resolved',
      target: `DOM.${propertyName}`,
    },
  };
}

/**
 * Emit a synthetic CallInfo for JSX attributes that are known XSS sinks.
 *
 * Currently handles `dangerouslySetInnerHTML={{ __html: expr }}` on any JSX
 * element. The synthetic call has method `dangerouslySetInnerHTML`, no
 * receiver, and a single argument carrying the `__html` value expression.
 * The taint matcher then catches the call via the standard
 * `dangerouslySetInnerHTML` sink entry in `configs/sinks/nodejs.json`.
 */
function extractJSXAttributeSink(attr: Node): CallInfo | null {
  // `jsx_attribute` has children: property_identifier '=' jsx_expression
  // Get the attribute name (first property_identifier child).
  let nameNode: Node | null = null;
  for (let i = 0; i < attr.childCount; i++) {
    const child = attr.child(i);
    if (child && child.type === 'property_identifier') {
      nameNode = child;
      break;
    }
  }
  if (!nameNode) return null;

  const attrName = getNodeText(nameNode);
  if (attrName !== 'dangerouslySetInnerHTML') return null;

  // Find the `jsx_expression` value child (the `{{__html: x}}` part).
  let valueExpr: Node | null = null;
  for (let i = 0; i < attr.childCount; i++) {
    const child = attr.child(i);
    if (child && child.type === 'jsx_expression') {
      valueExpr = child;
      break;
    }
  }
  if (!valueExpr) return null;

  // Inside the jsx_expression, find the inner `object` literal, then the
  // `pair` whose key is `__html`, then that pair's `value`.
  let htmlValue: Node | null = null;
  for (let i = 0; i < valueExpr.childCount; i++) {
    const inner = valueExpr.child(i);
    if (!inner || inner.type !== 'object') continue;
    for (let j = 0; j < inner.childCount; j++) {
      const pair = inner.child(j);
      if (!pair || pair.type !== 'pair') continue;
      const keyNode = pair.childForFieldName('key');
      if (!keyNode) continue;
      const keyText = getNodeText(keyNode).replace(/^["']|["']$/g, '');
      if (keyText === '__html') {
        htmlValue = pair.childForFieldName('value');
        break;
      }
    }
    if (htmlValue) break;
  }

  // If the `__html` field wasn't found (or the prop was passed a spread/var
  // like `{...props}`), fall back to using the entire jsx_expression body
  // so the matcher still sees the data dependency.
  if (!htmlValue) {
    for (let i = 0; i < valueExpr.childCount; i++) {
      const inner = valueExpr.child(i);
      if (inner && inner.type !== '{' && inner.type !== '}') {
        htmlValue = inner;
        break;
      }
    }
  }
  if (!htmlValue) return null;

  const expression = getNodeText(htmlValue);
  const { variable, literal } = analyzeJSArgument(htmlValue);

  const enclosingFunc = findJSEnclosingFunction(attr);

  return {
    method_name: 'dangerouslySetInnerHTML',
    receiver: null,
    arguments: [
      {
        position: 0,
        expression,
        variable,
        literal,
      },
    ],
    location: {
      line: attr.startPosition.row + 1,
      column: attr.startPosition.column,
    },
    in_method: enclosingFunc,
    resolved: true,
    resolution: {
      status: 'resolved',
      target: 'react.dangerouslySetInnerHTML',
    },
  };
}

/**
 * Build context for JS method resolution.
 */
interface JSResolutionContext {
  functionNames: Set<string>;
  variableTypes: Map<string, string>;
  imports: Map<string, string>; // variable name -> module
}

function buildJSResolutionContext(tree: Tree, cache?: NodeCache): JSResolutionContext {
  const context: JSResolutionContext = {
    functionNames: new Set(),
    variableTypes: new Map(),
    imports: new Map(),
  };

  // Collect function names
  const functions = getNodesFromCache(tree.rootNode, 'function_declaration', cache);
  for (const func of functions) {
    const nameNode = func.childForFieldName('name');
    if (nameNode) {
      context.functionNames.add(getNodeText(nameNode));
    }
  }

  // Collect arrow functions assigned to variables
  const varDecls = getNodesFromCache(tree.rootNode, 'variable_declaration', cache);
  const lexDecls = getNodesFromCache(tree.rootNode, 'lexical_declaration', cache);
  for (const decl of [...varDecls, ...lexDecls]) {
    const declarators = findNodes(decl, 'variable_declarator');
    for (const declarator of declarators) {
      const nameNode = declarator.childForFieldName('name');
      const valueNode = declarator.childForFieldName('value');
      if (nameNode && valueNode) {
        const name = getNodeText(nameNode);
        if (valueNode.type === 'arrow_function' || valueNode.type === 'function_expression') {
          context.functionNames.add(name);
        }
      }
    }
  }

  // Collect imports
  const imports = getNodesFromCache(tree.rootNode, 'import_statement', cache);
  for (const imp of imports) {
    const text = getNodeText(imp);
    // Simple pattern matching for common import formats
    // import x from 'module' or const x = require('module')
    const fromMatch = text.match(/import\s+(\w+)\s+from\s+['"]([^'"]+)['"]/);
    if (fromMatch) {
      context.imports.set(fromMatch[1], fromMatch[2]);
    }
    const destructMatch = text.match(/import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/);
    if (destructMatch) {
      const names = destructMatch[1].split(',').map(n => n.trim().split(/\s+as\s+/).pop()!.trim());
      for (const name of names) {
        context.imports.set(name, destructMatch[2]);
      }
    }
  }

  return context;
}

/**
 * Extract call information from a JS call_expression node.
 */
function extractJSCallInfo(node: Node, context: JSResolutionContext): CallInfo | null {
  const functionNode = node.childForFieldName('function');
  if (!functionNode) return null;

  let methodName: string;
  let receiver: string | null = null;

  if (functionNode.type === 'member_expression') {
    // Method call: obj.method() or obj.prop.method()
    const objectNode = functionNode.childForFieldName('object');
    const propertyNode = functionNode.childForFieldName('property');

    if (!propertyNode) return null;

    methodName = getNodeText(propertyNode);
    receiver = objectNode ? getNodeText(objectNode) : null;
  } else if (functionNode.type === 'identifier') {
    // Direct function call: func()
    methodName = getNodeText(functionNode);
  } else {
    // Complex expression like (getFunc())()
    methodName = getNodeText(functionNode);
  }

  // Get arguments
  const argsNode = node.childForFieldName('arguments');
  const args = argsNode ? extractJSArguments(argsNode) : [];

  // Find enclosing function
  const enclosingFunc = findJSEnclosingFunction(node);

  // Resolve the call
  const { resolved, resolution } = resolveJSCall(methodName, receiver, context);

  return {
    method_name: methodName,
    receiver,
    arguments: args,
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    in_method: enclosingFunc,
    resolved,
    resolution,
  };
}

/**
 * Extract call information from a JS new_expression (constructor call).
 */
function extractJSNewExpression(node: Node, context: JSResolutionContext): CallInfo | null {
  const constructorNode = node.childForFieldName('constructor');
  if (!constructorNode) return null;

  const typeName = getNodeText(constructorNode);

  // Get arguments
  const argsNode = node.childForFieldName('arguments');
  const args = argsNode ? extractJSArguments(argsNode) : [];

  // Find enclosing function
  const enclosingFunc = findJSEnclosingFunction(node);

  return {
    method_name: typeName,
    receiver: null,
    arguments: args,
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    in_method: enclosingFunc,
    resolved: true,
    resolution: {
      status: 'resolved',
      target: `${typeName}.<init>`,
    },
  };
}

/**
 * Extract arguments from a JS arguments node.
 */
function extractJSArguments(argsNode: Node): ArgumentInfo[] {
  const args: ArgumentInfo[] = [];
  let position = 0;

  for (let i = 0; i < argsNode.childCount; i++) {
    const child = argsNode.child(i);
    if (!child) continue;

    // Skip parentheses and commas
    if (child.type === '(' || child.type === ')' || child.type === ',') {
      continue;
    }

    const expression = getNodeText(child);
    const { variable, literal } = analyzeJSArgument(child);

    args.push({
      position,
      expression,
      variable,
      literal,
    });

    position++;
  }

  return args;
}

/**
 * Analyze a JS argument to extract variable name or literal value.
 */
function analyzeJSArgument(node: Node): { variable: string | null; literal: string | null } {
  // Check if it's a simple identifier (variable reference)
  if (node.type === 'identifier') {
    return { variable: getNodeText(node), literal: null };
  }

  // Check if it's a member expression (e.g., req.params.id)
  if (node.type === 'member_expression') {
    return { variable: getNodeText(node), literal: null };
  }

  // Check if it's a template string with interpolations (e.g., `hello ${name}`)
  // These are NOT safe literals — the interpolated expression may carry tainted data.
  if (node.type === 'template_string') {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type === 'template_substitution') {
        // Find the primary variable in the interpolation
        const identifier = findPrimaryIdentifier(child);
        if (identifier) {
          return { variable: identifier, literal: null };
        }
        return { variable: null, literal: null };
      }
    }
    // Plain template string with no interpolations — treat as literal
    return { variable: null, literal: extractJSLiteralValue(node) };
  }

  // Check if it's a literal
  if (isJSLiteral(node)) {
    return { variable: null, literal: extractJSLiteralValue(node) };
  }

  // For complex expressions, try to find the primary variable
  const identifier = findPrimaryIdentifier(node);
  if (identifier) {
    return { variable: identifier, literal: null };
  }

  return { variable: null, literal: null };
}

/**
 * Check if a node represents a JS literal value.
 */
function isJSLiteral(node: Node): boolean {
  const literalTypes = new Set([
    'string',
    'template_string',
    'number',
    'true',
    'false',
    'null',
    'undefined',
  ]);

  return literalTypes.has(node.type);
}

/**
 * Extract the value from a JS literal node.
 */
function extractJSLiteralValue(node: Node): string {
  const text = getNodeText(node);

  // Remove quotes from string literals
  if (node.type === 'string') {
    return text.slice(1, -1);
  }

  return text;
}

/**
 * Find the name of the enclosing function in JS.
 */
function findJSEnclosingFunction(node: Node): string | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'function_declaration') {
      const nameNode = current.childForFieldName('name');
      if (nameNode) {
        return getNodeText(nameNode);
      }
    }
    if (current.type === 'method_definition') {
      const nameNode = current.childForFieldName('name');
      if (nameNode) {
        return getNodeText(nameNode);
      }
    }
    if (current.type === 'variable_declarator') {
      // Arrow function assigned to variable
      const valueNode = current.childForFieldName('value');
      if (valueNode && (valueNode.type === 'arrow_function' || valueNode.type === 'function_expression')) {
        const nameNode = current.childForFieldName('name');
        if (nameNode) {
          return getNodeText(nameNode);
        }
      }
    }
    // Express route handler pattern: app.get('/path', (req, res) => { ... })
    if (current.type === 'arrow_function' || current.type === 'function_expression') {
      const parent = current.parent;
      if (parent?.type === 'arguments') {
        const callExpr = parent.parent;
        if (callExpr?.type === 'call_expression') {
          const funcNode = callExpr.childForFieldName('function');
          if (funcNode?.type === 'member_expression') {
            const propNode = funcNode.childForFieldName('property');
            if (propNode) {
              // Return route handler name like "get" or "post"
              return getNodeText(propNode) + '_handler';
            }
          }
        }
      }
    }
    current = current.parent;
  }
  return null;
}

/**
 * Resolve a JS function/method call to determine its target.
 */
function resolveJSCall(
  methodName: string,
  receiver: string | null,
  context: JSResolutionContext
): { resolved: boolean; resolution: CallResolution } {
  // No receiver - might be a local function or global
  if (!receiver) {
    if (context.functionNames.has(methodName)) {
      return {
        resolved: true,
        resolution: {
          status: 'resolved',
          target: methodName,
        },
      };
    }

    // Built-in globals
    const builtins = new Set(['eval', 'setTimeout', 'setInterval', 'fetch', 'require']);
    if (builtins.has(methodName)) {
      return {
        resolved: true,
        resolution: {
          status: 'resolved',
          target: methodName,
        },
      };
    }

    return {
      resolved: false,
      resolution: {
        status: 'external_method',
      },
    };
  }

  // Check common JS/Node.js patterns
  const jsTypeMappings = inferJSTypeFromReceiver(receiver);
  if (jsTypeMappings) {
    return {
      resolved: true,
      resolution: {
        status: 'resolved',
        target: `${jsTypeMappings}.${methodName}`,
      },
    };
  }

  // Check if receiver is an imported module
  const baseReceiver = receiver.split('.')[0];
  const moduleName = context.imports.get(baseReceiver);
  if (moduleName) {
    return {
      resolved: true,
      resolution: {
        status: 'resolved',
        target: `${moduleName}.${methodName}`,
      },
    };
  }

  return {
    resolved: false,
    resolution: {
      status: 'external_method',
    },
  };
}

/**
 * Infer type from JS receiver name patterns.
 */
function inferJSTypeFromReceiver(receiver: string): string | null {
  const patterns: Record<string, string> = {
    // Express
    req: 'Request',
    request: 'Request',
    res: 'Response',
    response: 'Response',
    app: 'Express',
    router: 'Router',

    // Node.js built-ins
    fs: 'fs',
    path: 'path',
    http: 'http',
    https: 'https',
    child_process: 'child_process',
    crypto: 'crypto',
    os: 'os',

    // Database
    db: 'Connection',
    connection: 'Connection',
    pool: 'Pool',
    client: 'Client',

    // Common patterns
    console: 'console',
    process: 'process',
    Buffer: 'Buffer',
    JSON: 'JSON',
    Math: 'Math',
    Object: 'Object',
    Array: 'Array',
    String: 'String',
    Promise: 'Promise',
  };

  // Check exact match first
  if (patterns[receiver]) {
    return patterns[receiver];
  }

  // Check base of member expression (e.g., req.params -> req)
  const base = receiver.split('.')[0];
  if (patterns[base]) {
    return patterns[base];
  }

  return null;
}

/**
 * Build context for method resolution.
 */
function buildResolutionContext(tree: Tree, cache?: NodeCache): ResolutionContext {
  const context: ResolutionContext = {
    className: null,
    packageName: null,
    methodNames: new Set(),
    fieldTypes: new Map(),
    localVarTypes: new Map(),
    paramTypes: new Map(),
    imports: new Map(),
    wildcardImports: [],
  };

  // Find package declaration (java grammar: `package_declaration`)
  const packages = getNodesFromCache(tree.rootNode, 'package_declaration', cache);
  if (packages.length > 0) {
    const text = getNodeText(packages[0]);
    const match = text.match(/package\s+([a-zA-Z0-9_.]+)/);
    if (match) {
      context.packageName = match[1];
    }
  }

  // Find class name
  const classes = getNodesFromCache(tree.rootNode, 'class_declaration', cache);
  if (classes.length > 0) {
    const nameNode = classes[0].childForFieldName('name');
    if (nameNode) {
      context.className = getNodeText(nameNode);
    }
  }

  // Collect method names + parameter types from the class
  const methods = getNodesFromCache(tree.rootNode, 'method_declaration', cache);
  for (const method of methods) {
    const nameNode = method.childForFieldName('name');
    if (nameNode) {
      context.methodNames.add(getNodeText(nameNode));
    }
    const paramsNode = method.childForFieldName('parameters');
    if (paramsNode) {
      collectParameterTypes(paramsNode, context.paramTypes);
    }
  }

  // Also collect parameters from constructors
  const constructors = getNodesFromCache(tree.rootNode, 'constructor_declaration', cache);
  for (const ctor of constructors) {
    const paramsNode = ctor.childForFieldName('parameters');
    if (paramsNode) {
      collectParameterTypes(paramsNode, context.paramTypes);
    }
  }

  // Collect field types
  const fields = getNodesFromCache(tree.rootNode, 'field_declaration', cache);
  for (const field of fields) {
    const typeNode = field.childForFieldName('type');
    const declarators = findNodes(field, 'variable_declarator');
    if (typeNode) {
      const typeName = getNodeText(typeNode);
      for (const decl of declarators) {
        const nameNode = decl.childForFieldName('name');
        if (nameNode) {
          context.fieldTypes.set(getNodeText(nameNode), typeName);
        }
      }
    }
  }

  // Collect local variable types from all method bodies
  const localVarDecls = getNodesFromCache(tree.rootNode, 'local_variable_declaration', cache);
  for (const decl of localVarDecls) {
    const typeNode = decl.childForFieldName('type');
    const declarators = findNodes(decl, 'variable_declarator');
    if (typeNode) {
      const typeName = getNodeText(typeNode);
      for (const declarator of declarators) {
        const nameNode = declarator.childForFieldName('name');
        if (nameNode) {
          context.localVarTypes.set(getNodeText(nameNode), typeName);
        }
      }
    }
  }

  // Collect imports — map simple class name to FQN
  const imports = getNodesFromCache(tree.rootNode, 'import_declaration', cache);
  for (const imp of imports) {
    const text = getNodeText(imp);
    // Match `import [static] some.qualified.Name;` (with optional trailing `.*`)
    const match = text.match(/import\s+(?:static\s+)?([a-zA-Z0-9_.]+)(\.\*)?/);
    if (!match) continue;
    const fqn = match[1];
    const isWildcard = match[2] === '.*';
    if (isWildcard) {
      context.wildcardImports.push(fqn);
    } else {
      const parts = fqn.split('.');
      const simple = parts[parts.length - 1];
      context.imports.set(simple, fqn);
    }
  }

  return context;
}

/**
 * Collect `paramName → typeName` from a `formal_parameters` node.
 * Handles formal_parameter and spread_parameter; receiver_parameter (Java
 * inner-class `this` reference) is skipped because it has no `name`.
 */
function collectParameterTypes(paramsNode: Node, out: Map<string, string>): void {
  for (let i = 0; i < paramsNode.childCount; i++) {
    const child = paramsNode.child(i);
    if (!child) continue;
    if (child.type !== 'formal_parameter' && child.type !== 'spread_parameter') {
      continue;
    }
    const typeNode = child.childForFieldName('type');
    const nameNode = child.childForFieldName('name');
    if (typeNode && nameNode) {
      out.set(getNodeText(nameNode), getNodeText(typeNode));
    }
  }
}

/**
 * Strip generic parameters from a Java type expression.
 * `List<String>` → `List`, `Map<String, User>` → `Map`, `User` → `User`.
 */
function stripGenerics(type: string): string {
  const ltIdx = type.indexOf('<');
  return ltIdx === -1 ? type : type.substring(0, ltIdx);
}

/**
 * Resolve the receiver expression to its declared simple type and (if
 * available) fully-qualified name. Returns `{ simpleName: null, fqn: null }`
 * for receivers that cannot be statically resolved — dynamic dispatch,
 * complex chained expressions, and missing declarations all fall back to
 * the conservative null result so downstream consumers can choose their
 * own heuristic (substring matching, hierarchy walk, etc.).
 */
function resolveReceiverType(
  receiver: string | null,
  context: ResolutionContext,
): { simpleName: string | null; fqn: string | null } {
  if (!receiver) return { simpleName: null, fqn: null };

  // `this` and `this.field` — current class methods/fields
  if (receiver === 'this') {
    return resolveFqn(context.className, context);
  }
  if (receiver.startsWith('this.')) {
    const fieldName = receiver.substring('this.'.length);
    const fieldType = context.fieldTypes.get(fieldName);
    if (fieldType) return resolveFqn(stripGenerics(fieldType), context);
    return { simpleName: null, fqn: null };
  }

  // `super` — defer; cannot determine parent class without hierarchy
  if (receiver === 'super') return { simpleName: null, fqn: null };

  // Local variable, parameter, or field declared in this file
  const declaredType =
    context.localVarTypes.get(receiver) ??
    context.paramTypes.get(receiver) ??
    context.fieldTypes.get(receiver);
  if (declaredType) {
    return resolveFqn(stripGenerics(declaredType), context);
  }

  // Receiver starts with uppercase letter — likely a static class reference.
  // Strip dotted prefix (`com.example.Foo` → `Foo`) and look up imports.
  if (/^[A-Z]/.test(receiver)) {
    const simple = receiver.includes('.')
      ? receiver.substring(receiver.lastIndexOf('.') + 1)
      : receiver;
    if (/^[A-Z][A-Za-z0-9_]*$/.test(simple)) {
      return resolveFqn(simple, context);
    }
  }

  // Chained receiver: `<var>.<method>(...)` — resolve the return type via the
  // servlet factory map so sink patterns keyed on the returned class (e.g.
  // `HttpSession.setAttribute` for trust_boundary) match receivers built from
  // `req.getSession()` / `req.getSession(false)`. cognium-dev #117 Sprint 91:
  // 0% recall on OWASP Java trust-boundary category because chained factory
  // calls produced receiver_type=null, dropping trust_boundary sink matches
  // while xss's classless setAttribute pattern still fired at the same line.
  const chained = receiver.match(/^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\([^()]*\)$/);
  if (chained) {
    const varName = chained[1];
    const methodName = chained[2];
    const varType =
      context.localVarTypes.get(varName) ??
      context.paramTypes.get(varName) ??
      context.fieldTypes.get(varName);
    if (varType) {
      const returnType = JAVA_CHAINED_FACTORY_RETURN_TYPES[stripGenerics(varType)]?.[methodName];
      if (returnType) return resolveFqn(returnType, context);
    }
  }

  return { simpleName: null, fqn: null };
}

/**
 * Chained factory-method return types for Java servlet/JSP APIs.
 *
 * Keyed as `receiverType -> methodName -> returnType`. Used by
 * `resolveReceiverType` to pin the type of a receiver written as
 * `req.getSession().setAttribute(...)` so downstream sink matchers can
 * recognise `getSession()` as producing `HttpSession` and thus fire the
 * class-scoped `HttpSession.setAttribute` trust_boundary sink pattern.
 *
 * Deliberately narrow: only the servlet-container APIs where the return
 * type is defined by the interface contract are listed. Application-level
 * factories (`someService.getFoo()`) are still unresolved.
 */
const JAVA_CHAINED_FACTORY_RETURN_TYPES: Record<string, Record<string, string>> = {
  HttpServletRequest: {
    getSession: 'HttpSession',
    getServletContext: 'ServletContext',
    getRequestDispatcher: 'RequestDispatcher',
  },
  HttpSession: {
    getServletContext: 'ServletContext',
  },
  ServletContext: {
    getRequestDispatcher: 'RequestDispatcher',
  },
};

/**
 * Look up the FQN of a simple type name in the file's imports map.
 * Falls back to same-package resolution when the type was declared in
 * the file's package, or `null` when only wildcards / external types
 * exist (the simple name is still surfaced).
 */
function resolveFqn(
  simpleName: string | null,
  context: ResolutionContext,
): { simpleName: string | null; fqn: string | null } {
  if (!simpleName) return { simpleName: null, fqn: null };

  // Explicit import wins
  const importedFqn = context.imports.get(simpleName);
  if (importedFqn) {
    return { simpleName, fqn: importedFqn };
  }

  // Type declared in this file → use the file's package
  if (context.className === simpleName && context.packageName) {
    return { simpleName, fqn: `${context.packageName}.${simpleName}` };
  }

  // java.lang.* is implicitly imported
  if (JAVA_LANG_TYPES.has(simpleName)) {
    return { simpleName, fqn: `java.lang.${simpleName}` };
  }

  // Wildcard imports — cannot disambiguate, return simple name only
  return { simpleName, fqn: null };
}

/**
 * Common types from `java.lang` that are implicitly imported in every
 * compilation unit. Not exhaustive; kept to the subset most likely to
 * appear as call receivers (String, Object, Class, Thread, …) so we
 * can answer the FQN for the common cases without false-positive risk.
 */
const JAVA_LANG_TYPES = new Set([
  'String', 'StringBuilder', 'StringBuffer', 'Object', 'Class',
  'Integer', 'Long', 'Double', 'Float', 'Boolean', 'Character', 'Byte', 'Short',
  'Number', 'Math', 'System', 'Thread', 'Runnable', 'Throwable', 'Exception',
  'RuntimeException', 'Error', 'Process', 'ProcessBuilder',
  'Iterable', 'Comparable', 'CharSequence', 'Enum',
]);

/**
 * Extract call information from a method_invocation node.
 */
function extractCallInfo(node: Node, context: ResolutionContext): CallInfo {
  // Get method name
  const nameNode = node.childForFieldName('name');
  const methodName = nameNode ? getNodeText(nameNode) : 'unknown';

  // Get receiver (object the method is called on)
  const objectNode = node.childForFieldName('object');
  const receiver = objectNode ? getNodeText(objectNode) : null;

  // Get arguments
  const argsNode = node.childForFieldName('arguments');
  const args = argsNode ? extractArguments(argsNode) : [];

  // Find enclosing method
  const enclosingMethod = findEnclosingMethod(node);

  // Resolve the call
  const { resolved, resolution } = resolveMethodCall(methodName, receiver, context);

  // Resolve the receiver's declared type and FQN
  const { simpleName, fqn } = resolveReceiverType(receiver, context);

  return {
    method_name: methodName,
    receiver,
    receiver_type: simpleName,
    receiver_type_fqn: fqn,
    arguments: args,
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    in_method: enclosingMethod,
    resolved,
    resolution,
  };
}

/**
 * Extract call information from an object_creation_expression (new ...).
 */
function extractObjectCreation(node: Node, context: ResolutionContext): CallInfo | null {
  // Get the type being instantiated
  const typeNode = node.childForFieldName('type');
  if (!typeNode) return null;

  const typeName = getNodeText(typeNode);

  // Get arguments
  const argsNode = node.childForFieldName('arguments');
  const args = argsNode ? extractArguments(argsNode) : [];

  // Find enclosing method
  const enclosingMethod = findEnclosingMethod(node);

  // Constructor calls are always resolved (we know the class)
  const resolution: CallResolution = {
    status: 'resolved',
    target: `${typeName}.<init>`,
  };

  // For a constructor `new Foo(...)`, the call site already names the class —
  // surface that as receiver_type/receiver_type_fqn so downstream consumers
  // see consistent type info regardless of dispatch shape.
  const simpleType = stripGenerics(typeName);
  const { simpleName, fqn } = resolveFqn(simpleType, context);

  return {
    method_name: typeName, // Constructor name is the class name
    receiver: null,
    receiver_type: simpleName,
    receiver_type_fqn: fqn,
    arguments: args,
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    in_method: enclosingMethod,
    resolved: true,
    resolution,
  };
}

/**
 * Extract arguments from an argument_list node.
 */
function extractArguments(argsNode: Node): ArgumentInfo[] {
  const args: ArgumentInfo[] = [];
  let position = 0;

  for (let i = 0; i < argsNode.childCount; i++) {
    const child = argsNode.child(i);
    if (!child) continue;

    // Skip parentheses and commas
    if (child.type === '(' || child.type === ')' || child.type === ',') {
      continue;
    }

    const expression = getNodeText(child);
    const { variable, literal } = analyzeArgument(child);

    args.push({
      position,
      expression,
      variable,
      literal,
    });

    position++;
  }

  return args;
}

/**
 * Analyze an argument to extract variable name or literal value.
 */
function analyzeArgument(node: Node): { variable: string | null; literal: string | null } {
  // Check if it's a simple identifier (variable reference)
  if (node.type === 'identifier') {
    return { variable: getNodeText(node), literal: null };
  }

  // Check if it's a literal
  if (isLiteral(node)) {
    return { variable: null, literal: extractLiteralValue(node) };
  }

  // Check for field access (e.g., this.field or obj.field)
  if (node.type === 'field_access') {
    const field = node.childForFieldName('field');
    if (field) {
      return { variable: getNodeText(field), literal: null };
    }
  }

  // For complex expressions, try to find the primary variable
  const identifier = findPrimaryIdentifier(node);
  if (identifier) {
    return { variable: identifier, literal: null };
  }

  return { variable: null, literal: null };
}

/**
 * Check if a node represents a literal value.
 */
function isLiteral(node: Node): boolean {
  const literalTypes = new Set([
    'string_literal',
    'character_literal',
    'decimal_integer_literal',
    'hex_integer_literal',
    'octal_integer_literal',
    'binary_integer_literal',
    'decimal_floating_point_literal',
    'hex_floating_point_literal',
    'true',
    'false',
    'null_literal',
  ]);

  return literalTypes.has(node.type);
}

/**
 * Extract the value from a literal node.
 */
function extractLiteralValue(node: Node): string {
  const text = getNodeText(node);

  // Remove quotes from string literals
  if (node.type === 'string_literal') {
    return text.slice(1, -1);
  }

  // Remove quotes from character literals
  if (node.type === 'character_literal') {
    return text.slice(1, -1);
  }

  return text;
}

/**
 * Find the primary identifier in a complex expression.
 */
function findPrimaryIdentifier(node: Node): string | null {
  // Direct identifier
  if (node.type === 'identifier') {
    return getNodeText(node);
  }

  // Search children
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === 'identifier') {
      return getNodeText(child);
    }
  }

  // Recursive search for first identifier
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) {
      const result = findPrimaryIdentifier(child);
      if (result) return result;
    }
  }

  return null;
}

/**
 * Find the name of the enclosing method.
 */
function findEnclosingMethod(node: Node): string | null {
  const methodDecl = findAncestor(node, 'method_declaration');
  if (methodDecl) {
    const nameNode = methodDecl.childForFieldName('name');
    if (nameNode) {
      return getNodeText(nameNode);
    }
  }

  const constructorDecl = findAncestor(node, 'constructor_declaration');
  if (constructorDecl) {
    const nameNode = constructorDecl.childForFieldName('name');
    if (nameNode) {
      return getNodeText(nameNode);
    }
    return '<init>';
  }

  return null;
}

/**
 * Resolve a method call to determine its target.
 */
function resolveMethodCall(
  methodName: string,
  receiver: string | null,
  context: ResolutionContext
): { resolved: boolean; resolution: CallResolution } {
  // No receiver - might be this.method() or static import
  if (!receiver) {
    // Check if it's a method in the current class
    if (context.methodNames.has(methodName)) {
      return {
        resolved: true,
        resolution: {
          status: 'resolved',
          target: context.className ? `${context.className}.${methodName}` : methodName,
        },
      };
    }

    // Unresolved - could be a static import or inherited method
    return {
      resolved: false,
      resolution: {
        status: 'external_method',
      },
    };
  }

  // 'this' receiver - definitely in current class
  if (receiver === 'this') {
    return {
      resolved: true,
      resolution: {
        status: 'resolved',
        target: context.className ? `${context.className}.${methodName}` : methodName,
      },
    };
  }

  // 'super' receiver - parent class method
  if (receiver === 'super') {
    return {
      resolved: false,
      resolution: {
        status: 'external_method',
      },
    };
  }

  // Check if receiver is a field with known type
  const fieldType = context.fieldTypes.get(receiver);
  if (fieldType) {
    // Check if it's likely an interface (common patterns)
    if (isLikelyInterface(fieldType)) {
      return {
        resolved: false,
        resolution: {
          status: 'interface_method',
          candidates: [`${fieldType}.${methodName}`],
        },
      };
    }

    return {
      resolved: true,
      resolution: {
        status: 'resolved',
        target: `${fieldType}.${methodName}`,
      },
    };
  }

  // Check if receiver is a local variable with known type
  const localVarType = context.localVarTypes.get(receiver);
  if (localVarType) {
    // Check if it's likely an interface (common patterns)
    if (isLikelyInterface(localVarType)) {
      return {
        resolved: false,
        resolution: {
          status: 'interface_method',
          candidates: [`${localVarType}.${methodName}`],
        },
      };
    }

    return {
      resolved: true,
      resolution: {
        status: 'resolved',
        target: `${localVarType}.${methodName}`,
      },
    };
  }

  // Check if receiver looks like a class name (starts with uppercase)
  if (receiver[0] === receiver[0].toUpperCase() && /^[A-Z]/.test(receiver)) {
    // Static method call
    return {
      resolved: true,
      resolution: {
        status: 'resolved',
        target: `${receiver}.${methodName}`,
      },
    };
  }

  // Check common external types by receiver name patterns
  const externalType = inferTypeFromReceiverName(receiver);
  if (externalType) {
    return {
      resolved: true,
      resolution: {
        status: 'resolved',
        target: `${externalType}.${methodName}`,
      },
    };
  }

  // Can't resolve - unknown receiver
  return {
    resolved: false,
    resolution: {
      status: 'external_method',
    },
  };
}

/**
 * Check if a type name is likely an interface.
 */
function isLikelyInterface(typeName: string): boolean {
  const interfacePatterns = [
    /^I[A-Z]/,  // IService, IRepository
    /Service$/,
    /Repository$/,
    /Dao$/,
    /Manager$/,
    /Handler$/,
    /Listener$/,
    /Callback$/,
    /Provider$/,
    /Factory$/,
  ];

  return interfacePatterns.some(pattern => pattern.test(typeName));
}

/**
 * Infer type from common receiver naming patterns.
 */
function inferTypeFromReceiverName(receiver: string): string | null {
  const patterns: Record<string, string> = {
    request: 'HttpServletRequest',
    req: 'HttpServletRequest',
    response: 'HttpServletResponse',
    resp: 'HttpServletResponse',
    session: 'HttpSession',
    stmt: 'Statement',
    ps: 'PreparedStatement',
    conn: 'Connection',
    connection: 'Connection',
    em: 'EntityManager',
    rs: 'ResultSet',
    runtime: 'Runtime',
    out: 'PrintStream',
    err: 'PrintStream',
    writer: 'PrintWriter',
    pw: 'PrintWriter',
    bw: 'BufferedWriter',
  };

  const lowerReceiver = receiver.toLowerCase();
  return patterns[lowerReceiver] ?? null;
}

// =============================================================================
// Bash Call Extraction
// =============================================================================

/**
 * Extract all commands (treated as calls) from a Bash tree.
 * In Bash, every command invocation is a `command` node in the AST.
 */
function extractBashCalls(tree: Tree, cache?: NodeCache): CallInfo[] {
  const calls: CallInfo[] = [];

  const commands = getNodesFromCache(tree.rootNode, 'command', cache);
  for (const cmd of commands) {
    const callInfo = extractBashCommandInfo(cmd);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  return calls;
}

/**
 * Extract call information from a Bash `command` AST node.
 * The `name` field holds the command name; remaining children are arguments.
 */
function extractBashCommandInfo(node: Node): CallInfo | null {
  // tree-sitter-bash: command has a 'name' field for the command word
  const nameNode = node.childForFieldName('name');
  if (!nameNode) return null;

  const commandName = getNodeText(nameNode);
  if (!commandName) return null;

  // Collect arguments: all non-name, non-redirect children
  const args: ArgumentInfo[] = [];
  let position = 0;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;
    if (child === nameNode || child.id === nameNode.id) continue;
    // Skip I/O redirects and heredoc operators
    if (
      child.type.includes('redirect') ||
      child.type === 'heredoc_body' ||
      child.type === 'file_descriptor'
    ) {
      continue;
    }

    const expression = getNodeText(child);
    if (!expression.trim()) continue;

    // Extract variable reference if argument is/contains a variable expansion
    const variable = extractBashVariableRef(child);

    // Detect string literals: quoted strings without variable expansions
    const literal = variable === null ? extractBashLiteral(child) : null;

    args.push({
      position: position++,
      expression,
      variable,
      literal,
    });
  }

  // Find enclosing function_definition (if any)
  const inMethod = findBashEnclosingFunction(node);

  return {
    method_name: commandName,
    receiver: null,
    arguments: args,
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    in_method: inMethod,
    resolved: false,
    resolution: { status: 'external_method' },
  };
}

/**
 * Try to extract the primary variable name from a Bash argument node.
 * Handles `$VAR`, `${VAR}`, `"$VAR"`, and concatenations.
 */
function extractBashVariableRef(node: Node): string | null {
  const type = node.type;

  // Direct expansion: $VAR or ${VAR}
  if (type === 'simple_expansion' || type === 'expansion') {
    return getNodeText(node).replace(/^\$\{?/, '').replace(/\}$/, '');
  }

  // String that wraps expansions: "$VAR"
  if (type === 'string' || type === 'concatenation') {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (!child) continue;
      if (child.type === 'simple_expansion' || child.type === 'expansion') {
        return getNodeText(child).replace(/^\$\{?/, '').replace(/\}$/, '');
      }
    }
  }

  // Plain word that starts with $
  if (type === 'word') {
    const text = getNodeText(node);
    if (text.startsWith('$')) {
      return text.slice(1).replace(/^\{/, '').replace(/\}$/, '');
    }
  }

  return null;
}

/**
 * Extract a string literal value from a Bash argument node.
 * Returns the unquoted string for pure literals (no variable expansions),
 * or null if the argument contains variables or is not a literal.
 */
function extractBashLiteral(node: Node): string | null {
  const type = node.type;
  const text = getNodeText(node);

  // raw_string: 'content' — no interpolation possible
  if (type === 'raw_string') return text.slice(1, -1);

  // ansi_c_string: $'content'
  if (type === 'ansi_c_string') return text.slice(2, -1);

  // Double-quoted string: "content" — only literal if no expansions inside
  if (type === 'string') {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (!child) continue;
      if (child.type === 'simple_expansion' || child.type === 'expansion' ||
          child.type === 'command_substitution') {
        return null; // Has variable/command interpolation
      }
    }
    // Strip surrounding quotes
    if (text.startsWith('"') && text.endsWith('"')) return text.slice(1, -1);
    return text;
  }

  // Plain word without any $ signs — treat as literal
  if (type === 'word' && !text.startsWith('$') && !text.includes('$')) {
    return text;
  }

  return null;
}

/**
 * Walk up the AST to find the enclosing function_definition, if any.
 */
function findBashEnclosingFunction(node: Node): string | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'function_definition') {
      const nameNode = current.childForFieldName('name');
      return nameNode ? getNodeText(nameNode) : null;
    }
    current = current.parent;
  }
  return null;
}

// =============================================================================
// Python Call Extraction
// =============================================================================

/**
 * Extract all function/method calls from a Python tree.
 */
function extractPythonCalls(tree: Tree, cache?: NodeCache): CallInfo[] {
  const calls: CallInfo[] = [];

  // Build Python resolution context
  const context = buildPythonResolutionContext(tree, cache);

  // Find all call nodes
  const callNodes = getNodesFromCache(tree.rootNode, 'call', cache);
  for (const callNode of callNodes) {
    const callInfo = extractPythonCallInfo(callNode, context);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  return calls;
}

/**
 * Python resolution context.
 */
interface PythonResolutionContext {
  functionNames: Set<string>;
  classNames: Set<string>;
  imports: Map<string, string>; // name -> module
  variableTypes: Map<string, string>;
}

/**
 * Build context for Python method resolution.
 */
function buildPythonResolutionContext(tree: Tree, cache?: NodeCache): PythonResolutionContext {
  const context: PythonResolutionContext = {
    functionNames: new Set(),
    classNames: new Set(),
    imports: new Map(),
    variableTypes: new Map(),
  };

  // Collect function names
  const functions = getNodesFromCache(tree.rootNode, 'function_definition', cache);
  for (const func of functions) {
    const nameNode = func.childForFieldName('name');
    if (nameNode) {
      context.functionNames.add(getNodeText(nameNode));
    }
  }

  // Collect class names
  const classes = getNodesFromCache(tree.rootNode, 'class_definition', cache);
  for (const cls of classes) {
    const nameNode = cls.childForFieldName('name');
    if (nameNode) {
      context.classNames.add(getNodeText(nameNode));
    }
  }

  // Collect imports
  const importStatements = getNodesFromCache(tree.rootNode, 'import_statement', cache);
  for (const stmt of importStatements) {
    // import os, sys
    for (let i = 0; i < stmt.childCount; i++) {
      const child = stmt.child(i);
      if (child?.type === 'dotted_name') {
        const name = getNodeText(child);
        const parts = name.split('.');
        context.imports.set(parts[parts.length - 1], name);
      } else if (child?.type === 'aliased_import') {
        const nameNode = child.childForFieldName('name');
        const aliasNode = child.childForFieldName('alias');
        if (nameNode && aliasNode) {
          context.imports.set(getNodeText(aliasNode), getNodeText(nameNode));
        }
      }
    }
  }

  const importFromStatements = getNodesFromCache(tree.rootNode, 'import_from_statement', cache);
  for (const stmt of importFromStatements) {
    const moduleNode = stmt.childForFieldName('module_name');
    const moduleName = moduleNode ? getNodeText(moduleNode) : '';

    // from module import name1, name2
    for (let i = 0; i < stmt.childCount; i++) {
      const child = stmt.child(i);
      if (child?.type === 'dotted_name' && child !== moduleNode) {
        context.imports.set(getNodeText(child), moduleName);
      } else if (child?.type === 'aliased_import') {
        const nameNode = child.childForFieldName('name');
        const aliasNode = child.childForFieldName('alias');
        if (nameNode) {
          const alias = aliasNode ? getNodeText(aliasNode) : getNodeText(nameNode);
          context.imports.set(alias, moduleName);
        }
      }
    }
  }

  return context;
}

/**
 * Extract call information from a Python call node.
 */
function extractPythonCallInfo(node: Node, context: PythonResolutionContext): CallInfo | null {
  const funcNode = node.childForFieldName('function');
  if (!funcNode) return null;

  let methodName: string;
  let receiver: string | null = null;

  if (funcNode.type === 'attribute') {
    // Method call: obj.method()
    const objNode = funcNode.childForFieldName('object');
    const attrNode = funcNode.childForFieldName('attribute');
    receiver = objNode ? getNodeText(objNode) : null;
    methodName = attrNode ? getNodeText(attrNode) : 'unknown';
  } else if (funcNode.type === 'identifier') {
    // Function call: func()
    methodName = getNodeText(funcNode);
  } else {
    // Complex expression: (get_func())()
    methodName = getNodeText(funcNode);
  }

  // Extract arguments
  const argsNode = node.childForFieldName('arguments');
  const args = argsNode ? extractPythonArguments(argsNode) : [];

  // Find enclosing method
  const inMethod = findPythonEnclosingMethod(node);

  // Resolve the call
  const resolution = resolvePythonCall(methodName, receiver, context);

  return {
    method_name: methodName,
    receiver,
    arguments: args,
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    in_method: inMethod,
    resolved: resolution.status === 'resolved',
    resolution,
  };
}

/**
 * Extract Python call arguments.
 */
function extractPythonArguments(node: Node): ArgumentInfo[] {
  const args: ArgumentInfo[] = [];
  let position = 0;

  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (!child) continue;

    // Skip punctuation
    if (child.type === ',' || child.type === '(' || child.type === ')') continue;

    if (child.type === 'keyword_argument') {
      // Named argument: key=value
      const keyNode = child.childForFieldName('name');
      const valueNode = child.childForFieldName('value');
      const key = keyNode ? getNodeText(keyNode) : null;
      const value = valueNode ? getNodeText(valueNode) : '';
      const literal = valueNode ? extractPythonLiteral(valueNode) : null;
      const variable = valueNode?.type === 'identifier' ? getNodeText(valueNode) : null;

      args.push({
        position: position++,
        expression: key ? `${key}=${value}` : value,
        variable,
        literal,
      });
    } else {
      // Positional argument
      const expression = getNodeText(child);
      const literal = extractPythonLiteral(child);
      const variable = child.type === 'identifier' ? expression : null;

      args.push({
        position: position++,
        expression,
        variable,
        literal,
      });
    }
  }

  return args;
}

/**
 * Extract literal value from a Python node.
 *
 * f-strings with interpolations (e.g. `f"hello {name}"`) are NOT literals —
 * the interpolated expression may carry tainted data. Return null in that
 * case so the taint-matcher treats the argument as a potentially tainted
 * expression rather than a safe literal. Plain f-strings without `{}`
 * interpolations (e.g. `f"hello world"`) are still treated as literals.
 */
function extractPythonLiteral(node: Node): string | null {
  const literalTypes = ['string', 'integer', 'float', 'true', 'false', 'none'];
  if (literalTypes.includes(node.type)) {
    const text = getNodeText(node);
    // Remove quotes from strings
    if (node.type === 'string') {
      // tree-sitter-python produces an `interpolation` child node for each
      // `{expr}` block inside an f-string. If any are present, the string
      // cannot be treated as a safe literal.
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child && child.type === 'interpolation') {
          return null;
        }
      }
      return text.replace(/^['"]|['"]$/g, '').replace(/^f['"]|['"]$/g, '');
    }
    return text;
  }
  return null;
}

/**
 * Find the enclosing method/function for a Python call.
 */
function findPythonEnclosingMethod(node: Node): string | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'function_definition') {
      const nameNode = current.childForFieldName('name');
      return nameNode ? getNodeText(nameNode) : null;
    }
    current = current.parent;
  }
  return null;
}

/**
 * Resolve a Python call to its target.
 */
function resolvePythonCall(methodName: string, receiver: string | null, context: PythonResolutionContext): CallResolution {
  // Check if it's a known function in the current module
  if (!receiver && context.functionNames.has(methodName)) {
    return {
      status: 'resolved',
      target: methodName,
    };
  }

  // Check if it's a class constructor
  if (!receiver && context.classNames.has(methodName)) {
    return {
      status: 'resolved',
      target: `${methodName}.__init__`,
    };
  }

  // Check if the receiver is an imported module
  if (receiver && context.imports.has(receiver)) {
    return {
      status: 'resolved',
      target: `${context.imports.get(receiver)}.${methodName}`,
    };
  }

  // Check if it's a direct import
  if (!receiver && context.imports.has(methodName)) {
    return {
      status: 'resolved',
      target: `${context.imports.get(methodName)}.${methodName}`,
    };
  }

  // Common Python built-ins
  const builtins = new Set([
    'print', 'len', 'range', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple',
    'open', 'input', 'type', 'isinstance', 'hasattr', 'getattr', 'setattr',
    'enumerate', 'zip', 'map', 'filter', 'sorted', 'reversed', 'sum', 'min', 'max',
  ]);

  if (!receiver && builtins.has(methodName)) {
    return {
      status: 'resolved',
      target: `builtins.${methodName}`,
    };
  }

  // If we have a receiver but can't resolve, it's likely an external method
  if (receiver) {
    return {
      status: 'external_method',
    };
  }

  return {
    status: 'external_method',
  };
}

// =============================================================================
// Rust Call Extraction
// =============================================================================

/**
 * Extract all function/method calls from a Rust tree.
 */
function extractRustCalls(tree: Tree, cache?: NodeCache): CallInfo[] {
  const calls: CallInfo[] = [];

  // Build Rust resolution context
  const context = buildRustResolutionContext(tree, cache);

  // Find all call expressions (function/method calls)
  const callExpressions = getNodesFromCache(tree.rootNode, 'call_expression', cache);
  for (const call of callExpressions) {
    const callInfo = extractRustCallInfo(call, context);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  // Find macro invocations (println!, format!, etc.)
  const macroInvocations = getNodesFromCache(tree.rootNode, 'macro_invocation', cache);
  for (const macro of macroInvocations) {
    const callInfo = extractRustMacroInfo(macro);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  return calls;
}

/**
 * Rust resolution context.
 */
interface RustResolutionContext {
  functionNames: Set<string>;
  structNames: Set<string>;
  imports: Map<string, string>; // item name -> full path
}

/**
 * Build context for Rust method resolution.
 */
function buildRustResolutionContext(tree: Tree, cache?: NodeCache): RustResolutionContext {
  const context: RustResolutionContext = {
    functionNames: new Set(),
    structNames: new Set(),
    imports: new Map(),
  };

  // Collect function names
  const functions = getNodesFromCache(tree.rootNode, 'function_item', cache);
  for (const func of functions) {
    const nameNode = func.childForFieldName('name');
    if (nameNode) {
      context.functionNames.add(getNodeText(nameNode));
    }
  }

  // Collect struct names
  const structs = getNodesFromCache(tree.rootNode, 'struct_item', cache);
  for (const s of structs) {
    const nameNode = s.childForFieldName('name');
    if (nameNode) {
      context.structNames.add(getNodeText(nameNode));
    }
  }

  // Collect use declarations
  const useDecls = getNodesFromCache(tree.rootNode, 'use_declaration', cache);
  for (const useDecl of useDecls) {
    const text = getNodeText(useDecl);
    // Parse: use std::io; or use actix_web::{web, App}; or use foo::bar::Baz;
    const simpleMatch = text.match(/use\s+([\w:]+);/);
    if (simpleMatch) {
      const path = simpleMatch[1];
      const parts = path.split('::');
      const name = parts[parts.length - 1];
      context.imports.set(name, path);
    }

    // Parse grouped imports: use foo::{Bar, Baz};
    const groupMatch = text.match(/use\s+([\w:]+)::\{([^}]+)\}/);
    if (groupMatch) {
      const basePath = groupMatch[1];
      const items = groupMatch[2].split(',').map(s => s.trim());
      for (const item of items) {
        // Handle aliasing: Foo as F
        const [name, alias] = item.split(/\s+as\s+/);
        const importName = alias || name;
        context.imports.set(importName.trim(), `${basePath}::${name.trim()}`);
      }
    }
  }

  return context;
}

/**
 * Extract call information from a Rust call_expression node.
 */
function extractRustCallInfo(node: Node, context: RustResolutionContext): CallInfo | null {
  const funcNode = node.childForFieldName('function');
  if (!funcNode) return null;

  let methodName = '';
  let receiver: string | null = null;
  let receiverType: string | null = null;

  if (funcNode.type === 'identifier') {
    // Simple function call: foo()
    methodName = getNodeText(funcNode);
  } else if (funcNode.type === 'field_expression') {
    // Method call: obj.method()
    const objectNode = funcNode.childForFieldName('value');
    const fieldNode = funcNode.childForFieldName('field');
    if (objectNode && fieldNode) {
      receiver = getNodeText(objectNode);
      methodName = getNodeText(fieldNode);
    }
  } else if (funcNode.type === 'scoped_identifier') {
    // Scoped call: Foo::bar() or std::io::read()
    const text = getNodeText(funcNode);
    const parts = text.split('::');
    methodName = parts.pop() || '';
    receiver = parts.join('::');
    receiverType = receiver;
  } else {
    // Other expression
    methodName = getNodeText(funcNode);
  }

  // Extract arguments
  const argsNode = node.childForFieldName('arguments');
  const args = argsNode ? extractRustArguments(argsNode) : [];

  // Resolve the call
  const resolution = resolveRustCall(methodName, receiver, context);

  return {
    method_name: methodName,
    receiver: receiver,
    receiver_type: receiverType,
    arguments: args,
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    resolution,
    is_constructor: false,
  };
}

/**
 * Extract macro invocation information.
 */
function extractRustMacroInfo(node: Node): CallInfo | null {
  // Macro: println!("hello") or format!("foo {}", bar)
  const macroNode = node.childForFieldName('macro');
  if (!macroNode) {
    // Try first child
    const firstChild = node.child(0);
    if (!firstChild) return null;

    const text = getNodeText(firstChild);
    const methodName = text.replace(/!$/, '') + '!';

    // Extract arguments from token_tree
    const args: ArgumentInfo[] = [];
    for (let i = 1; i < node.childCount; i++) {
      const child = node.child(i);
      if (child?.type === 'token_tree') {
        const tokenText = getNodeText(child);
        args.push({
          position: 0,
          value: null,
          expression: tokenText,
        });
        break;
      }
    }

    return {
      method_name: methodName,
      receiver: null,
      receiver_type: null,
      arguments: args,
      location: {
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
      },
      resolution: {
        status: 'resolved',
        target: `std::macros::${methodName}`,
      },
      is_constructor: false,
    };
  }

  const methodName = getNodeText(macroNode) + '!';

  return {
    method_name: methodName,
    receiver: null,
    receiver_type: null,
    arguments: [],
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    resolution: {
      status: 'resolved',
      target: `std::macros::${methodName}`,
    },
    is_constructor: false,
  };
}

/**
 * Extract arguments from Rust function call.
 */
function extractRustArguments(argsNode: Node): ArgumentInfo[] {
  const args: ArgumentInfo[] = [];

  for (let i = 0; i < argsNode.childCount; i++) {
    const child = argsNode.child(i);
    if (!child) continue;

    // Skip punctuation
    if (child.type === '(' || child.type === ')' || child.type === ',') continue;

    const text = getNodeText(child);

    // Check for literal value
    let value: string | null = null;
    if (child.type === 'string_literal') {
      // Remove quotes
      value = text.replace(/^["']|["']$/g, '');
    } else if (child.type === 'integer_literal' || child.type === 'float_literal' || child.type === 'boolean_literal') {
      value = text;
    }

    args.push({
      position: args.length,
      value,
      expression: text,
    });
  }

  return args;
}

/**
 * Resolve a Rust function/method call.
 */
function resolveRustCall(methodName: string, receiver: string | null, context: RustResolutionContext): CallResolution {
  // Check if it's a local function
  if (!receiver && context.functionNames.has(methodName)) {
    return {
      status: 'resolved',
      target: methodName,
    };
  }

  // Check if receiver is a known struct
  if (receiver && context.structNames.has(receiver)) {
    return {
      status: 'resolved',
      target: `${receiver}::${methodName}`,
    };
  }

  // Check imports
  if (receiver && context.imports.has(receiver)) {
    return {
      status: 'resolved',
      target: `${context.imports.get(receiver)}::${methodName}`,
    };
  }

  // Check if method name is imported
  if (!receiver && context.imports.has(methodName)) {
    return {
      status: 'resolved',
      target: context.imports.get(methodName)!,
    };
  }

  // Common Rust standard library methods
  const stdMethods = new Set([
    'unwrap', 'unwrap_or', 'expect', 'ok', 'err', 'map', 'and_then', 'or_else',
    'clone', 'to_string', 'to_owned', 'into', 'from', 'as_ref', 'as_mut',
    'push', 'pop', 'insert', 'remove', 'get', 'contains', 'len', 'is_empty',
    'iter', 'into_iter', 'collect', 'filter', 'map', 'fold', 'for_each',
    'read', 'write', 'read_to_string', 'read_to_end',
  ]);

  if (stdMethods.has(methodName)) {
    return {
      status: 'resolved',
      target: receiver ? `${receiver}.${methodName}` : methodName,
    };
  }

  // External method
  return {
    status: 'external_method',
  };
}

// =============================================================================
// Go Call Extraction
// =============================================================================

/**
 * Extract all function/method calls from a Go tree.
 */
function extractGoCalls(tree: Tree, cache?: NodeCache): CallInfo[] {
  const calls: CallInfo[] = [];

  const callExpressions = getNodesFromCache(tree.rootNode, 'call_expression', cache);
  for (const call of callExpressions) {
    const callInfo = extractGoCallInfo(call);
    if (callInfo) {
      calls.push(callInfo);
    }
  }

  return calls;
}

/**
 * Extract call information from a Go call_expression node.
 */
function extractGoCallInfo(node: Node): CallInfo | null {
  const funcNode = node.childForFieldName('function');
  if (!funcNode) return null;

  let methodName: string;
  let receiver: string | null = null;

  if (funcNode.type === 'selector_expression') {
    // pkg.Function() or obj.Method()
    const operand = funcNode.childForFieldName('operand');
    const field = funcNode.childForFieldName('field');
    receiver = operand ? getNodeText(operand) : null;
    methodName = field ? getNodeText(field) : getNodeText(funcNode);
  } else if (funcNode.type === 'identifier') {
    // Plain function call: funcName()
    methodName = getNodeText(funcNode);
  } else {
    // Other expression
    methodName = getNodeText(funcNode);
  }

  // Extract arguments
  const argsNode = node.childForFieldName('arguments');
  const args = argsNode ? extractGoArguments(argsNode) : [];

  // Find enclosing function/method
  const inMethod = findGoEnclosingFunction(node);

  return {
    method_name: methodName,
    receiver,
    arguments: args,
    location: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    in_method: inMethod,
    resolved: false,
    resolution: { status: 'external_method' },
  };
}

/**
 * Extract arguments from a Go argument_list node.
 */
function extractGoArguments(argsNode: Node): ArgumentInfo[] {
  const args: ArgumentInfo[] = [];
  let position = 0;

  for (let i = 0; i < argsNode.childCount; i++) {
    const child = argsNode.child(i);
    if (!child) continue;

    // Skip punctuation
    if (child.type === '(' || child.type === ')' || child.type === ',') continue;

    const expression = getNodeText(child);
    const variable = child.type === 'identifier' ? expression : null;
    const literal = isGoLiteral(child) ? extractGoLiteralValue(child) : null;

    args.push({
      position: position++,
      expression,
      variable,
      literal,
    });
  }

  return args;
}

/**
 * Check if a node is a Go literal.
 */
function isGoLiteral(node: Node): boolean {
  const literalTypes = new Set([
    'interpreted_string_literal',
    'raw_string_literal',
    'int_literal',
    'float_literal',
    'true',
    'false',
    'nil',
  ]);
  return literalTypes.has(node.type);
}

/**
 * Extract value from a Go literal node.
 */
function extractGoLiteralValue(node: Node): string {
  const text = getNodeText(node);
  if (node.type === 'interpreted_string_literal') {
    return text.slice(1, -1); // Remove quotes
  }
  if (node.type === 'raw_string_literal') {
    return text.slice(1, -1); // Remove backticks
  }
  return text;
}

/**
 * Find the enclosing function/method for a Go call expression.
 */
function findGoEnclosingFunction(node: Node): string | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'function_declaration') {
      const nameNode = current.childForFieldName('name');
      return nameNode ? getNodeText(nameNode) : null;
    }
    if (current.type === 'method_declaration') {
      const nameNode = current.childForFieldName('name');
      return nameNode ? getNodeText(nameNode) : null;
    }
    current = current.parent;
  }
  return null;
}
