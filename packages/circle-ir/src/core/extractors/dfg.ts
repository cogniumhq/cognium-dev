/**
 * DFG (Data Flow Graph) builder
 *
 * Tracks variable definitions and uses for data flow analysis.
 */

import type { Node, Tree } from 'web-tree-sitter';
import type { DFG, DFGDef, DFGUse, DFGChain, SupportedLanguage } from '../../types/index.js';
import { findNodes, walkTree, getNodeText, findAncestor, getNodesFromCache, type NodeCache } from '../parser.js';

/**
 * Detect language from tree structure.
 */
function detectLanguage(tree: Tree): 'javascript' | 'java' {
  const root = tree.rootNode;

  // Check for JavaScript-specific nodes
  const jsNodeTypes = new Set([
    'arrow_function', 'lexical_declaration', 'function_declaration',
    'export_statement', 'import_statement', 'const', 'let'
  ]);

  // Check for Java-specific nodes
  const javaNodeTypes = new Set([
    'package_declaration', 'import_declaration', 'class_declaration',
    'method_declaration', 'annotation', 'throws'
  ]);

  let jsScore = 0;
  let javaScore = 0;

  // Walk first level children to detect language
  for (let i = 0; i < Math.min(root.childCount, 20); i++) {
    const child = root.child(i);
    if (!child) continue;

    if (jsNodeTypes.has(child.type)) jsScore++;
    if (javaNodeTypes.has(child.type)) javaScore++;

    // Check deeper for function bodies
    if (child.type === 'expression_statement') {
      const expr = child.child(0);
      if (expr?.type === 'call_expression') jsScore++;
    }
  }

  return jsScore > javaScore ? 'javascript' : 'java';
}

/**
 * Build DFG for all methods in the tree.
 */
export function buildDFG(tree: Tree, cache?: NodeCache, language?: SupportedLanguage): DFG {
  // Auto-detect language if not provided
  const effectiveLanguage = language ?? detectLanguage(tree);
  const isJavaScript = effectiveLanguage === 'javascript' || effectiveLanguage === 'typescript' || effectiveLanguage === 'tsx';

  if (isJavaScript) {
    return buildJavaScriptDFG(tree, cache);
  }
  if (effectiveLanguage === 'rust') {
    return buildRustDFG(tree, cache);
  }
  if (effectiveLanguage === 'bash') {
    return buildBashDFG(tree);
  }
  if (effectiveLanguage === 'go') {
    return buildGoDFG(tree);
  }
  return buildJavaDFG(tree, cache);
}

/**
 * Build DFG for Java code.
 */
function buildJavaDFG(tree: Tree, cache?: NodeCache): DFG {
  const defs: DFGDef[] = [];
  const uses: DFGUse[] = [];
  let defIdCounter = 1;
  let useIdCounter = 1;

  // Track definitions by variable name and scope for reaching definitions
  const scopeStack: Map<string, number>[] = [new Map()];

  // Find all method/constructor bodies
  const methods = [
    ...getNodesFromCache(tree.rootNode, 'method_declaration', cache),
    ...getNodesFromCache(tree.rootNode, 'constructor_declaration', cache),
  ];

  for (const method of methods) {
    // Start new scope for method
    scopeStack.push(new Map());

    // Extract parameters as definitions
    const params = method.childForFieldName('parameters');
    if (params) {
      const paramDefs = extractParameterDefs(params, defIdCounter);
      for (const def of paramDefs) {
        defs.push(def);
        currentScope(scopeStack).set(def.variable, def.id);
        defIdCounter++;
      }
    }

    // Process method body
    const body = method.childForFieldName('body');
    if (body) {
      const result = processBlock(body, defIdCounter, useIdCounter, scopeStack, false);
      defs.push(...result.defs);
      uses.push(...result.uses);
      defIdCounter = result.nextDefId;
      useIdCounter = result.nextUseId;
    }

    // Pop method scope
    scopeStack.pop();
  }

  // Also extract field definitions
  const classes = getNodesFromCache(tree.rootNode, 'class_declaration', cache);
  for (const cls of classes) {
    const body = cls.childForFieldName('body');
    if (body) {
      const fieldDefs = extractFieldDefs(body, defIdCounter);
      for (const def of fieldDefs) {
        defs.push(def);
        currentScope(scopeStack).set(def.variable, def.id);
        defIdCounter++;
      }
    }
  }

  // Compute def-use chains
  const chains = computeChains(defs, uses);

  return { defs, uses, chains };
}

/**
 * Build DFG for JavaScript/TypeScript code.
 */
function buildJavaScriptDFG(tree: Tree, cache?: NodeCache): DFG {
  const defs: DFGDef[] = [];
  const uses: DFGUse[] = [];
  let defIdCounter = 1;
  let useIdCounter = 1;

  // Track definitions by variable name and scope for reaching definitions
  const scopeStack: Map<string, number>[] = [new Map()];

  // Find all function bodies (function declarations, arrow functions, method definitions)
  const functions = [
    ...getNodesFromCache(tree.rootNode, 'function_declaration', cache),
    ...getNodesFromCache(tree.rootNode, 'arrow_function', cache),
    ...getNodesFromCache(tree.rootNode, 'method_definition', cache),
    ...getNodesFromCache(tree.rootNode, 'function', cache),
    ...getNodesFromCache(tree.rootNode, 'function_expression', cache),
  ];

  for (const func of functions) {
    // Start new scope for function
    scopeStack.push(new Map());

    // Extract parameters as definitions
    const params = func.childForFieldName('parameters') ?? func.childForFieldName('parameter');
    if (params) {
      const paramDefs = extractJSParameterDefs(params, defIdCounter);
      for (const def of paramDefs) {
        defs.push(def);
        currentScope(scopeStack).set(def.variable, def.id);
        defIdCounter++;
      }
    }

    // Process function body
    const body = func.childForFieldName('body');
    if (body) {
      if (body.type === 'statement_block') {
        const result = processBlock(body, defIdCounter, useIdCounter, scopeStack, true);
        defs.push(...result.defs);
        uses.push(...result.uses);
        defIdCounter = result.nextDefId;
        useIdCounter = result.nextUseId;
      } else {
        // Arrow function with expression body
        const exprUses = extractUses(body, useIdCounter, scopeStack, true);
        uses.push(...exprUses.uses);
        useIdCounter = exprUses.nextId;
      }
    }

    // Pop function scope
    scopeStack.pop();
  }

  // Process top-level variable declarations
  const topLevelDecls = [
    ...getNodesFromCache(tree.rootNode, 'lexical_declaration', cache),
    ...getNodesFromCache(tree.rootNode, 'variable_declaration', cache),
  ].filter(node => node.parent?.type === 'program' || node.parent?.type === 'export_statement');

  for (const decl of topLevelDecls) {
    const declarators = findNodes(decl, 'variable_declarator');
    for (const declarator of declarators) {
      const nameNode = declarator.childForFieldName('name');
      if (nameNode && nameNode.type === 'identifier') {
        const name = getNodeText(nameNode);
        const def: DFGDef = {
          id: defIdCounter++,
          variable: name,
          line: declarator.startPosition.row + 1,
          kind: 'local',
        };
        defs.push(def);
        currentScope(scopeStack).set(name, def.id);

        // Process initializer for uses
        const init = declarator.childForFieldName('value');
        if (init) {
          const initUses = extractUses(init, useIdCounter, scopeStack, true);
          uses.push(...initUses.uses);
          useIdCounter = initUses.nextId;
        }
      }
    }
  }

  // Process top-level expression statements (e.g., eval(payload), func calls)
  // These are not inside any function body, so they need explicit handling
  const topLevelStmts = tree.rootNode.children.filter(
    node => node.type === 'expression_statement'
  );
  for (const stmt of topLevelStmts) {
    const expr = stmt.child(0);
    if (expr) {
      const result = processExpression(expr, defIdCounter, useIdCounter, scopeStack, true);
      defs.push(...result.defs);
      uses.push(...result.uses);
      defIdCounter = result.nextDefId;
      useIdCounter = result.nextUseId;
    }
  }

  // Also extract class field definitions
  const classes = getNodesFromCache(tree.rootNode, 'class_declaration', cache);
  for (const cls of classes) {
    const body = cls.childForFieldName('body');
    if (body) {
      const fieldDefs = extractJSFieldDefs(body, defIdCounter);
      for (const def of fieldDefs) {
        defs.push(def);
        currentScope(scopeStack).set(def.variable, def.id);
        defIdCounter++;
      }
    }
  }

  // Compute def-use chains
  const chains = computeChains(defs, uses);

  return { defs, uses, chains };
}

interface BlockResult {
  defs: DFGDef[];
  uses: DFGUse[];
  nextDefId: number;
  nextUseId: number;
}

/**
 * Process a block of statements.
 */
function processBlock(
  block: Node,
  startDefId: number,
  startUseId: number,
  scopeStack: Map<string, number>[],
  isJavaScript: boolean
): BlockResult {
  const defs: DFGDef[] = [];
  const uses: DFGUse[] = [];
  let defId = startDefId;
  let useId = startUseId;

  // Process each statement
  for (let i = 0; i < block.childCount; i++) {
    const stmt = block.child(i);
    if (!stmt) continue;

    const result = processStatement(stmt, defId, useId, scopeStack, isJavaScript);
    defs.push(...result.defs);
    uses.push(...result.uses);
    defId = result.nextDefId;
    useId = result.nextUseId;
  }

  return { defs, uses, nextDefId: defId, nextUseId: useId };
}

/**
 * Process a single statement.
 */
function processStatement(
  stmt: Node,
  startDefId: number,
  startUseId: number,
  scopeStack: Map<string, number>[],
  isJavaScript: boolean
): BlockResult {
  const defs: DFGDef[] = [];
  const uses: DFGUse[] = [];
  let defId = startDefId;
  let useId = startUseId;

  switch (stmt.type) {
    case 'local_variable_declaration':
    case 'lexical_declaration':
    case 'variable_declaration': {
      // Extract variable definitions (Java: local_variable_declaration, JS: lexical_declaration/variable_declaration)
      const declarators = findNodes(stmt, 'variable_declarator');
      for (const decl of declarators) {
        const nameNode = decl.childForFieldName('name');
        if (nameNode) {
          // Handle simple identifiers
          if (nameNode.type === 'identifier') {
            const name = getNodeText(nameNode);
            const def: DFGDef = {
              id: defId++,
              variable: name,
              line: decl.startPosition.row + 1,
              kind: 'local',
            };
            defs.push(def);
            currentScope(scopeStack).set(name, def.id);
          } else if (isJavaScript) {
            // Handle destructuring patterns in JavaScript
            const destructDefs = extractDestructuringDefs(nameNode, defId);
            for (const def of destructDefs) {
              defs.push(def);
              currentScope(scopeStack).set(def.variable, def.id);
              defId++;
            }
          }

          // Process initializer for uses
          const init = decl.childForFieldName('value');
          if (init) {
            const initUses = extractUses(init, useId, scopeStack, isJavaScript);
            uses.push(...initUses.uses);
            useId = initUses.nextId;
          }
        }
      }
      break;
    }

    case 'expression_statement': {
      // Process the expression for defs and uses
      const expr = stmt.child(0);
      if (expr) {
        const result = processExpression(expr, defId, useId, scopeStack, isJavaScript);
        defs.push(...result.defs);
        uses.push(...result.uses);
        defId = result.nextDefId;
        useId = result.nextUseId;
      }
      break;
    }

    case 'return_statement': {
      // Extract uses from return expression
      const returnExpr = stmt.child(1); // Skip 'return' keyword
      if (returnExpr && returnExpr.type !== ';') {
        const exprUses = extractUses(returnExpr, useId, scopeStack, isJavaScript);
        uses.push(...exprUses.uses);
        useId = exprUses.nextId;
      }
      break;
    }

    case 'if_statement': {
      // Process condition
      const condition = stmt.childForFieldName('condition');
      if (condition) {
        const condUses = extractUses(condition, useId, scopeStack, isJavaScript);
        uses.push(...condUses.uses);
        useId = condUses.nextId;
      }

      // Process branches
      const consequence = stmt.childForFieldName('consequence');
      if (consequence) {
        const result = processStatement(consequence, defId, useId, scopeStack, isJavaScript);
        defs.push(...result.defs);
        uses.push(...result.uses);
        defId = result.nextDefId;
        useId = result.nextUseId;
      }

      const alternative = stmt.childForFieldName('alternative');
      if (alternative) {
        const result = processStatement(alternative, defId, useId, scopeStack, isJavaScript);
        defs.push(...result.defs);
        uses.push(...result.uses);
        defId = result.nextDefId;
        useId = result.nextUseId;
      }
      break;
    }

    case 'for_statement':
    case 'enhanced_for_statement':
    case 'for_in_statement':
    case 'for_of_statement':
    case 'while_statement':
    case 'do_statement': {
      // Process loop variable definitions (Java: enhanced for, JS: for-in/for-of)
      if (stmt.type === 'enhanced_for_statement') {
        const varName = stmt.childForFieldName('name');
        if (varName) {
          const def: DFGDef = {
            id: defId++,
            variable: getNodeText(varName),
            line: varName.startPosition.row + 1,
            kind: 'local',
          };
          defs.push(def);
          currentScope(scopeStack).set(def.variable, def.id);
        }

        const value = stmt.childForFieldName('value');
        if (value) {
          const valueUses = extractUses(value, useId, scopeStack, isJavaScript);
          uses.push(...valueUses.uses);
          useId = valueUses.nextId;
        }
      } else if (isJavaScript && (stmt.type === 'for_in_statement' || stmt.type === 'for_of_statement')) {
        // Handle for-in/for-of in JavaScript
        const left = stmt.childForFieldName('left');
        if (left) {
          if (left.type === 'identifier') {
            const def: DFGDef = {
              id: defId++,
              variable: getNodeText(left),
              line: left.startPosition.row + 1,
              kind: 'local',
            };
            defs.push(def);
            currentScope(scopeStack).set(def.variable, def.id);
          } else if (left.type === 'lexical_declaration' || left.type === 'variable_declaration') {
            // const x of array
            const declarators = findNodes(left, 'variable_declarator');
            for (const decl of declarators) {
              const nameNode = decl.childForFieldName('name');
              if (nameNode && nameNode.type === 'identifier') {
                const def: DFGDef = {
                  id: defId++,
                  variable: getNodeText(nameNode),
                  line: nameNode.startPosition.row + 1,
                  kind: 'local',
                };
                defs.push(def);
                currentScope(scopeStack).set(def.variable, def.id);
              }
            }
          }
        }

        const right = stmt.childForFieldName('right');
        if (right) {
          const rightUses = extractUses(right, useId, scopeStack, isJavaScript);
          uses.push(...rightUses.uses);
          useId = rightUses.nextId;
        }
      }

      // Process condition
      const condition = stmt.childForFieldName('condition');
      if (condition) {
        const condUses = extractUses(condition, useId, scopeStack, isJavaScript);
        uses.push(...condUses.uses);
        useId = condUses.nextId;
      }

      // Process body
      const body = stmt.childForFieldName('body');
      if (body) {
        const result = processStatement(body, defId, useId, scopeStack, isJavaScript);
        defs.push(...result.defs);
        uses.push(...result.uses);
        defId = result.nextDefId;
        useId = result.nextUseId;
      }
      break;
    }

    case 'block':
    case 'statement_block': {
      // New scope for block
      scopeStack.push(new Map());
      const result = processBlock(stmt, defId, useId, scopeStack, isJavaScript);
      defs.push(...result.defs);
      uses.push(...result.uses);
      defId = result.nextDefId;
      useId = result.nextUseId;
      scopeStack.pop();
      break;
    }

    default: {
      // For other statements, just extract uses
      const stmtUses = extractUses(stmt, useId, scopeStack, isJavaScript);
      uses.push(...stmtUses.uses);
      useId = stmtUses.nextId;
    }
  }

  return { defs, uses, nextDefId: defId, nextUseId: useId };
}

/**
 * Process an expression for definitions and uses.
 */
function processExpression(
  expr: Node,
  startDefId: number,
  startUseId: number,
  scopeStack: Map<string, number>[],
  isJavaScript: boolean
): BlockResult {
  const defs: DFGDef[] = [];
  const uses: DFGUse[] = [];
  let defId = startDefId;
  let useId = startUseId;

  if (expr.type === 'assignment_expression') {
    // For chained assignments like o1 = o2 = o3 = value, we need to:
    // 1. Process the right side first (to handle nested assignments)
    // 2. Then create a def for the left side
    const left = expr.childForFieldName('left');
    const right = expr.childForFieldName('right');

    // Process right side first - may contain nested assignments
    if (right) {
      if (right.type === 'assignment_expression') {
        // Recursively process nested assignment expression
        const result = processExpression(right, defId, useId, scopeStack, isJavaScript);
        defs.push(...result.defs);
        uses.push(...result.uses);
        defId = result.nextDefId;
        useId = result.nextUseId;
      } else {
        // Normal right side - extract uses
        const rightUses = extractUses(right, useId, scopeStack, isJavaScript);
        uses.push(...rightUses.uses);
        useId = rightUses.nextId;
      }
    }

    // Now process left side as a definition
    if (left && left.type === 'identifier') {
      const name = getNodeText(left);
      const def: DFGDef = {
        id: defId++,
        variable: name,
        line: left.startPosition.row + 1,
        kind: 'local',
      };
      defs.push(def);
      currentScope(scopeStack).set(name, def.id);
    } else if (left) {
      // Field access or array access - extract uses
      const leftUses = extractUses(left, useId, scopeStack, isJavaScript);
      uses.push(...leftUses.uses);
      useId = leftUses.nextId;
    }
  } else if (expr.type === 'update_expression') {
    // ++i or i++ is both a use and a def
    const operand = expr.childForFieldName('operand') ?? expr.child(0) ?? expr.child(1);
    if (operand && operand.type === 'identifier') {
      const name = getNodeText(operand);

      // Use first
      const reachingDef = findReachingDef(name, scopeStack);
      const use: DFGUse = {
        id: useId++,
        variable: name,
        line: operand.startPosition.row + 1,
        def_id: reachingDef,
      };
      uses.push(use);

      // Then def
      const def: DFGDef = {
        id: defId++,
        variable: name,
        line: operand.startPosition.row + 1,
        kind: 'local',
      };
      defs.push(def);
      currentScope(scopeStack).set(name, def.id);
    }
  } else {
    // Other expressions - just extract uses
    const exprUses = extractUses(expr, useId, scopeStack, isJavaScript);
    uses.push(...exprUses.uses);
    useId = exprUses.nextId;
  }

  return { defs, uses, nextDefId: defId, nextUseId: useId };
}

/**
 * Extract uses from an expression.
 */
function extractUses(
  node: Node,
  startId: number,
  scopeStack: Map<string, number>[],
  isJavaScript: boolean
): { uses: DFGUse[]; nextId: number } {
  const uses: DFGUse[] = [];
  let id = startId;

  walkTree(node, (n) => {
    if (n.type === 'identifier') {
      // Check if it's not a method name or type name
      const parent = n.parent;
      if (parent) {
        // Skip if it's a method name (Java: method_invocation, JS: call_expression)
        if (parent.type === 'method_invocation') {
          const nameNode = parent.childForFieldName('name');
          if (nameNode === n) return;
        }
        if (isJavaScript && parent.type === 'call_expression') {
          const funcNode = parent.childForFieldName('function');
          if (funcNode === n) return;
        }
        // Skip if it's a property name in member expression (JS)
        if (isJavaScript && parent.type === 'member_expression') {
          const propNode = parent.childForFieldName('property');
          if (propNode === n) return;
        }
        // Skip if it's a type name
        if (parent.type === 'type_identifier' ||
            parent.type === 'class_declaration' ||
            parent.type === 'interface_declaration') {
          return;
        }
        // Skip if it's a field name in declaration
        if (parent.type === 'variable_declarator') {
          const nameNode = parent.childForFieldName('name');
          if (nameNode === n) return;
        }
        // Skip if it's a property name in object (JS)
        if (isJavaScript && parent.type === 'pair') {
          const keyNode = parent.childForFieldName('key');
          if (keyNode === n) return;
        }
        // Skip if it's a shorthand property in object (JS)
        if (isJavaScript && parent.type === 'shorthand_property_identifier_pattern') {
          return;
        }
        // Skip if it's a function/method name (JS)
        if (isJavaScript && (parent.type === 'function_declaration' || parent.type === 'method_definition')) {
          const nameNode = parent.childForFieldName('name');
          if (nameNode === n) return;
        }
        // Skip if it's a formal parameter name
        if (parent.type === 'formal_parameter' || parent.type === 'required_parameter' || parent.type === 'optional_parameter') {
          const nameNode = parent.childForFieldName('name') ?? parent.childForFieldName('pattern');
          if (nameNode === n) return;
        }
      }

      const name = getNodeText(n);
      const reachingDef = findReachingDef(name, scopeStack);

      uses.push({
        id: id++,
        variable: name,
        line: n.startPosition.row + 1,
        def_id: reachingDef,
      });
    }
  });

  return { uses, nextId: id };
}

/**
 * Extract parameter definitions.
 */
function extractParameterDefs(params: Node, startId: number): DFGDef[] {
  const defs: DFGDef[] = [];
  let id = startId;

  for (let i = 0; i < params.childCount; i++) {
    const param = params.child(i);
    if (!param) continue;

    if (param.type === 'formal_parameter' || param.type === 'spread_parameter') {
      const nameNode = param.childForFieldName('name');
      if (nameNode) {
        defs.push({
          id: id++,
          variable: getNodeText(nameNode),
          line: param.startPosition.row + 1,
          kind: 'param',
        });
      }
    }
  }

  return defs;
}

/**
 * Extract field definitions from a class body.
 */
function extractFieldDefs(body: Node, startId: number): DFGDef[] {
  const defs: DFGDef[] = [];
  let id = startId;

  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    if (child.type === 'field_declaration') {
      const declarators = findNodes(child, 'variable_declarator');
      for (const decl of declarators) {
        const nameNode = decl.childForFieldName('name');
        if (nameNode) {
          defs.push({
            id: id++,
            variable: getNodeText(nameNode),
            line: decl.startPosition.row + 1,
            kind: 'field',
          });
        }
      }
    }
  }

  return defs;
}

/**
 * Extract JavaScript parameter definitions.
 * Handles: simple params, default params, rest params, destructuring patterns
 */
function extractJSParameterDefs(params: Node, startId: number): DFGDef[] {
  const defs: DFGDef[] = [];
  let id = startId;

  for (let i = 0; i < params.childCount; i++) {
    const param = params.child(i);
    if (!param) continue;

    // Skip punctuation
    if (param.type === ',' || param.type === '(' || param.type === ')') continue;

    // Simple identifier parameter
    if (param.type === 'identifier') {
      defs.push({
        id: id++,
        variable: getNodeText(param),
        line: param.startPosition.row + 1,
        kind: 'param',
      });
    }
    // Rest parameter (...args)
    else if (param.type === 'rest_pattern' || param.type === 'rest_element') {
      const nameNode = param.namedChildCount > 0 ? param.namedChild(0) : null;
      if (nameNode && nameNode.type === 'identifier') {
        defs.push({
          id: id++,
          variable: getNodeText(nameNode),
          line: param.startPosition.row + 1,
          kind: 'param',
        });
      }
    }
    // Assignment pattern (default value): name = defaultValue
    else if (param.type === 'assignment_pattern') {
      const leftNode = param.childForFieldName('left');
      if (leftNode && leftNode.type === 'identifier') {
        defs.push({
          id: id++,
          variable: getNodeText(leftNode),
          line: param.startPosition.row + 1,
          kind: 'param',
        });
      } else if (leftNode) {
        // Could be destructuring with default
        const destructDefs = extractDestructuringDefs(leftNode, id);
        for (const def of destructDefs) {
          def.kind = 'param';
          defs.push(def);
          id++;
        }
      }
    }
    // Destructuring pattern
    else if (param.type === 'object_pattern' || param.type === 'array_pattern') {
      const destructDefs = extractDestructuringDefs(param, id);
      for (const def of destructDefs) {
        def.kind = 'param';
        defs.push(def);
        id++;
      }
    }
    // TypeScript formal parameters
    else if (param.type === 'required_parameter' || param.type === 'optional_parameter') {
      const patternNode = param.childForFieldName('pattern');
      if (patternNode && patternNode.type === 'identifier') {
        defs.push({
          id: id++,
          variable: getNodeText(patternNode),
          line: param.startPosition.row + 1,
          kind: 'param',
        });
      }
    }
  }

  return defs;
}

/**
 * Extract JavaScript field definitions from a class body.
 */
function extractJSFieldDefs(body: Node, startId: number): DFGDef[] {
  const defs: DFGDef[] = [];
  let id = startId;

  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child) continue;

    // Class field definition (public_field_definition in tree-sitter-javascript)
    if (child.type === 'public_field_definition' || child.type === 'field_definition') {
      const nameNode = child.childForFieldName('name');
      if (nameNode && nameNode.type === 'property_identifier') {
        defs.push({
          id: id++,
          variable: getNodeText(nameNode),
          line: child.startPosition.row + 1,
          kind: 'field',
        });
      }
    }
  }

  return defs;
}

/**
 * Extract definitions from destructuring patterns.
 */
function extractDestructuringDefs(node: Node, startId: number): DFGDef[] {
  const defs: DFGDef[] = [];
  let id = startId;

  if (node.type === 'object_pattern') {
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (!child) continue;

      if (child.type === 'shorthand_property_identifier_pattern') {
        // { foo } shorthand
        defs.push({
          id: id++,
          variable: getNodeText(child),
          line: child.startPosition.row + 1,
          kind: 'local',
        });
      } else if (child.type === 'pair_pattern') {
        // { key: value }
        const valueNode = child.childForFieldName('value');
        if (valueNode && valueNode.type === 'identifier') {
          defs.push({
            id: id++,
            variable: getNodeText(valueNode),
            line: valueNode.startPosition.row + 1,
            kind: 'local',
          });
        } else if (valueNode) {
          // Nested destructuring
          const nestedDefs = extractDestructuringDefs(valueNode, id);
          defs.push(...nestedDefs);
          id += nestedDefs.length;
        }
      } else if (child.type === 'rest_pattern') {
        // { ...rest }
        const nameNode = child.namedChildCount > 0 ? child.namedChild(0) : null;
        if (nameNode && nameNode.type === 'identifier') {
          defs.push({
            id: id++,
            variable: getNodeText(nameNode),
            line: child.startPosition.row + 1,
            kind: 'local',
          });
        }
      } else if (child.type === 'assignment_pattern') {
        // { foo = defaultValue }
        const leftNode = child.childForFieldName('left');
        if (leftNode && leftNode.type === 'shorthand_property_identifier_pattern') {
          defs.push({
            id: id++,
            variable: getNodeText(leftNode),
            line: leftNode.startPosition.row + 1,
            kind: 'local',
          });
        } else if (leftNode && leftNode.type === 'identifier') {
          defs.push({
            id: id++,
            variable: getNodeText(leftNode),
            line: leftNode.startPosition.row + 1,
            kind: 'local',
          });
        }
      }
    }
  } else if (node.type === 'array_pattern') {
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (!child) continue;

      if (child.type === 'identifier') {
        defs.push({
          id: id++,
          variable: getNodeText(child),
          line: child.startPosition.row + 1,
          kind: 'local',
        });
      } else if (child.type === 'rest_pattern') {
        const nameNode = child.namedChildCount > 0 ? child.namedChild(0) : null;
        if (nameNode && nameNode.type === 'identifier') {
          defs.push({
            id: id++,
            variable: getNodeText(nameNode),
            line: child.startPosition.row + 1,
            kind: 'local',
          });
        }
      } else if (child.type === 'assignment_pattern') {
        // [x = defaultValue]
        const leftNode = child.childForFieldName('left');
        if (leftNode && leftNode.type === 'identifier') {
          defs.push({
            id: id++,
            variable: getNodeText(leftNode),
            line: leftNode.startPosition.row + 1,
            kind: 'local',
          });
        }
      } else if (child.type === 'object_pattern' || child.type === 'array_pattern') {
        // Nested destructuring
        const nestedDefs = extractDestructuringDefs(child, id);
        defs.push(...nestedDefs);
        id += nestedDefs.length;
      }
    }
  }

  return defs;
}

/**
 * Get the current scope.
 */
function currentScope(scopeStack: Map<string, number>[]): Map<string, number> {
  return scopeStack[scopeStack.length - 1];
}

/**
 * Find the reaching definition for a variable.
 */
function findReachingDef(name: string, scopeStack: Map<string, number>[]): number | null {
  // Search from innermost scope to outermost
  for (let i = scopeStack.length - 1; i >= 0; i--) {
    const defId = scopeStack[i].get(name);
    if (defId !== undefined) {
      return defId;
    }
  }
  return null;
}

/**
 * Compute def-use chains.
 *
 * A chain connects a definition to another definition when the first
 * definition's value flows to create the second definition.
 *
 * Example:
 *   int x = getInput();  // def1: x
 *   int y = x + 1;       // use1: x (def_id=1), def2: y
 *
 * Chain: { from_def: 1, to_def: 2, via: "x" }
 */
function computeChains(defs: DFGDef[], uses: DFGUse[]): DFGChain[] {
  const chains: DFGChain[] = [];

  // Create a map of def_id -> def for quick lookup
  const defById = new Map<number, DFGDef>();
  for (const def of defs) {
    defById.set(def.id, def);
  }

  // Group uses by line to find uses in definitions
  const usesByLine = new Map<number, DFGUse[]>();
  for (const use of uses) {
    const existing = usesByLine.get(use.line) ?? [];
    existing.push(use);
    usesByLine.set(use.line, existing);
  }

  // For each definition, find uses on the same line that might be in its initializer
  // This is a heuristic - more precise would require tracking def-use relationships in AST
  for (const def of defs) {
    if (def.kind === 'local') {
      const usesOnLine = usesByLine.get(def.line) ?? [];

      for (const use of usesOnLine) {
        // If this use has a reaching def, create a chain
        if (use.def_id !== null && use.def_id !== def.id) {
          // Avoid duplicate chains
          const exists = chains.some(
            c => c.from_def === use.def_id && c.to_def === def.id && c.via === use.variable
          );

          if (!exists) {
            chains.push({
              from_def: use.def_id,
              to_def: def.id,
              via: use.variable,
            });
          }
        }
      }
    }
  }

  // Sort chains for consistent output
  chains.sort((a, b) => a.from_def - b.from_def || a.to_def - b.to_def);

  return chains;
}

/**
 * Build DFG for Bash/Shell code.
 *
 * Bash has dynamic scoping — all variables are global unless declared with
 * `local`.  We track:
 *   - DFGDef from `variable_assignment` (VAR=value)
 *   - DFGDef from `read` commands (read VAR)
 *   - DFGDef from `for_statement` loop variable
 *   - DFGUse from `simple_expansion` ($VAR) and `expansion` (${VAR})
 */
function buildBashDFG(tree: Tree): DFG {
  const defs: DFGDef[] = [];
  const uses: DFGUse[] = [];
  let defIdCounter = 1;
  let useIdCounter = 1;

  // Single global scope (Bash dynamic scoping)
  const scopeStack: Map<string, number>[] = [new Map()];

  // Positional parameters ($1–$9, $@, $*) are always external input.
  // Create synthetic defs at line 0 so they get reaching-def chains.
  const positionalParams = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '@', '*'];
  for (const p of positionalParams) {
    const def: DFGDef = {
      id: defIdCounter++,
      variable: p,
      line: 0,
      kind: 'param',
    };
    defs.push(def);
    currentScope(scopeStack).set(p, def.id);
  }

  walkTree(tree.rootNode, (node) => {
    if (node.type === 'variable_assignment') {
      // VAR=value  — Tree-sitter Bash: variable_assignment has `name` and `value` fields
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const varName = getNodeText(nameNode);
        const def: DFGDef = {
          id: defIdCounter++,
          variable: varName,
          line: node.startPosition.row + 1,
          kind: 'local',
        };
        defs.push(def);
        currentScope(scopeStack).set(varName, def.id);
        // Value-side uses ($VAR, ${VAR}) are picked up by the main walkTree
        // descending into children — no need for a separate extraction pass.
      }
    } else if (node.type === 'command') {
      // Check for `read` builtin: read VAR1 VAR2 ...
      const nameNode = node.childForFieldName('name');
      if (nameNode && getNodeText(nameNode) === 'read') {
        // Arguments after `read` are variable names being defined
        for (let i = 0; i < node.namedChildCount; i++) {
          const arg = node.namedChild(i);
          if (!arg || arg === nameNode) continue;
          // Skip flags like -r, -p, etc.
          if (arg.type === 'word') {
            const text = getNodeText(arg);
            if (text.startsWith('-')) continue;
            const def: DFGDef = {
              id: defIdCounter++,
              variable: text,
              line: node.startPosition.row + 1,
              kind: 'local',
            };
            defs.push(def);
            currentScope(scopeStack).set(text, def.id);
          }
        }
      }
    } else if (node.type === 'for_statement') {
      // for VAR in ...; do ...; done
      const varNode = node.childForFieldName('variable');
      if (varNode) {
        const varName = getNodeText(varNode);
        const def: DFGDef = {
          id: defIdCounter++,
          variable: varName,
          line: node.startPosition.row + 1,
          kind: 'local',
        };
        defs.push(def);
        currentScope(scopeStack).set(varName, def.id);
      }
    } else if (node.type === 'simple_expansion') {
      // $VAR — child is a `variable_name` node
      const varNameNode = node.namedChildCount > 0 ? node.namedChild(0) : null;
      if (varNameNode) {
        const varName = getNodeText(varNameNode);
        if (varName && !varName.startsWith('?') && !varName.startsWith('#')) {
          let reachingDef = findReachingDef(varName, scopeStack);
          // If the variable has no reaching def (i.e. it's an env var or an
          // unbound identifier), synthesize a `param`-kind def at line 0 so that
          // env-sourced taint can be seeded and propagated through the DFG.
          // Skip single-character special parameters (already created above).
          if (reachingDef === null && !positionalParams.includes(varName)) {
            const def: DFGDef = {
              id: defIdCounter++,
              variable: varName,
              line: 0,
              kind: 'param',
            };
            defs.push(def);
            scopeStack[0].set(varName, def.id);
            reachingDef = def.id;
          }
          uses.push({
            id: useIdCounter++,
            variable: varName,
            line: node.startPosition.row + 1,
            def_id: reachingDef,
          });
        }
      }
    } else if (node.type === 'expansion') {
      // ${VAR}, ${VAR:-default}, etc. — first named child is usually `variable_name`
      // or the operator expression
      const varNameNode = node.namedChildCount > 0 ? node.namedChild(0) : null;
      if (varNameNode && varNameNode.type === 'variable_name') {
        const varName = getNodeText(varNameNode);
        let reachingDef = findReachingDef(varName, scopeStack);
        if (reachingDef === null && !positionalParams.includes(varName)) {
          const def: DFGDef = {
            id: defIdCounter++,
            variable: varName,
            line: 0,
            kind: 'param',
          };
          defs.push(def);
          scopeStack[0].set(varName, def.id);
          reachingDef = def.id;
        }
        uses.push({
          id: useIdCounter++,
          variable: varName,
          line: node.startPosition.row + 1,
          def_id: reachingDef,
        });
      }
    }
  });

  const chains = computeChains(defs, uses);
  return { defs, uses, chains };
}

/**
 * Build DFG for Rust code.
 */
function buildRustDFG(tree: Tree, cache?: NodeCache): DFG {
  const defs: DFGDef[] = [];
  const uses: DFGUse[] = [];
  let defIdCounter = 1;
  let useIdCounter = 1;

  // Track definitions by variable name and scope for reaching definitions
  const scopeStack: Map<string, number>[] = [new Map()];

  // Find all function bodies
  const functions = findNodes(tree.rootNode, 'function_item');

  for (const func of functions) {
    // Start new scope for function
    scopeStack.push(new Map());

    // Extract parameters as definitions
    const params = func.childForFieldName('parameters');
    if (params) {
      for (let i = 0; i < params.childCount; i++) {
        const param = params.child(i);
        if (param?.type === 'parameter') {
          const patternNode = param.childForFieldName('pattern');
          if (patternNode) {
            const varName = getNodeText(patternNode);
            const def: DFGDef = {
              id: defIdCounter++,
              variable: varName,
              kind: 'param',
              line: param.startPosition.row + 1,
              column: param.startPosition.column,
              expression: getNodeText(param),
            };
            defs.push(def);
            currentScope(scopeStack).set(varName, def.id);
          }
        }
      }
    }

    // Process function body
    const body = func.childForFieldName('body');
    if (body) {
      processRustBlock(body, defs, uses, defIdCounter, useIdCounter, scopeStack);
    }

    // Pop function scope
    scopeStack.pop();
  }

  // Build chains from defs and uses
  const chains = computeChains(defs, uses);

  return { defs, uses, chains };
}

/**
 * Process a Rust block and extract definitions and uses.
 */
function processRustBlock(
  node: Node,
  defs: DFGDef[],
  uses: DFGUse[],
  defIdCounter: number,
  useIdCounter: number,
  scopeStack: Map<string, number>[]
): { defId: number; useId: number } {
  walkTree(node, (child) => {
    if (child.type === 'let_declaration') {
      // Extract variable definition from let binding
      const patternNode = child.childForFieldName('pattern');
      const valueNode = child.childForFieldName('value');

      if (patternNode) {
        const varName = getNodeText(patternNode);
        const def: DFGDef = {
          id: defIdCounter++,
          variable: varName,
          kind: 'local',
          line: child.startPosition.row + 1,
          column: child.startPosition.column,
          expression: valueNode ? getNodeText(valueNode) : undefined,
        };
        defs.push(def);
        currentScope(scopeStack).set(varName, def.id);
      }

      // Extract uses from the value expression
      if (valueNode) {
        extractRustUses(valueNode, uses, useIdCounter, scopeStack);
      }
    } else if (child.type === 'assignment_expression') {
      // Handle reassignment
      const leftNode = child.childForFieldName('left');
      const rightNode = child.childForFieldName('right');

      if (leftNode && leftNode.type === 'identifier') {
        const varName = getNodeText(leftNode);
        const def: DFGDef = {
          id: defIdCounter++,
          variable: varName,
          kind: 'local',
          line: child.startPosition.row + 1,
          column: child.startPosition.column,
          expression: rightNode ? getNodeText(rightNode) : undefined,
        };
        defs.push(def);
        currentScope(scopeStack).set(varName, def.id);
      }

      // Extract uses from right side
      if (rightNode) {
        extractRustUses(rightNode, uses, useIdCounter, scopeStack);
      }
    } else if (child.type === 'call_expression') {
      // Extract uses from call arguments
      const argsNode = child.childForFieldName('arguments');
      if (argsNode) {
        extractRustUses(argsNode, uses, useIdCounter, scopeStack);
      }
    }
  });

  return { defId: defIdCounter, useId: useIdCounter };
}

/**
 * Extract variable uses from a Rust expression.
 */
function extractRustUses(
  node: Node,
  uses: DFGUse[],
  useIdCounter: number,
  scopeStack: Map<string, number>[]
): number {
  walkTree(node, (child) => {
    if (child.type === 'identifier') {
      const varName = getNodeText(child);
      // Skip keywords and type names (simple heuristic: starts with uppercase = type)
      if (varName.length > 0 && !isRustKeyword(varName) && varName[0] === varName[0].toLowerCase()) {
        const defId = findReachingDef(varName, scopeStack);
        uses.push({
          id: useIdCounter++,
          variable: varName,
          line: child.startPosition.row + 1,
          column: child.startPosition.column,
          def_id: defId,
        });
      }
    }
  });
  return useIdCounter;
}

/**
 * Check if a name is a Rust keyword.
 */
function isRustKeyword(name: string): boolean {
  const keywords = new Set([
    'as', 'break', 'const', 'continue', 'crate', 'else', 'enum', 'extern',
    'false', 'fn', 'for', 'if', 'impl', 'in', 'let', 'loop', 'match', 'mod',
    'move', 'mut', 'pub', 'ref', 'return', 'self', 'Self', 'static', 'struct',
    'super', 'trait', 'true', 'type', 'unsafe', 'use', 'where', 'while',
    'async', 'await', 'dyn', 'abstract', 'become', 'box', 'do', 'final',
    'macro', 'override', 'priv', 'typeof', 'unsized', 'virtual', 'yield',
  ]);
  return keywords.has(name);
}

// =============================================================================
// Go DFG Builder
// =============================================================================

const GO_KEYWORDS = new Set([
  'break', 'case', 'chan', 'const', 'continue', 'default', 'defer', 'else',
  'fallthrough', 'for', 'func', 'go', 'goto', 'if', 'import', 'interface',
  'map', 'package', 'range', 'return', 'select', 'struct', 'switch', 'type',
  'var', 'true', 'false', 'nil', 'iota', 'append', 'cap', 'close', 'complex',
  'copy', 'delete', 'imag', 'len', 'make', 'new', 'panic', 'print', 'println',
  'real', 'recover', 'string', 'int', 'int8', 'int16', 'int32', 'int64',
  'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'float32', 'float64',
  'complex64', 'complex128', 'byte', 'rune', 'bool', 'error', 'any',
]);

/**
 * Build DFG for Go code.
 *
 * Go has block scoping with := introducing new variables. Track:
 *   - DFGDef from function/method parameters
 *   - DFGDef from short_var_declaration (:=)
 *   - DFGDef from var_declaration
 *   - DFGDef from assignment_statement (=) — reassignment
 *   - DFGDef from range_clause loop variables
 *   - DFGUse from identifier references in expressions
 */
function buildGoDFG(tree: Tree): DFG {
  const defs: DFGDef[] = [];
  const uses: DFGUse[] = [];
  let defIdCounter = 1;
  let useIdCounter = 1;

  const scopeStack: Map<string, number>[] = [new Map()];

  // Process each function/method declaration
  const functions = [
    ...findNodes(tree.rootNode, 'function_declaration'),
    ...findNodes(tree.rootNode, 'method_declaration'),
  ];

  for (const func of functions) {
    scopeStack.push(new Map());

    // Extract parameters
    const params = func.childForFieldName('parameters');
    if (params) {
      extractGoParamDefs(params, defs, defIdCounter, scopeStack);
      defIdCounter = defs.length + 1;
    }

    // For method declarations, extract receiver as a def
    const receiver = func.childForFieldName('receiver');
    if (receiver) {
      extractGoParamDefs(receiver, defs, defIdCounter, scopeStack);
      defIdCounter = defs.length + 1;
    }

    // Process function body
    const body = func.childForFieldName('body');
    if (body) {
      processGoBlock(body, defs, uses, scopeStack, { defId: defIdCounter, useId: useIdCounter });
      defIdCounter = defs.length + 1;
      useIdCounter = uses.length + 1;
    }

    scopeStack.pop();
  }

  // Also process top-level var declarations (package-level)
  for (let i = 0; i < tree.rootNode.childCount; i++) {
    const child = tree.rootNode.child(i);
    if (!child) continue;
    if (child.type === 'var_declaration') {
      processGoVarDecl(child, defs, scopeStack, { defId: defIdCounter });
      defIdCounter = defs.length + 1;
    }
  }

  const chains = computeChains(defs, uses);
  return { defs, uses, chains };
}

/**
 * Extract parameter definitions from a Go parameter_list.
 */
function extractGoParamDefs(
  params: Node,
  defs: DFGDef[],
  _startId: number,
  scopeStack: Map<string, number>[]
): void {
  for (let i = 0; i < params.childCount; i++) {
    const param = params.child(i);
    if (!param || param.type !== 'parameter_declaration') continue;

    // parameter_declaration can have multiple names: (a, b int)
    const typeNode = param.childForFieldName('type');
    for (let j = 0; j < param.childCount; j++) {
      const nameNode = param.child(j);
      if (!nameNode || nameNode.type !== 'identifier') continue;
      if (nameNode === typeNode) continue;

      const varName = getNodeText(nameNode);
      if (varName === '_') continue;

      const def: DFGDef = {
        id: defs.length + 1,
        variable: varName,
        kind: 'param',
        line: param.startPosition.row + 1,
      };
      defs.push(def);
      currentScope(scopeStack).set(varName, def.id);
    }
  }
}

/**
 * Process a Go block (function body, if body, etc.) for definitions and uses.
 */
function processGoBlock(
  node: Node,
  defs: DFGDef[],
  uses: DFGUse[],
  scopeStack: Map<string, number>[],
  counters: { defId: number; useId: number }
): void {
  walkTree(node, (child) => {
    if (child.type === 'short_var_declaration') {
      // x, y := expr
      const left = child.childForFieldName('left');
      const right = child.childForFieldName('right');

      // Extract uses from right side first
      if (right) {
        extractGoUses(right, uses, scopeStack);
      }

      // Then create defs for left side
      if (left) {
        extractGoLhsDefs(left, defs, scopeStack, child.startPosition.row + 1);
      }
    } else if (child.type === 'var_declaration') {
      processGoVarDecl(child, defs, scopeStack, counters);
    } else if (child.type === 'assignment_statement') {
      const left = child.childForFieldName('left');
      const right = child.childForFieldName('right');

      // Uses from right side
      if (right) {
        extractGoUses(right, uses, scopeStack);
      }

      // Defs for left side (reassignment)
      if (left) {
        extractGoLhsDefs(left, defs, scopeStack, child.startPosition.row + 1);
      }
    } else if (child.type === 'for_statement') {
      // range clause: for k, v := range expr
      const rangeClause = findChildByTypeGo(child, 'range_clause');
      if (rangeClause) {
        const left = rangeClause.childForFieldName('left');
        if (left) {
          extractGoLhsDefs(left, defs, scopeStack, child.startPosition.row + 1);
        }
      }
    } else if (child.type === 'call_expression') {
      // Extract uses from call arguments
      extractGoUses(child, uses, scopeStack);
    } else if (child.type === 'return_statement') {
      // Extract uses from return expressions
      for (let i = 0; i < child.childCount; i++) {
        const expr = child.child(i);
        if (expr && expr.type !== 'return') {
          extractGoUses(expr, uses, scopeStack);
        }
      }
    }
  });
}

/**
 * Process a Go var declaration (var x = value or var x type = value).
 */
function processGoVarDecl(
  node: Node,
  defs: DFGDef[],
  scopeStack: Map<string, number>[],
  _counters: { defId: number }
): void {
  // var_declaration contains var_spec children
  for (let i = 0; i < node.childCount; i++) {
    const spec = node.child(i);
    if (!spec || spec.type !== 'var_spec') continue;

    // var_spec has name(s) and optionally a type and value
    for (let j = 0; j < spec.childCount; j++) {
      const nameNode = spec.child(j);
      if (!nameNode || nameNode.type !== 'identifier') continue;
      const varName = getNodeText(nameNode);
      if (varName === '_') continue;

      const def: DFGDef = {
        id: defs.length + 1,
        variable: varName,
        kind: 'local',
        line: spec.startPosition.row + 1,
      };
      defs.push(def);
      currentScope(scopeStack).set(varName, def.id);
    }
  }
}

/**
 * Extract definitions from the left side of := or = in Go.
 */
function extractGoLhsDefs(
  left: Node,
  defs: DFGDef[],
  scopeStack: Map<string, number>[],
  line: number
): void {
  if (left.type === 'identifier') {
    const varName = getNodeText(left);
    if (varName === '_') return;
    const def: DFGDef = {
      id: defs.length + 1,
      variable: varName,
      kind: 'local',
      line,
    };
    defs.push(def);
    currentScope(scopeStack).set(varName, def.id);
  } else if (left.type === 'expression_list') {
    // Multiple return: x, err := ...
    for (let i = 0; i < left.childCount; i++) {
      const item = left.child(i);
      if (item && item.type === 'identifier') {
        const varName = getNodeText(item);
        if (varName === '_') continue;
        const def: DFGDef = {
          id: defs.length + 1,
          variable: varName,
          kind: 'local',
          line,
        };
        defs.push(def);
        currentScope(scopeStack).set(varName, def.id);
      }
    }
  }
}

/**
 * Extract variable uses from a Go expression.
 */
function extractGoUses(
  node: Node,
  uses: DFGUse[],
  scopeStack: Map<string, number>[]
): void {
  walkTree(node, (child) => {
    if (child.type === 'identifier') {
      const varName = getNodeText(child);
      if (varName === '_' || GO_KEYWORDS.has(varName)) return;
      // Skip if this is a function name in a call (selector field)
      const parent = child.parent;
      if (parent?.type === 'selector_expression' && parent.childForFieldName('field') === child) {
        return; // This is the method name, not a variable use
      }
      // Skip type names in declarations
      if (parent?.type === 'parameter_declaration' && parent.childForFieldName('type') === child) {
        return;
      }
      // Skip type identifier nodes (tree-sitter uses type_identifier for type references)
      if (parent?.type === 'type_identifier') {
        return;
      }

      const defId = findReachingDef(varName, scopeStack);
      uses.push({
        id: uses.length + 1,
        variable: varName,
        line: child.startPosition.row + 1,
        def_id: defId,
      });
    }
  });
}

/**
 * Find a child node by type in Go AST.
 */
function findChildByTypeGo(node: Node, type: string): Node | null {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child?.type === type) return child;
  }
  return null;
}
