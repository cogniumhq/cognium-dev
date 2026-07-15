/**
 * CFG (Control Flow Graph) builder
 */

import type { Node, Tree } from 'web-tree-sitter';
import type { CFG, CFGBlock, CFGEdge, SupportedLanguage } from '../../types/index.js';
import { findNodes, getNodesFromCache, type NodeCache } from '../parser.js';

/**
 * Detect language from tree structure.
 */
function detectLanguage(tree: Tree): 'javascript' | 'java' {
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

  let jsScore = 0;
  let javaScore = 0;

  for (let i = 0; i < Math.min(root.childCount, 20); i++) {
    const child = root.child(i);
    if (!child) continue;

    if (jsNodeTypes.has(child.type)) jsScore++;
    if (javaNodeTypes.has(child.type)) javaScore++;
  }

  return jsScore > javaScore ? 'javascript' : 'java';
}

/**
 * Build CFG for all methods in the tree.
 *
 * `cache` (added in 3.172.0, cognium-dev#254 T2-A): when provided, top-level
 * `findNodes` walks for function/method containers are replaced with O(1)
 * cache lookups populated by `collectAllNodes` at analyzer entry. Java's
 * `method_declaration`/`import_declaration` and JS's `function_declaration`/
 * `arrow_function`/`method_definition` are already in the language-cache set;
 * `constructor_declaration`, `function`, `function_expression` are added by
 * this ship. Falls back to `findNodes` when cache is absent (test / library
 * callers that build a Tree directly).
 */
export function buildCFG(tree: Tree, language?: SupportedLanguage, cache?: NodeCache): CFG {
  const effectiveLanguage = language ?? detectLanguage(tree);
  const isJavaScript = effectiveLanguage === 'javascript' || effectiveLanguage === 'typescript' || effectiveLanguage === 'tsx';

  const allBlocks: CFGBlock[] = [];
  const allEdges: CFGEdge[] = [];
  let blockIdCounter = 0;

  if (effectiveLanguage === 'bash') {
    return buildBashCFG(tree, blockIdCounter);
  }

  if (effectiveLanguage === 'go') {
    return buildGoCFG(tree, blockIdCounter);
  }

  if (isJavaScript) {
    // Find all JavaScript function bodies
    const functions = [
      ...getNodesFromCache(tree.rootNode, 'function_declaration', cache),
      ...getNodesFromCache(tree.rootNode, 'arrow_function', cache),
      ...getNodesFromCache(tree.rootNode, 'method_definition', cache),
      ...getNodesFromCache(tree.rootNode, 'function', cache),
      ...getNodesFromCache(tree.rootNode, 'function_expression', cache),
    ];

    for (const func of functions) {
      const body = func.childForFieldName('body');
      if (!body) continue;

      // Arrow functions can have expression bodies
      if (body.type === 'statement_block') {
        const { blocks, edges, nextId } = buildMethodCFG(body, blockIdCounter, true);
        allBlocks.push(...blocks);
        allEdges.push(...edges);
        blockIdCounter = nextId;
      } else {
        // Expression body (arrow function with implicit return)
        const block: CFGBlock = {
          id: blockIdCounter++,
          type: 'normal',
          start_line: body.startPosition.row + 1,
          end_line: body.endPosition.row + 1,
        };
        allBlocks.push(block);
      }
    }
  } else {
    // Find all Java method bodies
    const methods = [
      ...getNodesFromCache(tree.rootNode, 'method_declaration', cache),
      ...getNodesFromCache(tree.rootNode, 'constructor_declaration', cache),
    ];

    for (const method of methods) {
      const body = method.childForFieldName('body');
      if (!body) continue;

      const { blocks, edges, nextId } = buildMethodCFG(body, blockIdCounter, false);
      allBlocks.push(...blocks);
      allEdges.push(...edges);
      blockIdCounter = nextId;
    }
  }

  return { blocks: allBlocks, edges: allEdges };
}

interface CFGBuildResult {
  blocks: CFGBlock[];
  edges: CFGEdge[];
  entryId: number;
  exitIds: number[];
  nextId: number;
}

/**
 * Build CFG for a method body.
 */
function buildMethodCFG(
  body: Node,
  startId: number,
  isJavaScript: boolean
): { blocks: CFGBlock[]; edges: CFGEdge[]; nextId: number } {
  const blocks: CFGBlock[] = [];
  const edges: CFGEdge[] = [];
  let currentId = startId;

  // Create entry block
  const entryBlock: CFGBlock = {
    id: currentId++,
    type: 'entry',
    start_line: body.startPosition.row + 1,
    end_line: body.startPosition.row + 1,
  };
  blocks.push(entryBlock);

  // Process statements in the body
  const result = processStatements(body, currentId, blocks, edges, isJavaScript);
  currentId = result.nextId;

  // Connect entry to first statement
  if (result.entryId !== -1) {
    edges.push({
      from: entryBlock.id,
      to: result.entryId,
      type: 'sequential',
    });
  }

  // Create exit block
  const exitBlock: CFGBlock = {
    id: currentId++,
    type: 'exit',
    start_line: body.endPosition.row + 1,
    end_line: body.endPosition.row + 1,
  };
  blocks.push(exitBlock);

  // Connect last statements to exit
  for (const exitId of result.exitIds) {
    edges.push({
      from: exitId,
      to: exitBlock.id,
      type: 'sequential',
    });
  }

  // If body is empty, connect entry directly to exit
  if (result.entryId === -1) {
    edges.push({
      from: entryBlock.id,
      to: exitBlock.id,
      type: 'sequential',
    });
  }

  return { blocks, edges, nextId: currentId };
}

interface StatementsResult {
  entryId: number;
  exitIds: number[];
  nextId: number;
}

/**
 * Process statements in a block.
 */
function processStatements(
  container: Node,
  startId: number,
  blocks: CFGBlock[],
  edges: CFGEdge[],
  isJavaScript: boolean
): StatementsResult {
  let currentId = startId;
  let firstBlockId = -1;
  let lastExitIds: number[] = [];

  for (let i = 0; i < container.childCount; i++) {
    const stmt = container.child(i);
    if (!stmt) continue;

    // Skip non-statement nodes
    if (!isStatement(stmt, isJavaScript)) continue;

    const result = processStatement(stmt, currentId, blocks, edges, isJavaScript);
    currentId = result.nextId;

    if (firstBlockId === -1) {
      firstBlockId = result.entryId;
    } else {
      // Connect previous exits to this entry
      for (const exitId of lastExitIds) {
        edges.push({
          from: exitId,
          to: result.entryId,
          type: 'sequential',
        });
      }
    }

    lastExitIds = result.exitIds;
  }

  return {
    entryId: firstBlockId,
    exitIds: lastExitIds,
    nextId: currentId,
  };
}

/**
 * Process a single statement.
 */
function processStatement(
  stmt: Node,
  startId: number,
  blocks: CFGBlock[],
  edges: CFGEdge[],
  isJavaScript: boolean
): StatementsResult {
  switch (stmt.type) {
    case 'if_statement':
      return processIfStatement(stmt, startId, blocks, edges, isJavaScript);

    case 'for_statement':
    case 'enhanced_for_statement':
    case 'for_in_statement':
    case 'for_of_statement':
      return processForStatement(stmt, startId, blocks, edges, isJavaScript);

    case 'while_statement':
      return processWhileStatement(stmt, startId, blocks, edges, isJavaScript);

    case 'do_statement':
      return processDoWhileStatement(stmt, startId, blocks, edges, isJavaScript);

    case 'try_statement':
      return processTryStatement(stmt, startId, blocks, edges, isJavaScript);

    case 'switch_expression':
    case 'switch_statement':
      return processSwitchStatement(stmt, startId, blocks, edges, isJavaScript);

    case 'block':
    case 'statement_block':
      return processStatements(stmt, startId, blocks, edges, isJavaScript);

    default:
      return processSimpleStatement(stmt, startId, blocks);
  }
}

/**
 * Process a simple (non-control-flow) statement.
 */
function processSimpleStatement(
  stmt: Node,
  startId: number,
  blocks: CFGBlock[]
): StatementsResult {
  const block: CFGBlock = {
    id: startId,
    type: 'normal',
    start_line: stmt.startPosition.row + 1,
    end_line: stmt.endPosition.row + 1,
  };
  blocks.push(block);

  return {
    entryId: startId,
    exitIds: [startId],
    nextId: startId + 1,
  };
}

/**
 * Process an if statement.
 */
function processIfStatement(
  stmt: Node,
  startId: number,
  blocks: CFGBlock[],
  edges: CFGEdge[],
  isJavaScript: boolean
): StatementsResult {
  let currentId = startId;

  // Create conditional block
  const condBlock: CFGBlock = {
    id: currentId++,
    type: 'conditional',
    start_line: stmt.startPosition.row + 1,
    end_line: stmt.startPosition.row + 1,
  };
  blocks.push(condBlock);

  const exitIds: number[] = [];

  // Process consequence (then branch)
  const consequence = stmt.childForFieldName('consequence');
  if (consequence) {
    const thenResult = processStatement(consequence, currentId, blocks, edges, isJavaScript);
    currentId = thenResult.nextId;

    edges.push({
      from: condBlock.id,
      to: thenResult.entryId,
      type: 'true',
    });

    exitIds.push(...thenResult.exitIds);
  }

  // Process alternative (else branch)
  const alternative = stmt.childForFieldName('alternative');
  if (alternative) {
    const elseResult = processStatement(alternative, currentId, blocks, edges, isJavaScript);
    currentId = elseResult.nextId;

    edges.push({
      from: condBlock.id,
      to: elseResult.entryId,
      type: 'false',
    });

    exitIds.push(...elseResult.exitIds);
  } else {
    // No else branch - condition block can exit directly
    exitIds.push(condBlock.id);
  }

  return {
    entryId: condBlock.id,
    exitIds,
    nextId: currentId,
  };
}

/**
 * Process a for statement.
 */
function processForStatement(
  stmt: Node,
  startId: number,
  blocks: CFGBlock[],
  edges: CFGEdge[],
  isJavaScript: boolean
): StatementsResult {
  let currentId = startId;

  // Create loop header block
  const loopBlock: CFGBlock = {
    id: currentId++,
    type: 'loop',
    start_line: stmt.startPosition.row + 1,
    end_line: stmt.startPosition.row + 1,
  };
  blocks.push(loopBlock);

  // Process body
  const body = stmt.childForFieldName('body');
  if (body) {
    const bodyResult = processStatement(body, currentId, blocks, edges, isJavaScript);
    currentId = bodyResult.nextId;

    // Connect loop to body (true branch)
    edges.push({
      from: loopBlock.id,
      to: bodyResult.entryId,
      type: 'true',
    });

    // Connect body exits back to loop (back edge)
    for (const exitId of bodyResult.exitIds) {
      edges.push({
        from: exitId,
        to: loopBlock.id,
        type: 'back',
      });
    }
  }

  return {
    entryId: loopBlock.id,
    exitIds: [loopBlock.id], // Exit when condition is false
    nextId: currentId,
  };
}

/**
 * Process a while statement.
 */
function processWhileStatement(
  stmt: Node,
  startId: number,
  blocks: CFGBlock[],
  edges: CFGEdge[],
  isJavaScript: boolean
): StatementsResult {
  // Similar to for statement
  return processForStatement(stmt, startId, blocks, edges, isJavaScript);
}

/**
 * Process a do-while statement.
 */
function processDoWhileStatement(
  stmt: Node,
  startId: number,
  blocks: CFGBlock[],
  edges: CFGEdge[],
  isJavaScript: boolean
): StatementsResult {
  let currentId = startId;

  // Process body first
  const body = stmt.childForFieldName('body');
  let bodyEntryId = currentId;
  let bodyExitIds: number[] = [];

  if (body) {
    const bodyResult = processStatement(body, currentId, blocks, edges, isJavaScript);
    currentId = bodyResult.nextId;
    bodyEntryId = bodyResult.entryId;
    bodyExitIds = bodyResult.exitIds;
  }

  // Create condition block
  const condBlock: CFGBlock = {
    id: currentId++,
    type: 'loop',
    start_line: stmt.endPosition.row + 1,
    end_line: stmt.endPosition.row + 1,
  };
  blocks.push(condBlock);

  // Connect body to condition
  for (const exitId of bodyExitIds) {
    edges.push({
      from: exitId,
      to: condBlock.id,
      type: 'sequential',
    });
  }

  // Back edge from condition to body
  edges.push({
    from: condBlock.id,
    to: bodyEntryId,
    type: 'back',
  });

  return {
    entryId: bodyEntryId,
    exitIds: [condBlock.id],
    nextId: currentId,
  };
}

/**
 * Process a try statement.
 */
function processTryStatement(
  stmt: Node,
  startId: number,
  blocks: CFGBlock[],
  edges: CFGEdge[],
  isJavaScript: boolean
): StatementsResult {
  let currentId = startId;
  const exitIds: number[] = [];

  // Process try body
  const body = stmt.childForFieldName('body');
  let tryEntryId = -1;

  if (body) {
    const bodyResult = processStatements(body, currentId, blocks, edges, isJavaScript);
    currentId = bodyResult.nextId;
    tryEntryId = bodyResult.entryId;
    exitIds.push(...bodyResult.exitIds);
  }

  // Process catch clauses
  for (let i = 0; i < stmt.childCount; i++) {
    const child = stmt.child(i);
    if (child?.type === 'catch_clause') {
      const catchBody = child.childForFieldName('body');
      if (catchBody) {
        const catchResult = processStatements(catchBody, currentId, blocks, edges, isJavaScript);
        currentId = catchResult.nextId;

        // Add exception edges from try blocks to catch
        if (tryEntryId !== -1) {
          edges.push({
            from: tryEntryId,
            to: catchResult.entryId,
            type: 'exception',
          });
        }

        exitIds.push(...catchResult.exitIds);
      }
    }
  }

  // Process finally clause (Java: finally, JS: finalizer)
  const finallyClause = stmt.childForFieldName('finally') ?? stmt.childForFieldName('finalizer');
  if (finallyClause) {
    const finallyResult = processStatements(finallyClause, currentId, blocks, edges, isJavaScript);
    currentId = finallyResult.nextId;

    // Connect all exits to finally
    for (const exitId of exitIds) {
      edges.push({
        from: exitId,
        to: finallyResult.entryId,
        type: 'sequential',
      });
    }

    return {
      entryId: tryEntryId !== -1 ? tryEntryId : finallyResult.entryId,
      exitIds: finallyResult.exitIds,
      nextId: currentId,
    };
  }

  return {
    entryId: tryEntryId,
    exitIds,
    nextId: currentId,
  };
}

/**
 * Process a switch statement.
 */
function processSwitchStatement(
  stmt: Node,
  startId: number,
  blocks: CFGBlock[],
  edges: CFGEdge[],
  isJavaScript: boolean
): StatementsResult {
  let currentId = startId;

  // Create conditional block for switch expression
  const switchBlock: CFGBlock = {
    id: currentId++,
    type: 'conditional',
    start_line: stmt.startPosition.row + 1,
    end_line: stmt.startPosition.row + 1,
  };
  blocks.push(switchBlock);

  const exitIds: number[] = [];

  // Find switch body
  const body = stmt.childForFieldName('body');
  if (body) {
    // Process each case (Java: switch_block_statement_group, JS: switch_case, switch_default)
    const caseTypes = isJavaScript
      ? ['switch_case', 'switch_default']
      : ['switch_block_statement_group', 'switch_rule'];

    for (let i = 0; i < body.childCount; i++) {
      const child = body.child(i);
      if (child && caseTypes.includes(child.type)) {
        const caseResult = processStatements(child, currentId, blocks, edges, isJavaScript);
        currentId = caseResult.nextId;

        if (caseResult.entryId !== -1) {
          edges.push({
            from: switchBlock.id,
            to: caseResult.entryId,
            type: 'sequential',
          });
          exitIds.push(...caseResult.exitIds);
        }
      }
    }
  }

  // If no cases, switch exits directly
  if (exitIds.length === 0) {
    exitIds.push(switchBlock.id);
  }

  return {
    entryId: switchBlock.id,
    exitIds,
    nextId: currentId,
  };
}

/**
 * Build CFG for Bash/Shell code.
 *
 * Processes function_definition bodies and the top-level program body
 * as a synthetic "main" function.
 */
function buildBashCFG(tree: Tree, startId: number): CFG {
  const allBlocks: CFGBlock[] = [];
  const allEdges: CFGEdge[] = [];
  let blockIdCounter = startId;

  // Process function_definition nodes
  const functions = findNodes(tree.rootNode, 'function_definition');
  for (const func of functions) {
    const body = func.childForFieldName('body');
    if (!body) continue;
    const { blocks, edges, nextId } = buildMethodCFG(body, blockIdCounter, false);
    allBlocks.push(...blocks);
    allEdges.push(...edges);
    blockIdCounter = nextId;
  }

  // Process top-level program body as a synthetic "main"
  // Filter out function_definition nodes to avoid duplicating them
  const topLevelStatements: Node[] = [];
  for (let i = 0; i < tree.rootNode.childCount; i++) {
    const child = tree.rootNode.child(i);
    if (child && child.type !== 'function_definition' && isBashStatement(child)) {
      topLevelStatements.push(child);
    }
  }

  if (topLevelStatements.length > 0) {
    // Create entry block
    const entryBlock: CFGBlock = {
      id: blockIdCounter++,
      type: 'entry',
      start_line: topLevelStatements[0].startPosition.row + 1,
      end_line: topLevelStatements[0].startPosition.row + 1,
    };
    allBlocks.push(entryBlock);

    let lastExitIds: number[] = [];
    let firstBlockId = -1;

    for (const stmt of topLevelStatements) {
      const result = processStatement(stmt, blockIdCounter, allBlocks, allEdges, false);
      blockIdCounter = result.nextId;

      if (firstBlockId === -1) {
        firstBlockId = result.entryId;
      } else {
        for (const exitId of lastExitIds) {
          allEdges.push({ from: exitId, to: result.entryId, type: 'sequential' });
        }
      }
      lastExitIds = result.exitIds;
    }

    // Connect entry to first statement
    if (firstBlockId !== -1) {
      allEdges.push({ from: entryBlock.id, to: firstBlockId, type: 'sequential' });
    }

    // Create exit block
    const exitBlock: CFGBlock = {
      id: blockIdCounter++,
      type: 'exit',
      start_line: topLevelStatements[topLevelStatements.length - 1].endPosition.row + 1,
      end_line: topLevelStatements[topLevelStatements.length - 1].endPosition.row + 1,
    };
    allBlocks.push(exitBlock);

    for (const exitId of lastExitIds) {
      allEdges.push({ from: exitId, to: exitBlock.id, type: 'sequential' });
    }
  }

  return { blocks: allBlocks, edges: allEdges };
}

/**
 * Check if a Bash node is a statement-like construct.
 */
function isBashStatement(node: Node): boolean {
  const bashStatementTypes = new Set([
    'command',
    'variable_assignment',
    'if_statement',
    'for_statement',
    'while_statement',
    'case_statement',
    'pipeline',
    'list',
    'redirected_statement',
    'compound_statement',
    'subshell',
    'declaration_command',
  ]);
  return bashStatementTypes.has(node.type);
}

/**
 * Check if a node is a statement.
 */
function isStatement(node: Node, isJavaScript: boolean): boolean {
  const javaStatementTypes = new Set([
    'local_variable_declaration',
    'expression_statement',
    'if_statement',
    'for_statement',
    'enhanced_for_statement',
    'while_statement',
    'do_statement',
    'try_statement',
    'switch_statement',
    'switch_expression',
    'return_statement',
    'throw_statement',
    'break_statement',
    'continue_statement',
    'assert_statement',
    'synchronized_statement',
    'block',
  ]);

  const jsStatementTypes = new Set([
    'lexical_declaration',
    'variable_declaration',
    'expression_statement',
    'if_statement',
    'for_statement',
    'for_in_statement',
    'for_of_statement',
    'while_statement',
    'do_statement',
    'try_statement',
    'switch_statement',
    'return_statement',
    'throw_statement',
    'break_statement',
    'continue_statement',
    'statement_block',
    'with_statement',
    'labeled_statement',
    'debugger_statement',
    'empty_statement',
    'export_statement',
    'import_statement',
  ]);

  return isJavaScript ? jsStatementTypes.has(node.type) : javaStatementTypes.has(node.type);
}

// =============================================================================
// Go CFG Builder
// =============================================================================

/**
 * Build CFG for Go code.
 *
 * Processes function_declaration and method_declaration bodies.
 * Top-level source_file statements are treated as a synthetic main.
 */
function buildGoCFG(tree: Tree, blockIdCounter: number): CFG {
  const allBlocks: CFGBlock[] = [];
  const allEdges: CFGEdge[] = [];

  const functions = [
    ...findNodes(tree.rootNode, 'function_declaration'),
    ...findNodes(tree.rootNode, 'method_declaration'),
  ];

  for (const func of functions) {
    const body = func.childForFieldName('body');
    if (!body || body.type !== 'block') continue;

    const { blocks, edges, nextId } = buildMethodCFG(body, blockIdCounter, false);
    allBlocks.push(...blocks);
    allEdges.push(...edges);
    blockIdCounter = nextId;
  }

  // Process top-level var/const declarations as a synthetic block
  const hasTopLevelDecls = tree.rootNode.children.some(c =>
    c !== null && isGoStatement(c)
  );

  if (hasTopLevelDecls) {
    // Create a single block for top-level declarations
    const block: CFGBlock = {
      id: blockIdCounter++,
      type: 'normal',
      start_line: 1,
      end_line: tree.rootNode.endPosition.row + 1,
    };
    allBlocks.push(block);
  }

  return { blocks: allBlocks, edges: allEdges };
}

/**
 * Check if a Go node is a statement-like construct.
 */
function isGoStatement(node: Node): boolean {
  const goStatementTypes = new Set([
    'short_var_declaration',
    'var_declaration',
    'assignment_statement',
    'expression_statement',
    'if_statement',
    'for_statement',
    'switch_statement',
    'type_switch_statement',
    'select_statement',
    'return_statement',
    'go_statement',
    'defer_statement',
    'send_statement',
    'inc_statement',
    'dec_statement',
    'block',
    'type_declaration',
    'const_declaration',
  ]);
  return goStatementTypes.has(node.type);
}
