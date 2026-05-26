/**
 * Main Constant Propagator class.
 *
 * Tracks constant values through variable assignments and evaluates expressions
 * to detect dead code and reduce false positives in taint analysis.
 */

import type { Node, Tree } from 'web-tree-sitter';
import type { ConstantValue, ConstantPropagatorResult, TaintedParameter, FieldTaintInfo } from './types.js';
import { isKnown, createUnknown, getNodeText, getNodeLine } from './ast-utils.js';
import { ExpressionEvaluator } from './evaluator.js';
import { TAINT_PATTERN_REGEX, SANITIZER_METHODS, PROPAGATOR_METHODS, ANTI_SANITIZER_METHODS } from './patterns.js';

/**
 * Constant Propagator for taint analysis.
 *
 * Key features:
 * - Tracks variable → constant value mappings
 * - Evaluates arithmetic, comparison, and string expressions
 * - Detects dead/unreachable code via if/switch/ternary evaluation
 * - Integrates with taint analysis to skip false positives
 */
export class ConstantPropagator {
  private symbols: Map<string, ConstantValue> = new Map();
  private tainted: Set<string> = new Set();
  private unreachableLines: Set<number> = new Set();
  private taintedCollections: Map<string, Set<string>> = new Map();
  // Track variables explicitly assigned from sanitizer calls
  private sanitizedVars: Set<string> = new Set();
  private source: string = '';
  private evaluator!: ExpressionEvaluator;

  // Track the expression node that defined each variable (for refinement)
  private definitionNodes: Map<string, Node> = new Map();
  // Track if we're inside a conditional branch (for conservative taint handling)
  private inConditionalBranch: boolean = false;
  // Track which methods always return constants (inter-procedural analysis)
  private methodReturnsConstant: Set<string> = new Set();
  // Track which methods always return sanitized values (inter-procedural analysis)
  private methodReturnsSanitized: Set<string> = new Set();
  // Track which methods return a specific parameter (index) - for taint propagation
  private methodReturnsParameter: Map<string, number> = new Map();
  // Track which methods return safe (non-tainted) values even with tainted input
  private methodReturnsSafeValue: Set<string> = new Set();
  // Additional taint patterns (for test harnesses to inject custom patterns)
  private additionalTaintPatterns: string[] = [];
  // Track list elements by index for precise list taint tracking
  private listElements: Map<string, (string | null)[]> = new Map();
  // Track loop variables (should not be overwritten with constant values)
  private loopVariables: Set<string> = new Set();
  // Track tainted array elements: array name → set of tainted indices (or '*' for whole array)
  private taintedArrayElements: Map<string, Set<string>> = new Map();
  // Track current method name for scoping local variables
  private currentMethod: string | null = null;
  // Track conditional taints: which variables were tainted under which conditions
  // Maps condition expression string → set of variables tainted under that condition
  private conditionalTaints: Map<string, Set<string>> = new Map();
  // Stack of condition expressions we're currently inside (for nested ifs)
  private conditionStack: string[] = [];
  // Track which lines are under which conditions
  private lineConditions: Map<number, string> = new Map();
  // Track lines that are inside synchronized blocks (where field strong updates are safe)
  private synchronizedLines: Set<number> = new Set();
  // Track if we're currently inside a synchronized block
  private inSynchronizedBlock: boolean = false;
  // Track iterator sources: iterator variable name → collection name it was created from
  private iteratorSources: Map<string, string> = new Map();
  // Track class field names (declared at class level, not local variables)
  private classFields: Set<string> = new Set();
  // Track tainted method parameters for inter-procedural analysis
  private taintedParametersList: TaintedParameter[] = [];
  // Track instance fields assigned from tainted constructor parameters
  private instanceFieldTaint: Map<string, FieldTaintInfo> = new Map();
  // Track current class name for field taint tracking
  private currentClassName: string | null = null;
  // Track if we're currently inside a constructor (vs regular method)
  private inConstructor: boolean = false;
  // Map constructor parameter names to their positions (0-indexed)
  private constructorParamPositions: Map<string, number> = new Map();

  /**
   * Analyze source code and build constant propagation state.
   */
  analyze(tree: Tree, sourceCode: string, additionalTaintPatterns: string[] = [], sanitizerMethods: string[] = [], taintedParameters: TaintedParameter[] = []): ConstantPropagatorResult {
    this.source = sourceCode;
    this.additionalTaintPatterns = additionalTaintPatterns;
    this.taintedParametersList = taintedParameters;
    this.symbols.clear();
    this.tainted.clear();
    this.unreachableLines.clear();
    this.taintedCollections.clear();
    this.definitionNodes.clear();
    this.inConditionalBranch = false;
    this.methodReturnsConstant.clear();
    this.methodReturnsSanitized.clear();
    this.methodReturnsParameter.clear();
    this.methodReturnsSafeValue.clear();
    this.listElements.clear();
    this.loopVariables.clear();
    this.taintedArrayElements.clear();
    this.sanitizedVars.clear();
    this.currentMethod = null;
    this.conditionalTaints.clear();
    this.conditionStack = [];
    this.lineConditions.clear();
    this.synchronizedLines.clear();
    this.inSynchronizedBlock = false;
    this.iteratorSources.clear();
    this.classFields.clear();
    this.instanceFieldTaint.clear();
    this.currentClassName = null;
    this.inConstructor = false;
    this.constructorParamPositions.clear();

    // Pre-pass: identify class fields
    this.collectClassFields(tree.rootNode);

    // Pre-populate methodReturnsSanitized with methods marked with @sanitizer annotation
    for (const methodName of sanitizerMethods) {
      this.methodReturnsSanitized.add(methodName);
    }

    // Create evaluator with symbol lookup that handles scoped names
    this.evaluator = new ExpressionEvaluator(
      this.source,
      (name: string) => this.lookupSymbol(name)
    );

    // Pre-pass: identify methods that always return constants or sanitized values
    this.analyzeMethodReturns(tree.rootNode);

    // First pass: collect symbols, taint, and unreachable lines
    this.visit(tree.rootNode);

    // Second pass: refine taint for variables derived from constants
    this.refineTaintFromConstants();

    // Build result with both scoped and unscoped names for backward compatibility
    // Unscoped names are needed for legacy code and tests
    const resultTainted = new Set(this.tainted);
    const resultSanitized = new Set(this.sanitizedVars);
    const resultSymbols = new Map(this.symbols);

    // Add unscoped versions of scoped names for backward compatibility
    for (const name of this.tainted) {
      if (name.includes(':')) {
        const unscoped = name.substring(name.indexOf(':') + 1);
        resultTainted.add(unscoped);
      }
    }
    for (const name of this.sanitizedVars) {
      if (name.includes(':')) {
        const unscoped = name.substring(name.indexOf(':') + 1);
        resultSanitized.add(unscoped);
      }
    }
    // Add unscoped symbols for backward compatibility with tests
    // The scoped versions take priority in filterCleanVariableSinks
    for (const [name, value] of this.symbols) {
      if (name.includes(':')) {
        const unscoped = name.substring(name.indexOf(':') + 1);
        // Only add if not already present (scoped version wins on conflict)
        if (!resultSymbols.has(unscoped)) {
          resultSymbols.set(unscoped, value);
        }
      }
    }

    return {
      symbols: resultSymbols,
      tainted: resultTainted,
      unreachableLines: new Set(this.unreachableLines),
      taintedCollections: new Map(this.taintedCollections),
      taintedArrayElements: new Map(this.taintedArrayElements),
      sanitizedVars: resultSanitized,
      conditionalTaints: new Map(this.conditionalTaints),
      lineConditions: new Map(this.lineConditions),
      synchronizedLines: new Set(this.synchronizedLines),
      instanceFieldTaint: new Map(this.instanceFieldTaint),
    };
  }

  /**
   * Evaluate an expression to determine its constant value.
   */
  evaluateExpression(node: Node): ConstantValue {
    return this.evaluator.evaluate(node);
  }

  /**
   * Check if a variable has a known constant value.
   */
  getValue(varName: string): ConstantValue | undefined {
    return this.symbols.get(varName);
  }

  /**
   * Check if a variable is tainted.
   */
  isTainted(varName: string): boolean {
    return this.tainted.has(varName);
  }

  /**
   * Check if a line is reachable (not dead code).
   */
  isLineReachable(line: number): boolean {
    return !this.unreachableLines.has(line);
  }

  // ===========================================================================
  // Inter-procedural Analysis
  // ===========================================================================

  /**
   * Pre-pass: Analyze all methods to detect those that always return constants or sanitized values.
   */
  private analyzeMethodReturns(root: Node): void {
    const methods = this.findAllMethods(root);

    for (const method of methods) {
      const methodName = this.getMethodName(method);
      if (!methodName) continue;

      const body = method.childForFieldName('body');
      if (!body) continue;

      // Find all return statements
      const returns: Node[] = [];
      const findReturns = (n: Node) => {
        if (n.type === 'return_statement') {
          returns.push(n);
        }
        for (const child of n.children) {
          findReturns(child);
        }
      };
      findReturns(body);

      if (returns.length === 0) continue;

      // Create temp propagator for analysis
      const tempPropagator = new ConstantPropagator();
      tempPropagator.source = this.source;
      tempPropagator.additionalTaintPatterns = this.additionalTaintPatterns;

      // Mark parameters as tainted for parameter-return tracking
      const params = this.getMethodParameters(method);
      for (const paramName of params) {
        tempPropagator.tainted.add(paramName);
      }

      // Initialize evaluator for temp propagator
      tempPropagator.evaluator = new ExpressionEvaluator(
        tempPropagator.source,
        (name: string) => tempPropagator.symbols.get(name)
      );

      tempPropagator.visit(body);

      // Analyze returns
      let allReturnsConstant = true;
      let allReturnsSanitized = true;
      let allReturnsSafe = true; // Track if all returns are non-tainted
      let returnedParamIndex = -1;
      let hasReachableReturn = false;

      for (const ret of returns) {
        const retLine = getNodeLine(ret);

        if (tempPropagator.unreachableLines.has(retLine)) {
          continue;
        }

        hasReachableReturn = true;

        const valueNode = ret.children.find(c =>
          c.type !== 'return' && c.type !== ';' && c.type !== 'comment'
        );

        if (!valueNode) {
          allReturnsConstant = false;
          allReturnsSanitized = false;
          allReturnsSafe = false; // void return or unknown - not safe
          continue;
        }

        const value = tempPropagator.evaluateExpression(valueNode);
        if (!isKnown(value)) {
          allReturnsConstant = false;
        }

        if (!this.isSanitizerCall(valueNode, body)) {
          allReturnsSanitized = false;
        }

        // Check if return value is tainted
        if (tempPropagator.isTaintedExpression(valueNode)) {
          allReturnsSafe = false;
        }

        if (params.length > 0) {
          const returnExpr = getNodeText(valueNode, this.source);
          const directParamIdx = params.indexOf(returnExpr);

          if (directParamIdx >= 0) {
            if (returnedParamIndex >= 0 && returnedParamIndex !== directParamIdx) {
              returnedParamIndex = -2;
            } else if (returnedParamIndex !== -2) {
              returnedParamIndex = directParamIdx;
            }
          } else if (valueNode.type === 'identifier' && tempPropagator.tainted.has(returnExpr)) {
            const derivedFrom = this.findParameterSource(body, returnExpr, params);
            if (derivedFrom >= 0) {
              if (returnedParamIndex >= 0 && returnedParamIndex !== derivedFrom) {
                returnedParamIndex = -2;
              } else if (returnedParamIndex !== -2) {
                returnedParamIndex = derivedFrom;
              }
            }
          }
        }
      }

      if (hasReachableReturn) {
        if (allReturnsConstant) {
          this.methodReturnsConstant.add(methodName);
        }
        if (allReturnsSanitized) {
          this.methodReturnsSanitized.add(methodName);
        }
        if (returnedParamIndex >= 0) {
          this.methodReturnsParameter.set(methodName, returnedParamIndex);
        }
        // Track methods that return safe values even with tainted input
        // Only add if it's not already covered by constant/sanitized returns
        if (allReturnsSafe && !allReturnsConstant && !allReturnsSanitized) {
          this.methodReturnsSafeValue.add(methodName);
        }
      }
    }
  }

  private findParameterSource(body: Node, varName: string, params: string[]): number {
    const visited = new Set<string>();
    const queue = [varName];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      const paramIdx = params.indexOf(current);
      if (paramIdx >= 0) {
        return paramIdx;
      }

      const findAssignment = (n: Node): string | null => {
        if (n.type === 'local_variable_declaration') {
          const declarator = n.children.find(c => c.type === 'variable_declarator');
          if (declarator) {
            const nameNode = declarator.childForFieldName('name');
            const valueNode = declarator.childForFieldName('value');
            if (nameNode && valueNode) {
              const name = getNodeText(nameNode, this.source);
              if (name === current) {
                return this.extractSourceVariable(valueNode, params);
              }
            }
          }
        }
        if (n.type === 'assignment_expression') {
          const left = n.childForFieldName('left');
          const right = n.childForFieldName('right');
          if (left && right) {
            const name = getNodeText(left, this.source);
            if (name === current) {
              return this.extractSourceVariable(right, params);
            }
          }
        }
        for (const child of n.children) {
          const result = findAssignment(child);
          if (result) return result;
        }
        return null;
      };

      const source = findAssignment(body);
      if (source) {
        queue.push(source);
      }
    }

    return -1;
  }

  private extractSourceVariable(node: Node, params: string[]): string | null {
    if (node.type === 'identifier') {
      return getNodeText(node, this.source);
    }

    if (node.type === 'method_invocation' || node.type === 'object_creation_expression') {
      const argsNode = node.childForFieldName('arguments');
      if (argsNode) {
        for (const arg of argsNode.children) {
          if (arg.type === 'identifier') {
            const argName = getNodeText(arg, this.source);
            if (params.includes(argName)) {
              return argName;
            }
          }
        }
      }
      const obj = node.childForFieldName('object');
      if (obj && obj.type === 'identifier') {
        const objName = getNodeText(obj, this.source);
        if (params.includes(objName)) {
          return objName;
        }
      }
    }

    if (node.type === 'ternary_expression') {
      const consequence = node.childForFieldName('consequence');
      const alternative = node.childForFieldName('alternative');
      if (consequence) {
        const consVar = this.extractSourceVariable(consequence, params);
        if (consVar && params.includes(consVar)) return consVar;
      }
      if (alternative) {
        const altVar = this.extractSourceVariable(alternative, params);
        if (altVar && params.includes(altVar)) return altVar;
      }
    }

    if (node.type === 'binary_expression') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left) {
        const leftVar = this.extractSourceVariable(left, params);
        if (leftVar && params.includes(leftVar)) return leftVar;
      }
      if (right) {
        const rightVar = this.extractSourceVariable(right, params);
        if (rightVar && params.includes(rightVar)) return rightVar;
      }
    }

    return null;
  }

  private getMethodParameters(method: Node): string[] {
    const params: string[] = [];
    const paramsNode = method.childForFieldName('parameters');
    if (!paramsNode) return params;

    for (const child of paramsNode.children) {
      if (child.type === 'formal_parameter' || child.type === 'spread_parameter') {
        const nameNode = child.childForFieldName('name');
        if (nameNode) {
          params.push(getNodeText(nameNode, this.source));
        }
      }
    }
    return params;
  }

  private isSanitizerCall(node: Node, methodBody?: Node): boolean {
    if (node.type === 'method_invocation') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const methodName = getNodeText(nameNode, this.source);
        if (SANITIZER_METHODS.has(methodName)) {
          return true;
        }
      }
    }

    if (node.type === 'identifier' && methodBody) {
      const varName = getNodeText(node, this.source);
      if (this.variableIsAssignedFromSanitizer(varName, methodBody)) {
        return true;
      }
    }

    return false;
  }

  private variableIsAssignedFromSanitizer(varName: string, methodBody: Node): boolean {
    const findAssignments = (n: Node): boolean => {
      if (n.type === 'local_variable_declaration') {
        const declarator = n.children.find(c => c.type === 'variable_declarator');
        if (declarator) {
          const nameNode = declarator.childForFieldName('name');
          const valueNode = declarator.childForFieldName('value');
          if (nameNode && valueNode) {
            const name = getNodeText(nameNode, this.source);
            if (name === varName) {
              return this.isSanitizerCall(valueNode);
            }
          }
        }
      }

      if (n.type === 'assignment_expression') {
        const leftNode = n.childForFieldName('left');
        const rightNode = n.childForFieldName('right');
        if (leftNode && rightNode) {
          const name = getNodeText(leftNode, this.source);
          if (name === varName) {
            return this.isSanitizerCall(rightNode);
          }
        }
      }

      for (const child of n.children) {
        if (findAssignments(child)) {
          return true;
        }
      }

      return false;
    };

    return findAssignments(methodBody);
  }

  /**
   * Collect all class field names (instance/static variables declared at class level).
   * These are variables declared directly in the class body, not inside methods.
   */
  private collectClassFields(root: Node): void {
    const traverse = (n: Node, inClass: boolean, inMethod: boolean) => {
      if (!n) return;

      // Track when we enter a class body
      if (n.type === 'class_body') {
        for (const child of n.children) {
          // Field declarations are direct children of class_body
          if (child.type === 'field_declaration') {
            // Find the variable declarator(s) in this field declaration
            for (const declarator of child.children) {
              if (declarator.type === 'variable_declarator') {
                const nameNode = declarator.childForFieldName('name');
                if (nameNode) {
                  const fieldName = getNodeText(nameNode, this.source);
                  this.classFields.add(fieldName);
                }
              }
            }
          }
          // Recurse into methods without marking them as fields
          if (child.type === 'method_declaration' || child.type === 'constructor_declaration') {
            traverse(child, true, true);
          } else {
            traverse(child, true, false);
          }
        }
        return;
      }

      for (const child of n.children) {
        traverse(child, inClass, inMethod);
      }
    };

    traverse(root, false, false);
  }

  private findAllMethods(node: Node): Node[] {
    const methods: Node[] = [];

    const traverse = (n: Node) => {
      if (!n) return;
      if (n.type === 'method_declaration' || n.type === 'function_declaration') {
        methods.push(n);
      }
      for (const child of n.children) {
        if (child) traverse(child);
      }
    };

    traverse(node);
    return methods;
  }

  private getMethodName(method: Node): string | null {
    const nameNode = method.childForFieldName('name');
    if (nameNode) {
      return getNodeText(nameNode, this.source);
    }
    return null;
  }

  // ===========================================================================
  // Taint Refinement
  // ===========================================================================

  private refineTaintFromConstants(): void {
    let changed = true;
    let iterations = 0;
    const maxIterations = 10;

    while (changed && iterations < maxIterations) {
      changed = false;
      iterations++;
      const toRemove: string[] = [];

      for (const varName of this.tainted) {
        const symbol = this.symbols.get(varName);

        if (symbol && symbol.type !== 'unknown') {
          toRemove.push(varName);
          continue;
        }

        const defNode = this.definitionNodes.get(varName);
        if (defNode) {
          // Extract method name from scoped variable name for proper taint lookup
          // e.g., "handleRequest:param" -> currentMethod = "handleRequest"
          const prevMethod = this.currentMethod;
          if (varName.includes(':')) {
            this.currentMethod = varName.substring(0, varName.indexOf(':'));
          }

          const isTainted = this.isTaintedExpression(defNode);

          // Restore previous method context
          this.currentMethod = prevMethod;

          if (!isTainted) {
            toRemove.push(varName);
          }
        }
      }

      for (const varName of toRemove) {
        this.tainted.delete(varName);
        this.definitionNodes.delete(varName);
        changed = true;
      }
    }
  }

  // ===========================================================================
  // AST Visitor
  // ===========================================================================

  private visit(node: Node): void {
    const line = getNodeLine(node);

    if (this.unreachableLines.has(line)) {
      return;
    }

    // Track which condition this line is under for correlated predicate analysis
    if (this.conditionStack.length > 0 && !this.lineConditions.has(line)) {
      // Use the innermost (most recent) condition
      this.lineConditions.set(line, this.conditionStack[this.conditionStack.length - 1]);
    }

    switch (node.type) {
      case 'method_declaration':
      case 'constructor_declaration':
        this.handleMethodDeclaration(node);
        return; // Don't visit children directly, handleMethodDeclaration does it

      case 'local_variable_declaration':
        this.handleVariableDeclaration(node);
        break;

      case 'assignment_expression':
        this.handleAssignment(node);
        break;

      case 'update_expression':
        this.handleUpdateExpression(node);
        break;

      case 'if_statement':
        this.handleIfStatement(node);
        return;

      case 'switch_expression':
      case 'switch_statement':
        this.handleSwitch(node);
        return;

      case 'ternary_expression':
        this.handleTernary(node);
        break;

      case 'expression_statement':
        this.handleExpressionStatement(node);
        break;

      case 'for_statement':
      case 'enhanced_for_statement':
      case 'while_statement':
      case 'do_statement':
        this.handleLoopStatement(node);
        return;

      case 'synchronized_statement':
        this.handleSynchronizedStatement(node);
        return;

      default:
        for (const child of node.children) {
          this.visit(child);
        }
    }
  }

  /**
   * Handle method declarations - scope local variables to this method.
   * This prevents local variables from one method bleeding into another.
   */
  private handleMethodDeclaration(node: Node): void {
    const nameNode = node.childForFieldName('name');
    const methodName = nameNode ? getNodeText(nameNode, this.source) : null;

    // Save the previous method context
    const prevMethod = this.currentMethod;
    const prevInConstructor = this.inConstructor;
    const prevClassName = this.currentClassName;
    this.currentMethod = methodName;

    // Detect if this is a constructor
    this.inConstructor = node.type === 'constructor_declaration';
    this.constructorParamPositions.clear();

    // For constructors, find the parent class name
    if (this.inConstructor) {
      let parent = node.parent;
      while (parent) {
        if (parent.type === 'class_declaration' || parent.type === 'class_body') {
          if (parent.type === 'class_declaration') {
            const classNameNode = parent.childForFieldName('name');
            if (classNameNode) {
              this.currentClassName = getNodeText(classNameNode, this.source);
            }
            break;
          } else {
            // class_body - look at parent for class_declaration
            parent = parent.parent;
          }
        } else {
          parent = parent.parent;
        }
      }
    }

    // Mark inter-procedural tainted parameters and track positions for constructors
    const parameters = node.childForFieldName('parameters');
    if (parameters) {
      let paramPosition = 0;
      for (const param of parameters.children) {
        if (param.type === 'formal_parameter' || param.type === 'spread_parameter') {
          const paramNameNode = param.childForFieldName('name');
          if (paramNameNode) {
            const paramName = getNodeText(paramNameNode, this.source);

            // Track constructor parameter positions
            if (this.inConstructor) {
              this.constructorParamPositions.set(paramName, paramPosition);
            }

            // Check if this parameter should be marked as tainted
            if (methodName) {
              for (const tp of this.taintedParametersList) {
                if (tp.methodName === methodName && tp.paramName === paramName) {
                  const scopedName = this.getScopedName(paramName);
                  this.tainted.add(scopedName);
                  this.tainted.add(paramName); // Also add unscoped for flexibility
                }
              }
            }
            paramPosition++;
          }
        }
      }
    }

    // Visit the method body
    const body = node.childForFieldName('body');
    if (body) {
      this.visit(body);
    }

    // Restore the previous method context
    this.currentMethod = prevMethod;
    this.inConstructor = prevInConstructor;
    this.currentClassName = prevClassName;
  }

  /**
   * Get the scoped name for a variable (includes method name if in a method).
   * This ensures local variables from different methods don't conflict.
   */
  private getScopedName(varName: string): string {
    // If the variable already has scope indicators (contains . or :), use as-is
    if (varName.includes('.') || varName.includes(':')) {
      return varName;
    }
    // Scope local variables by method name
    if (this.currentMethod) {
      return `${this.currentMethod}:${varName}`;
    }
    return varName;
  }

  /**
   * Look up a variable value, checking both scoped and unscoped names.
   * This handles cases where we need to find a variable that might be
   * either local (scoped) or global (unscoped, like class fields).
   */
  private lookupSymbol(varName: string): ConstantValue | undefined {
    // First try the scoped name (local variable in current method)
    if (this.currentMethod && !varName.includes('.') && !varName.includes(':')) {
      const scopedName = `${this.currentMethod}:${varName}`;
      const scopedValue = this.symbols.get(scopedName);
      if (scopedValue) {
        return scopedValue;
      }
    }
    // Fall back to unscoped name (class fields, etc.)
    return this.symbols.get(varName);
  }

  private handleLoopStatement(node: Node): void {
    // For loops: mark the loop variable as unknown since it changes during iteration
    // This prevents false dead code detection for conditions depending on loop variables
    const loopVarNames = new Set<string>();

    if (node.type === 'for_statement') {
      // Find the init part and extract variable names
      const initNode = node.childForFieldName('init');
      if (initNode) {
        this.collectLoopVariableNames(initNode, loopVarNames);
      }
      // Also check update expression for variables that are modified
      const updateNode = node.childForFieldName('update');
      if (updateNode) {
        this.collectLoopVariableNames(updateNode, loopVarNames);
      }
    } else if (node.type === 'enhanced_for_statement') {
      // Enhanced for: for (Type item : collection)
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const varName = getNodeText(nameNode, this.source);
        loopVarNames.add(varName);
      }
    }

    // Mark all loop variables as unknown BEFORE visiting children
    // Also add to loopVariables set so they're not overwritten in handleVariableDeclaration
    for (const varName of loopVarNames) {
      this.symbols.set(varName, createUnknown(getNodeLine(node)));
      this.loopVariables.add(varName);
    }

    // Track iterator assignments in for-loop init (e.g., for(Iterator iter = list.iterator(); ...))
    if (node.type === 'for_statement') {
      const initNode = node.childForFieldName('init');
      if (initNode) {
        this.trackIteratorsInNode(initNode);
      }
    }

    // Visit all children (condition, body, etc.)
    for (const child of node.children) {
      this.visit(child);
    }

    // After visiting children, ensure loop variables stay unknown (they may have been overwritten)
    for (const varName of loopVarNames) {
      this.symbols.set(varName, createUnknown(getNodeLine(node)));
    }
  }

  private collectLoopVariableNames(node: Node, names: Set<string>): void {
    // Find all variable names that are defined/modified in this node
    if (node.type === 'local_variable_declaration') {
      for (const child of node.children) {
        if (child.type === 'variable_declarator') {
          const nameNode = child.childForFieldName('name');
          if (nameNode) {
            names.add(getNodeText(nameNode, this.source));
          }
        }
      }
    } else if (node.type === 'assignment_expression' || node.type === 'update_expression') {
      // Find the variable being assigned/updated
      const leftNode = node.childForFieldName('left') || node.childForFieldName('operand');
      if (leftNode && leftNode.type === 'identifier') {
        names.add(getNodeText(leftNode, this.source));
      }
    }
    // Recurse into children
    for (const child of node.children) {
      if (child) this.collectLoopVariableNames(child, names);
    }
  }

  /**
   * Handle synchronized statements.
   * Operations inside synchronized blocks are atomic, so field strong updates are safe.
   */
  private handleSynchronizedStatement(node: Node): void {
    const wasInSyncBlock = this.inSynchronizedBlock;
    this.inSynchronizedBlock = true;

    // Visit all children and track their lines as synchronized
    for (const child of node.children) {
      this.collectSynchronizedLines(child);
      this.visit(child);
    }

    this.inSynchronizedBlock = wasInSyncBlock;
  }

  /**
   * Recursively collect line numbers that are inside a synchronized block.
   */
  private collectSynchronizedLines(node: Node): void {
    const line = getNodeLine(node);
    if (line > 0) {
      this.synchronizedLines.add(line);
    }
    for (const child of node.children) {
      if (child) {
        this.collectSynchronizedLines(child);
      }
    }
  }

  private markLoopVariables(node: Node): void {
    // Find all variable declarations or assignments and mark them as unknown
    if (node.type === 'local_variable_declaration') {
      for (const child of node.children) {
        if (child.type === 'variable_declarator') {
          const nameNode = child.childForFieldName('name');
          if (nameNode) {
            const varName = getNodeText(nameNode, this.source);
            this.symbols.set(varName, createUnknown(getNodeLine(node)));
          }
        }
      }
    } else if (node.type === 'assignment_expression' || node.type === 'update_expression') {
      // Find the variable being assigned/updated
      const leftNode = node.childForFieldName('left') || node.childForFieldName('operand');
      if (leftNode) {
        const varName = getNodeText(leftNode, this.source);
        this.symbols.set(varName, createUnknown(getNodeLine(node)));
      }
    }
    // Recurse into children
    for (const child of node.children) {
      this.markLoopVariables(child);
    }
  }

  // ===========================================================================
  // Variable Tracking
  // ===========================================================================

  private handleVariableDeclaration(node: Node): void {
    for (const child of node.children) {
      if (child.type === 'variable_declarator') {
        const nameNode = child.childForFieldName('name');
        const valueNode = child.childForFieldName('value');

        if (nameNode) {
          const varName = getNodeText(nameNode, this.source);
          const scopedName = this.getScopedName(varName);
          const line = getNodeLine(node);

          // Skip loop variables - they should stay unknown
          if (this.loopVariables.has(varName) || this.loopVariables.has(scopedName)) {
            continue;
          }

          if (valueNode) {
            // Track iterator assignments: iter = collection.iterator()
            this.trackIteratorAssignment(scopedName, valueNode);

            const isTainted = this.isTaintedExpression(valueNode);
            if (isTainted) {
              this.tainted.add(scopedName);
              this.sanitizedVars.delete(scopedName); // No longer sanitized if receiving tainted value
              this.definitionNodes.set(scopedName, valueNode);
              this.symbols.set(scopedName, createUnknown(line));
            } else {
              if (this.inConditionalBranch) {
                this.symbols.set(scopedName, createUnknown(line));
                continue;
              }
              this.tainted.delete(scopedName);
              this.definitionNodes.delete(scopedName);
              const value = this.evaluateExpression(valueNode);
              this.symbols.set(scopedName, value);

              // Track if this variable was explicitly assigned from a sanitizer call
              if (this.isSanitizerMethodCall(valueNode)) {
                this.sanitizedVars.add(scopedName);
              }

              // Check if this is an anti-sanitizer call that reintroduces taint
              // e.g., URLDecoder.decode(sanitizedVar) produces tainted output
              if (this.antiSanitizerReintroducesTaint(valueNode)) {
                this.tainted.add(scopedName);
                this.sanitizedVars.delete(scopedName);
              }
            }
          } else {
            this.symbols.set(scopedName, createUnknown(line));
          }
        }
      }
    }
  }

  private handleAssignment(node: Node): void {
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');

    if (!left || !right) return;

    // Handle chained assignments like o1 = o2 = o3 = value
    // Process the right side first if it's also an assignment
    if (right.type === 'assignment_expression') {
      this.handleAssignment(right);
    }

    // Check if this is an array element assignment: array[index] = value
    if (left.type === 'array_access' || left.type === 'subscript_expression') {
      this.handleArrayElementAssignment(left, right, node);
      return;
    }

    const varName = getNodeText(left, this.source);
    // Only scope simple variable names, not field access like this.field
    const scopedName = varName.includes('.') ? varName : this.getScopedName(varName);
    const line = getNodeLine(node);

    // Track iterator assignments: iter = collection.iterator()
    this.trackIteratorAssignment(scopedName, right);

    if (this.isTaintedExpression(right)) {
      this.tainted.add(scopedName);
      this.sanitizedVars.delete(scopedName); // No longer sanitized if receiving tainted value
      this.definitionNodes.set(scopedName, right);
      this.symbols.set(scopedName, createUnknown(line));

      // Track constructor field assignments: this.field = taintedParam
      if (this.inConstructor && varName.startsWith('this.')) {
        const fieldName = varName.substring(5); // Remove 'this.' prefix
        const rightText = getNodeText(right, this.source);

        // Check if right side is a constructor parameter
        if (this.constructorParamPositions.has(rightText)) {
          const paramPosition = this.constructorParamPositions.get(rightText)!;
          const taintType = this.getTaintTypeForVariable(rightText);

          this.instanceFieldTaint.set(fieldName, {
            fieldName,
            className: this.currentClassName || 'Unknown',
            sourceParam: rightText,
            paramPosition,
            taintType: taintType || 'interprocedural_param',
            assignmentLine: line,
          });
        }
      }
    } else {
      if (this.inConditionalBranch) {
        this.symbols.set(scopedName, createUnknown(line));
        return;
      }

      // Check if this is a class field assignment outside synchronized block
      // Class fields are shared across threads, so strong updates are unsafe
      // unless we're in a synchronized block
      const baseVarName = varName.includes('.') ? varName.split('.').pop()! : varName;
      const isClassField = this.classFields.has(baseVarName);

      if (isClassField && !this.inSynchronizedBlock) {
        // Don't remove taint from class fields outside synchronized blocks
        // Another thread could have set the field to a tainted value
        // Mark as unknown since we can't guarantee the value
        this.symbols.set(scopedName, createUnknown(line));
        // Keep the variable tainted if it was previously tainted
        // (don't call this.tainted.delete)
      } else {
        this.tainted.delete(scopedName);
        this.definitionNodes.delete(scopedName);
        const value = this.evaluateExpression(right);
        this.symbols.set(scopedName, value);

        // Track if this variable was explicitly assigned from a sanitizer call
        if (this.isSanitizerMethodCall(right)) {
          this.sanitizedVars.add(scopedName);
        }
      }

      // Check if this is an anti-sanitizer call that reintroduces taint
      // e.g., URLDecoder.decode(sanitizedVar) produces tainted output
      if (this.antiSanitizerReintroducesTaint(right)) {
        this.tainted.add(scopedName);
        this.sanitizedVars.delete(scopedName);
      }
    }
  }

  private handleArrayElementAssignment(left: Node, right: Node, node: Node): void {
    // Extract array name and index from array[index]
    const arrayNode = left.childForFieldName('array') || left.child(0);
    const indexNode = left.childForFieldName('index') || left.child(2);

    if (!arrayNode) return;

    const arrayName = getNodeText(arrayNode, this.source);

    // Determine the index key (numeric or '*' for unknown)
    let indexKey = '*';
    if (indexNode) {
      const indexValue = this.evaluateExpression(indexNode);
      if (isKnown(indexValue) && (indexValue.type === 'int' || indexValue.type === 'string')) {
        indexKey = String(indexValue.value);
      }
    }

    const isTainted = this.isTaintedExpression(right);

    if (isTainted) {
      // Mark this array element as tainted
      if (!this.taintedArrayElements.has(arrayName)) {
        this.taintedArrayElements.set(arrayName, new Set());
      }
      this.taintedArrayElements.get(arrayName)!.add(indexKey);
    } else {
      // Mark this array element as clean (remove from tainted set)
      const taintedIndices = this.taintedArrayElements.get(arrayName);
      if (taintedIndices) {
        taintedIndices.delete(indexKey);
        // If we're assigning to a specific index and '*' is in the set,
        // we can't remove '*' because other indices might still be tainted
      }
    }
  }

  private handleUpdateExpression(node: Node): void {
    // Handle x++, ++x, x--, --x
    // The operand is a positional child (identifier), not a named field
    const operand = node.children.find(c => c.type === 'identifier');
    if (!operand) {
      return;
    }

    const varName = getNodeText(operand, this.source);
    const scopedName = this.getScopedName(varName);
    const line = getNodeLine(node);

    // Skip loop variables
    if (this.loopVariables.has(varName) || this.loopVariables.has(scopedName)) {
      return;
    }

    const currentValue = this.symbols.get(scopedName);
    if (!currentValue || !isKnown(currentValue) || currentValue.type !== 'int') {
      // If not a known integer, mark as unknown
      this.symbols.set(scopedName, createUnknown(line));
      return;
    }

    // Determine operator (++ or --)
    const operatorNode = node.children.find(c => c.type === '++' || c.type === '--');
    if (!operatorNode) {
      this.symbols.set(scopedName, createUnknown(line));
      return;
    }

    const op = operatorNode.type;
    const currentInt = currentValue.value as number;
    const newValue = op === '++' ? currentInt + 1 : currentInt - 1;

    this.symbols.set(scopedName, {
      value: newValue,
      type: 'int',
      sourceLine: line,
    });
  }

  // ===========================================================================
  // Control Flow Analysis (Dead Code Detection)
  // ===========================================================================

  private handleIfStatement(node: Node): void {
    const condition = node.childForFieldName('condition');
    const consequence = node.childForFieldName('consequence');
    const alternative = node.childForFieldName('alternative');

    if (!condition) {
      for (const child of node.children) {
        this.visit(child);
      }
      return;
    }

    const condValue = this.evaluateExpression(condition);

    if (isKnown(condValue) && condValue.type === 'bool') {
      if (condValue.value === true) {
        if (alternative) {
          this.markUnreachable(alternative);
        }
        if (consequence) {
          this.visit(consequence);
        }
      } else {
        if (consequence) {
          this.markUnreachable(consequence);
        }
        if (alternative) {
          this.visit(alternative);
        }
      }
    } else {
      const taintedBefore = new Set(this.tainted);
      const wasInConditional = this.inConditionalBranch;
      this.inConditionalBranch = true;

      // Get the condition expression string for tracking
      const condExpr = getNodeText(condition, this.source);
      const normalizedCond = this.normalizeCondition(condExpr);

      // Check if we're entering a block with a negated condition
      // If so, temporarily remove taints that were added under the positive condition
      const negatedCond = this.getNegatedCondition(normalizedCond);
      const taintsToExclude = this.conditionalTaints.get(negatedCond) || new Set();

      // Visit then branch with condition context
      this.conditionStack.push(normalizedCond);
      if (consequence) {
        this.visit(consequence);
      }
      this.conditionStack.pop();
      const taintedAfterThen = new Set(this.tainted);

      // Track which variables were newly tainted in the then branch
      const newlyTaintedInThen = new Set<string>();
      for (const v of taintedAfterThen) {
        if (!taintedBefore.has(v)) {
          newlyTaintedInThen.add(v);
        }
      }

      // Record conditional taints for this condition
      if (newlyTaintedInThen.size > 0) {
        if (!this.conditionalTaints.has(normalizedCond)) {
          this.conditionalTaints.set(normalizedCond, new Set());
        }
        for (const v of newlyTaintedInThen) {
          this.conditionalTaints.get(normalizedCond)!.add(v);
        }
      }

      // Visit else branch
      this.tainted = new Set(taintedBefore);
      this.conditionStack.push(negatedCond);
      if (alternative) {
        this.visit(alternative);
      }
      this.conditionStack.pop();
      const taintedAfterElse = new Set(this.tainted);

      // Track which variables were newly tainted in the else branch
      const newlyTaintedInElse = new Set<string>();
      for (const v of taintedAfterElse) {
        if (!taintedBefore.has(v)) {
          newlyTaintedInElse.add(v);
        }
      }

      // Record conditional taints for the negated condition
      if (newlyTaintedInElse.size > 0) {
        if (!this.conditionalTaints.has(negatedCond)) {
          this.conditionalTaints.set(negatedCond, new Set());
        }
        for (const v of newlyTaintedInElse) {
          this.conditionalTaints.get(negatedCond)!.add(v);
        }
      }

      this.inConditionalBranch = wasInConditional;
      this.tainted = new Set([...taintedBefore, ...taintedAfterThen, ...taintedAfterElse]);
    }
  }

  /**
   * Normalize a condition expression for comparison.
   * Strips parentheses and whitespace for consistent matching.
   */
  private normalizeCondition(cond: string): string {
    // Remove outer parentheses from parenthesized expressions
    let normalized = cond.trim();
    while (normalized.startsWith('(') && normalized.endsWith(')')) {
      // Check if the parens are balanced (not something like "(a) && (b)")
      let depth = 0;
      let balanced = true;
      for (let i = 0; i < normalized.length - 1; i++) {
        if (normalized[i] === '(') depth++;
        else if (normalized[i] === ')') depth--;
        if (depth === 0 && i > 0) {
          balanced = false;
          break;
        }
      }
      if (balanced) {
        normalized = normalized.slice(1, -1).trim();
      } else {
        break;
      }
    }
    return normalized;
  }

  /**
   * Get the negated form of a condition expression.
   * "x" -> "!x"
   * "!x" -> "x"
   */
  private getNegatedCondition(cond: string): string {
    const normalized = this.normalizeCondition(cond);
    if (normalized.startsWith('!')) {
      // !x -> x
      return this.normalizeCondition(normalized.slice(1));
    } else {
      // x -> !x
      return '!' + normalized;
    }
  }

  /**
   * Check if a variable's taint should be excluded in the current condition context.
   * Returns true if the variable was tainted under a condition that is mutually
   * exclusive with the current condition context.
   */
  isExcludedByCondition(varName: string): boolean {
    if (this.conditionStack.length === 0) {
      return false;
    }

    // Check if any current condition is the negation of a condition where varName was tainted
    for (const currentCond of this.conditionStack) {
      const negatedCond = this.getNegatedCondition(currentCond);
      const taintsUnderNegated = this.conditionalTaints.get(negatedCond);
      if (taintsUnderNegated && taintsUnderNegated.has(varName)) {
        // The variable was tainted under the negated condition,
        // and we're currently under the opposite condition,
        // so the taint doesn't apply here
        return true;
      }
    }

    return false;
  }

  private handleSwitch(node: Node): void {
    let switchValue: ConstantValue | null = null;

    for (const child of node.children) {
      if (child.type === 'parenthesized_expression') {
        const inner = child.children.find((c: Node) => c.type !== '(' && c.type !== ')');
        if (inner) {
          switchValue = this.evaluateExpression(inner);
        }
        break;
      }
    }

    const switchBlock = node.children.find((c: Node) => c.type === 'switch_block');
    if (!switchBlock) {
      for (const child of node.children) {
        this.visit(child);
      }
      return;
    }

    const caseGroups = switchBlock.children.filter(
      (c: Node) => c.type === 'switch_block_statement_group' || c.type === 'switch_rule'
    );

    if (switchValue && isKnown(switchValue)) {
      let matchingIdx = -1;
      let defaultIdx = -1;

      for (let i = 0; i < caseGroups.length; i++) {
        const caseGroup = caseGroups[i];
        for (const child of caseGroup.children) {
          if (child.type === 'switch_label') {
            const labelText = getNodeText(child, this.source);
            if (labelText.includes('default')) {
              defaultIdx = i;
            } else {
              const caseValue = this.extractCaseValue(child);
              if (caseValue !== null && caseValue === switchValue.value) {
                matchingIdx = i;
              }
            }
          }
        }
      }

      const startIdx = matchingIdx >= 0 ? matchingIdx : defaultIdx;

      for (let i = 0; i < startIdx && startIdx >= 0; i++) {
        this.markUnreachable(caseGroups[i]);
      }

      if (startIdx >= 0) {
        for (let i = startIdx; i < caseGroups.length; i++) {
          this.visit(caseGroups[i]);

          const hasBreak = this.hasBreakStatement(caseGroups[i]);
          if (hasBreak) {
            for (let j = i + 1; j < caseGroups.length; j++) {
              this.markUnreachable(caseGroups[j]);
            }
            break;
          }
        }
      }
    } else {
      for (const caseGroup of caseGroups) {
        this.visit(caseGroup);
      }
    }
  }

  private handleTernary(node: Node): void {
    const condition = node.childForFieldName('condition');
    const consequence = node.childForFieldName('consequence');
    const alternative = node.childForFieldName('alternative');

    if (condition) {
      const condValue = this.evaluateExpression(condition);

      if (isKnown(condValue) && condValue.type === 'bool') {
        if (condValue.value === true && alternative) {
          this.markUnreachable(alternative);
        } else if (condValue.value === false && consequence) {
          this.markUnreachable(consequence);
        }
      }
    }

    for (const child of node.children) {
      if (!this.unreachableLines.has(getNodeLine(child))) {
        this.visit(child);
      }
    }
  }

  private handleExpressionStatement(node: Node): void {
    for (const child of node.children) {
      if (child.type === 'method_invocation') {
        this.checkCollectionTaint(child);
      }
    }

    for (const child of node.children) {
      this.visit(child);
    }
  }

  private markUnreachable(node: Node): void {
    const startLine = node.startPosition.row + 1;
    const endLine = node.endPosition.row + 1;
    for (let line = startLine; line <= endLine; line++) {
      this.unreachableLines.add(line);
    }
  }

  private hasBreakStatement(node: Node): boolean {
    if (node.type === 'break_statement') {
      return true;
    }
    for (const child of node.children) {
      if (this.hasBreakStatement(child)) {
        return true;
      }
    }
    return false;
  }

  private extractCaseValue(labelNode: Node): string | number | null {
    for (const child of labelNode.children) {
      if (child.type === 'decimal_integer_literal') {
        return parseInt(getNodeText(child, this.source), 10);
      }
      if (child.type === 'character_literal') {
        const text = getNodeText(child, this.source);
        return text.slice(1, -1);
      }
      if (child.type === 'string_literal') {
        const text = getNodeText(child, this.source);
        return text.slice(1, -1);
      }
    }
    return null;
  }

  // ===========================================================================
  // Taint Analysis Integration
  // ===========================================================================

  /**
   * Check if an expression is a call to a sanitizer method.
   * This includes both built-in sanitizers and @sanitizer annotated methods.
   */
  isSanitizerMethodCall(node: Node): boolean {
    if (node.type !== 'method_invocation') {
      return false;
    }

    const nameNode = node.childForFieldName('name');
    if (!nameNode) {
      return false;
    }

    const methodName = getNodeText(nameNode, this.source);
    return SANITIZER_METHODS.has(methodName) || this.methodReturnsSanitized.has(methodName);
  }

  /**
   * Check if an expression is a call to an anti-sanitizer method.
   * Anti-sanitizers reverse the effect of sanitization (e.g., URLDecoder.decode reverses URLEncoder.encode).
   * If an argument to the anti-sanitizer was previously sanitized, the result is tainted again.
   */
  isAntiSanitizerCall(node: Node): boolean {
    if (node.type !== 'method_invocation') {
      return false;
    }

    const nameNode = node.childForFieldName('name');
    if (!nameNode) {
      return false;
    }

    const methodName = getNodeText(nameNode, this.source);
    return ANTI_SANITIZER_METHODS.has(methodName);
  }

  /**
   * Check if an anti-sanitizer call has a sanitized argument (which means the result should be tainted).
   * For example: URLDecoder.decode(sanitizedVar) should produce tainted output.
   */
  antiSanitizerReintroducesTaint(node: Node): boolean {
    if (!this.isAntiSanitizerCall(node)) {
      return false;
    }

    const argsNode = node.childForFieldName('arguments');
    if (!argsNode) {
      return false;
    }

    const args = argsNode.children.filter(
      (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
    );

    // Check if any argument is a sanitized variable
    for (const arg of args) {
      if (arg.type === 'identifier') {
        const varName = getNodeText(arg, this.source);
        const scopedName = this.getScopedName(varName);
        if (this.sanitizedVars.has(scopedName) || this.sanitizedVars.has(varName)) {
          return true;
        }
      }
      // Also check if any argument was originally tainted (even if currently not in tainted set)
      // This handles cases where taint flows through multiple variables
      if (this.isTaintedExpression(arg)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Recursively track iterator assignments in a node (for handling for-loop init).
   */
  private trackIteratorsInNode(node: Node): void {
    if (node.type === 'local_variable_declaration') {
      for (const child of node.children) {
        if (child.type === 'variable_declarator') {
          const nameNode = child.childForFieldName('name');
          const valueNode = child.childForFieldName('value');
          if (nameNode && valueNode) {
            const varName = getNodeText(nameNode, this.source);
            const scopedName = this.getScopedName(varName);
            this.trackIteratorAssignment(scopedName, valueNode);
          }
        }
      }
    }
    // Recurse into children
    for (const child of node.children) {
      if (child) this.trackIteratorsInNode(child);
    }
  }

  /**
   * Track iterator assignments: when iter = collection.iterator() is called,
   * record that 'iter' was created from 'collection' so we can propagate taint
   * through iter.next() calls.
   */
  private trackIteratorAssignment(varName: string, valueNode: Node): void {
    if (valueNode.type !== 'method_invocation') return;

    const nameNode = valueNode.childForFieldName('name');
    const objectNode = valueNode.childForFieldName('object');

    if (!nameNode || !objectNode) return;

    const methodName = getNodeText(nameNode, this.source);

    // Track iterator() calls
    if (methodName === 'iterator' || methodName === 'listIterator') {
      const collectionName = getNodeText(objectNode, this.source);
      this.iteratorSources.set(varName, collectionName);
    }
  }

  /**
   * Check if a collection is tainted (has any tainted elements).
   */
  private isCollectionTainted(collectionName: string): boolean {
    // Check if the collection has tainted elements via list tracking
    const listElems = this.listElements.get(collectionName);
    if (listElems) {
      for (const elem of listElems) {
        if (elem === '__TAINTED__') return true;
        if (elem !== null) {
          const scopedElem = this.currentMethod ? `${this.currentMethod}:${elem}` : elem;
          if (this.tainted.has(elem) || this.tainted.has(scopedElem)) {
            return true;
          }
        }
      }
    }

    // Check if the collection has tainted keys (for maps)
    const taintedKeys = this.taintedCollections.get(collectionName);
    if (taintedKeys && taintedKeys.size > 0) {
      return true;
    }

    // Check if the collection variable itself is tainted
    const scopedCollection = this.currentMethod ? `${this.currentMethod}:${collectionName}` : collectionName;
    if (this.tainted.has(collectionName) || this.tainted.has(scopedCollection)) {
      return true;
    }

    return false;
  }

  /**
   * Get the taint type for a variable based on how it was tainted.
   * Returns the taint type (e.g., 'http_param', 'io_input') or null if not found.
   */
  private getTaintTypeForVariable(varName: string): string | null {
    // Check if it's a tainted parameter from the list
    for (const tp of this.taintedParametersList) {
      if (tp.paramName === varName) {
        // For now, return a generic type - the actual type would come from source matching
        return 'interprocedural_param';
      }
    }
    // If the variable is tainted but we don't know the type, return generic
    if (this.tainted.has(varName) || this.tainted.has(this.getScopedName(varName))) {
      return 'interprocedural_param';
    }
    return null;
  }

  isTaintedExpression(node: Node): boolean {
    const text = getNodeText(node, this.source);

    if (node.type === 'method_invocation') {
      const nameNode = node.childForFieldName('name');
      const objectNode = node.childForFieldName('object');

      if (nameNode) {
        const methodName = getNodeText(nameNode, this.source);

        if (SANITIZER_METHODS.has(methodName)) {
          return false;
        }

        if (this.methodReturnsConstant.has(methodName)) {
          return false;
        }

        if (this.methodReturnsSanitized.has(methodName)) {
          return false;
        }

        // Method returns safe value even with tainted input
        if (this.methodReturnsSafeValue.has(methodName)) {
          return false;
        }

        const returnedParamIdx = this.methodReturnsParameter.get(methodName);
        if (returnedParamIdx !== undefined && returnedParamIdx >= 0) {
          const argsNode = node.childForFieldName('arguments');
          if (argsNode) {
            const args = argsNode.children.filter(
              (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
            );
            if (args.length > returnedParamIdx) {
              const argNode = args[returnedParamIdx];
              if (this.isTaintedExpression(argNode)) {
                return true;
              }
            }
          }
        }

        if (PROPAGATOR_METHODS.has(methodName)) {
          const argsNode = node.childForFieldName('arguments');
          if (argsNode) {
            const args = argsNode.children.filter(
              (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
            );
            for (const argNode of args) {
              if (this.isTaintedExpression(argNode)) {
                return true;
              }
            }
          }
        }

        // IMPORTANT: Handle list.get() BEFORE generic object taint check
        // This allows precise index tracking to work correctly
        if (methodName === 'get') {
          const argsNode = node.childForFieldName('arguments');

          if (objectNode && argsNode) {
            const collectionName = getNodeText(objectNode, this.source);

            const listElems = this.listElements.get(collectionName);
            if (listElems) {
              const args = argsNode.children.filter(
                (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
              );

              if (args.length > 0) {
                // First, check if ANY element in the collection is tainted
                // This is a conservative approach for safety analysis
                const hasAnyTainted = listElems.some(e => {
                  if (e === null) return false;
                  if (e === '__TAINTED__') return true;
                  const scopedE = this.currentMethod ? `${this.currentMethod}:${e}` : e;
                  return this.tainted.has(e) || this.tainted.has(scopedE);
                });

                const indexValue = this.evaluateExpression(args[0]);
                if (isKnown(indexValue) && indexValue.type === 'int') {
                  const index = indexValue.value as number;
                  if (index >= 0 && index < listElems.length) {
                    const elem = listElems[index];
                    if (elem === null) {
                      // Index points to a literal value (like "safe" or "moresafe")
                      // which was added directly, not via a variable - this is clean
                      return false;
                    }
                    if (elem === '__TAINTED__') {
                      return true;
                    }
                    // Check both scoped and unscoped name for taint
                    const scopedElem = this.currentMethod ? `${this.currentMethod}:${elem}` : elem;
                    if (this.tainted.has(elem) || this.tainted.has(scopedElem)) {
                      return true;
                    }
                    // Specific element at known index is clean (not tainted variable)
                    return false;
                  }
                }
                // Unknown index - return true if any element is tainted
                return hasAnyTainted;
              }
            }

            const taintedKeys = this.taintedCollections.get(collectionName);

            if (taintedKeys) {
              const args = argsNode.children.filter(
                (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
              );

              if (args.length > 0) {
                const keyValue = this.evaluateExpression(args[0]);
                if (isKnown(keyValue) && keyValue.type === 'string') {
                  const keyStr = String(keyValue.value);
                  if (!taintedKeys.has(keyStr) && !taintedKeys.has('*')) {
                    return false;
                  }
                  if (taintedKeys.has(keyStr)) {
                    return true;
                  }
                }
                return true;
              }
            } else if (!listElems) {
              // No key tracking and no list element tracking
              // Fall back to checking if the collection itself is tainted
              if (this.isCollectionTainted(collectionName)) {
                return true;
              }
              // Collection is not tainted - safe to return false
              return false;
            }
          }
        }

        // Handle getLast(), getFirst() - return tainted if list has any tainted element
        if (methodName === 'getLast' || methodName === 'getFirst' || methodName === 'peek' ||
            methodName === 'peekFirst' || methodName === 'peekLast' || methodName === 'poll' ||
            methodName === 'pollFirst' || methodName === 'pollLast' || methodName === 'element') {
          if (objectNode) {
            const collectionName = getNodeText(objectNode, this.source);
            if (this.isCollectionTainted(collectionName)) {
              return true;
            }
          }
        }

        // Handle toArray() - return tainted if collection is tainted
        if (methodName === 'toArray') {
          if (objectNode) {
            const collectionName = getNodeText(objectNode, this.source);
            if (this.isCollectionTainted(collectionName)) {
              return true;
            }
          }
        }

        // Handle iterator.next() - return tainted if the iterator's source collection is tainted
        if (methodName === 'next') {
          if (objectNode) {
            const iteratorName = getNodeText(objectNode, this.source);
            // Check if this iterator was created from a tainted collection
            const sourceCollection = this.iteratorSources.get(iteratorName);
            if (sourceCollection) {
              // We know this is an iterator.next() call - return based on collection taint
              return this.isCollectionTainted(sourceCollection);
            }
            // Also check with scoped name
            const scopedIterator = this.currentMethod ? `${this.currentMethod}:${iteratorName}` : iteratorName;
            const scopedSourceCollection = this.iteratorSources.get(scopedIterator);
            if (scopedSourceCollection) {
              // We know this is an iterator.next() call - return based on collection taint
              return this.isCollectionTainted(scopedSourceCollection);
            }
            // If we have no record of this iterator, fall through to other checks
          }
        }

        // Generic object taint check - applies to methods NOT handled above
        // Skip for 'get' since it has precise index tracking
        if (methodName !== 'get' && objectNode) {
          const objectText = getNodeText(objectNode, this.source);
          if (objectNode.type === 'identifier' && this.tainted.has(objectText)) {
            return true;
          }
          if (this.isTaintedExpression(objectNode)) {
            return true;
          }
        }
      }
    }

    if (node.type === 'array_access' || node.type === 'subscript_expression') {
      const arrayNode = node.childForFieldName('array') || node.child(0);
      const indexNode = node.childForFieldName('index') || node.child(2);

      if (arrayNode) {
        const arrayName = getNodeText(arrayNode, this.source);

        // Check if the whole array is tainted
        if (arrayNode.type === 'identifier' && this.tainted.has(arrayName)) {
          return true;
        }

        // Check element-level taint tracking
        const taintedIndices = this.taintedArrayElements.get(arrayName);
        if (taintedIndices) {
          // If '*' is in the set, the whole array has tainted elements
          if (taintedIndices.has('*')) {
            return true;
          }

          // Check specific index
          if (indexNode) {
            const indexValue = this.evaluateExpression(indexNode);
            if (isKnown(indexValue) && (indexValue.type === 'int' || indexValue.type === 'string')) {
              const indexKey = String(indexValue.value);
              if (taintedIndices.has(indexKey)) {
                return true;
              }
              // Specific index is NOT tainted - return false for this access
              return false;
            }
            // Unknown index - check if ANY element is tainted
            if (taintedIndices.size > 0) {
              return true;
            }
          }
        }

        // Recursively check if arrayNode itself is tainted
        if (this.isTaintedExpression(arrayNode)) {
          return true;
        }
      }
    }

    if (node.type === 'ternary_expression') {
      const condition = node.childForFieldName('condition');
      const consequence = node.childForFieldName('consequence');
      const alternative = node.childForFieldName('alternative');

      if (condition) {
        const condValue = this.evaluateExpression(condition);
        if (isKnown(condValue) && condValue.type === 'bool') {
          if (condValue.value === true && consequence) {
            return this.isTaintedExpression(consequence);
          } else if (condValue.value === false && alternative) {
            return this.isTaintedExpression(alternative);
          }
        }
      }

      return (
        (consequence ? this.isTaintedExpression(consequence) : false) ||
        (alternative ? this.isTaintedExpression(alternative) : false)
      );
    }

    // Handle cast expressions - evaluate the inner expression, not the full text
    // This prevents false positives from patterns like ".next(" matching "(String) iter.next()"
    if (node.type === 'cast_expression') {
      const value = node.childForFieldName('value');
      if (value) {
        return this.isTaintedExpression(value);
      }
    }

    // Handle object creation expressions - check for collection copy constructors
    // e.g., new ArrayList(taintedList), new HashMap(taintedMap), List.copyOf(tainted)
    if (node.type === 'object_creation_expression') {
      const typeNode = node.childForFieldName('type');
      const argsNode = node.childForFieldName('arguments');

      if (typeNode && argsNode) {
        const typeName = getNodeText(typeNode, this.source);

        // Check if this is a known collection type
        const collectionTypes = ['ArrayList', 'LinkedList', 'HashSet', 'TreeSet', 'HashMap', 'TreeMap', 'LinkedHashMap', 'LinkedHashSet', 'Vector', 'CopyOnWriteArrayList', 'ConcurrentHashMap'];
        const isCollectionType = collectionTypes.some(t => typeName.includes(t));

        if (isCollectionType) {
          // Check if any argument is a tainted collection (copy constructor)
          const args = argsNode.children.filter((c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ',');
          for (const arg of args) {
            if (arg.type === 'identifier') {
              const argName = getNodeText(arg, this.source);
              if (this.isCollectionTainted(argName)) {
                return true;
              }
            }
            if (this.isTaintedExpression(arg)) {
              return true;
            }
          }
        }
      }
    }

    // Check taint patterns, but exclude known-safe iterator.next() calls
    // The .next( pattern is meant for Scanner.next(), not Iterator.next()
    if (TAINT_PATTERN_REGEX.test(text)) {
      // If this matches .next( but is a known iterator, skip this pattern
      if (text.includes('.next(') && node.type === 'method_invocation') {
        const objectNode = node.childForFieldName('object');
        if (objectNode) {
          const iteratorName = getNodeText(objectNode, this.source);
          const scopedIterator = this.currentMethod ? `${this.currentMethod}:${iteratorName}` : iteratorName;
          // If we've tracked this as an iterator, don't match the .next( pattern
          if (this.iteratorSources.has(iteratorName) || this.iteratorSources.has(scopedIterator)) {
            // Fall through to check other patterns and iterator-specific handling
          } else {
            return true;
          }
        } else {
          return true;
        }
      } else {
        return true;
      }
    }

    for (const pattern of this.additionalTaintPatterns) {
      if (text.includes(pattern)) {
        return true;
      }
    }

    if (node.type === 'identifier') {
      // Check both scoped and unscoped taint
      // Scoped: methodName:varName (for local variables)
      // Unscoped: varName (for class fields or when not in a method)
      const scopedName = this.currentMethod ? `${this.currentMethod}:${text}` : text;
      const isTainted = this.tainted.has(scopedName) || this.tainted.has(text);

      if (isTainted) {
        // Check if this taint is excluded by correlated predicate analysis
        // If the variable was tainted under condition C, and we're now under !C,
        // the taint doesn't apply in this context
        if (this.isExcludedByCondition(scopedName) || this.isExcludedByCondition(text)) {
          return false;
        }
      }

      return isTainted;
    }

    for (const child of node.children) {
      if (this.isTaintedExpression(child)) {
        return true;
      }
    }

    return false;
  }

  private checkCollectionTaint(node: Node): void {
    const objectNode = node.childForFieldName('object');
    const nameNode = node.childForFieldName('name');
    const argsNode = node.childForFieldName('arguments');

    if (!objectNode || !nameNode || !argsNode) return;

    const methodName = getNodeText(nameNode, this.source);
    const collectionName = getNodeText(objectNode, this.source);

    if (methodName === 'put') {
      const args = argsNode.children.filter(
        (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
      );

      if (args.length >= 2) {
        const valueArg = args[1];
        if (this.isTaintedExpression(valueArg)) {
          const keyValue = this.evaluateExpression(args[0]);
          const keyStr = isKnown(keyValue) && keyValue.type === 'string'
            ? String(keyValue.value)
            : '*';

          if (!this.taintedCollections.has(collectionName)) {
            this.taintedCollections.set(collectionName, new Set());
          }
          this.taintedCollections.get(collectionName)!.add(keyStr);
        }
      }
    }

    if (methodName === 'add' || methodName === 'addLast') {
      const args = argsNode.children.filter(
        (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
      );

      if (args.length >= 1) {
        if (!this.listElements.has(collectionName)) {
          this.listElements.set(collectionName, []);
        }

        const list = this.listElements.get(collectionName)!;
        const valueArg = args[0];
        let isTainted = false;

        if (valueArg.type === 'identifier') {
          const varName = getNodeText(valueArg, this.source);
          // Check both scoped and unscoped name for taint
          const scopedName = this.currentMethod ? `${this.currentMethod}:${varName}` : varName;
          isTainted = this.tainted.has(scopedName) || this.tainted.has(varName);
          list.push(isTainted ? varName : null);
        } else if (this.isTaintedExpression(valueArg)) {
          list.push('__TAINTED__');
          isTainted = true;
        } else {
          list.push(null);
        }

        // Also mark the collection variable itself as tainted if it contains tainted elements
        if (isTainted) {
          const scopedCollection = this.currentMethod ? `${this.currentMethod}:${collectionName}` : collectionName;
          this.tainted.add(scopedCollection);
        }
      }
    }

    // Handle addAll() - copy all elements from source collection to target
    if (methodName === 'addAll') {
      const args = argsNode.children.filter(
        (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
      );

      if (args.length >= 1) {
        const sourceArg = args[0];
        if (sourceArg.type === 'identifier') {
          const sourceName = getNodeText(sourceArg, this.source);
          // Check if the source collection is tainted
          if (this.isCollectionTainted(sourceName)) {
            if (!this.listElements.has(collectionName)) {
              this.listElements.set(collectionName, []);
            }
            // Add a tainted marker to indicate the collection now has tainted elements
            this.listElements.get(collectionName)!.push('__TAINTED__');
            // Also mark the target collection as tainted
            const scopedCollection = this.currentMethod ? `${this.currentMethod}:${collectionName}` : collectionName;
            this.tainted.add(scopedCollection);
          }
        } else if (this.isTaintedExpression(sourceArg)) {
          if (!this.listElements.has(collectionName)) {
            this.listElements.set(collectionName, []);
          }
          this.listElements.get(collectionName)!.push('__TAINTED__');
          const scopedCollection = this.currentMethod ? `${this.currentMethod}:${collectionName}` : collectionName;
          this.tainted.add(scopedCollection);
        }
      }
    }

    // Handle putAll() - copy all entries from source map to target
    if (methodName === 'putAll') {
      const args = argsNode.children.filter(
        (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
      );

      if (args.length >= 1) {
        const sourceArg = args[0];
        if (sourceArg.type === 'identifier') {
          const sourceName = getNodeText(sourceArg, this.source);
          // Check if the source map has any tainted keys
          const sourceTaintedKeys = this.taintedCollections.get(sourceName);
          if (sourceTaintedKeys && sourceTaintedKeys.size > 0) {
            if (!this.taintedCollections.has(collectionName)) {
              this.taintedCollections.set(collectionName, new Set());
            }
            // Copy all tainted keys from source to target
            for (const key of sourceTaintedKeys) {
              this.taintedCollections.get(collectionName)!.add(key);
            }
          }
          // Also check if source collection itself is tainted
          if (this.isCollectionTainted(sourceName)) {
            const scopedCollection = this.currentMethod ? `${this.currentMethod}:${collectionName}` : collectionName;
            this.tainted.add(scopedCollection);
          }
        } else if (this.isTaintedExpression(sourceArg)) {
          if (!this.taintedCollections.has(collectionName)) {
            this.taintedCollections.set(collectionName, new Set());
          }
          this.taintedCollections.get(collectionName)!.add('*');
          const scopedCollection = this.currentMethod ? `${this.currentMethod}:${collectionName}` : collectionName;
          this.tainted.add(scopedCollection);
        }
      }
    }

    if (methodName === 'addFirst') {
      const args = argsNode.children.filter(
        (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
      );

      if (args.length >= 1) {
        if (!this.listElements.has(collectionName)) {
          this.listElements.set(collectionName, []);
        }

        const list = this.listElements.get(collectionName)!;
        const valueArg = args[0];

        if (valueArg.type === 'identifier') {
          const varName = getNodeText(valueArg, this.source);
          // Check both scoped and unscoped name for taint
          const scopedName = this.currentMethod ? `${this.currentMethod}:${varName}` : varName;
          const isTainted = this.tainted.has(scopedName) || this.tainted.has(varName);
          list.unshift(isTainted ? varName : null);
        } else if (this.isTaintedExpression(valueArg)) {
          list.unshift('__TAINTED__');
        } else {
          list.unshift(null);
        }
      }
    }

    // retainAll() does NOT transfer taint - it only keeps elements that already exist in the target collection
    // c2.retainAll(c1) keeps only elements in c2 that are in c1 - the values come from c2, not c1
    // So if c2 has "abc" and c1 has tainted_value, c2 either has "abc" or is empty - never tainted
    if (methodName === 'retainAll') {
      // retainAll doesn't introduce taint, so we don't need to do anything
      // The target collection keeps its own (non-tainted) values
    }

    if (methodName === 'remove') {
      const args = argsNode.children.filter(
        (c: Node) => c.type !== '(' && c.type !== ')' && c.type !== ','
      );

      if (args.length >= 1 && this.listElements.has(collectionName)) {
        const list = this.listElements.get(collectionName)!;
        const indexValue = this.evaluateExpression(args[0]);

        if (isKnown(indexValue) && indexValue.type === 'int') {
          const index = indexValue.value as number;
          if (index >= 0 && index < list.length) {
            list.splice(index, 1);
          }
        }
      }
    }
  }
}
