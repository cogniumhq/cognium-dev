/**
 * Expression evaluation for constant propagation.
 *
 * Evaluates AST expressions to determine their constant values.
 */

import type { Node } from 'web-tree-sitter';
import type { ConstantValue } from './types.js';
import { isKnown, createUnknown, createConstant, getNodeText, getNodeLine } from './ast-utils.js';

/**
 * Expression evaluator for constant propagation.
 *
 * Takes a symbol lookup function to resolve variable values,
 * allowing it to be used with different symbol tables.
 */
export class ExpressionEvaluator {
  constructor(
    private source: string,
    private getSymbol: (name: string) => ConstantValue | undefined
  ) {}

  /**
   * Evaluate an expression node to determine its constant value.
   */
  evaluate(node: Node): ConstantValue {
    const line = getNodeLine(node);
    const text = getNodeText(node, this.source);

    switch (node.type) {
      // Literals
      case 'decimal_integer_literal':
      case 'hex_integer_literal':
      case 'octal_integer_literal':
        return createConstant(parseInt(text, 10), 'int', line);

      case 'decimal_floating_point_literal':
        return createConstant(parseFloat(text), 'float', line);

      case 'string_literal':
        return createConstant(text.slice(1, -1), 'string', line);

      case 'character_literal': {
        let char = text.slice(1, -1);
        if (char.startsWith('\\')) {
          char = this.unescapeChar(char);
        }
        return createConstant(char, 'char', line);
      }

      case 'true':
        return createConstant(true, 'bool', line);

      case 'false':
        return createConstant(false, 'bool', line);

      case 'null_literal':
        return createConstant(null, 'null', line);

      // Variable reference
      case 'identifier': {
        const existing = this.getSymbol(text);
        if (existing) {
          return existing;
        }
        return createUnknown(line);
      }

      // Parenthesized expression
      case 'parenthesized_expression': {
        const inner = node.children.find((c: Node) => c.type !== '(' && c.type !== ')');
        if (inner) {
          return this.evaluate(inner);
        }
        return createUnknown(line);
      }

      // Binary expression
      case 'binary_expression':
        return this.evaluateBinary(node);

      // Unary expression
      case 'unary_expression':
        return this.evaluateUnary(node);

      // Ternary expression
      case 'ternary_expression':
        return this.evaluateTernary(node);

      // Method invocation
      case 'method_invocation':
        return this.evaluateMethodCall(node);

      // Field access
      case 'field_access':
        return this.evaluateFieldAccess(node);

      default:
        return createUnknown(line);
    }
  }

  private evaluateBinary(node: Node): ConstantValue {
    const line = getNodeLine(node);
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    const operatorNode = node.childForFieldName('operator');

    if (!left || !right || !operatorNode) {
      return createUnknown(line);
    }

    const leftVal = this.evaluate(left);
    const rightVal = this.evaluate(right);

    if (!isKnown(leftVal) || !isKnown(rightVal)) {
      return createUnknown(line);
    }

    const lv = leftVal.value;
    const rv = rightVal.value;
    const op = getNodeText(operatorNode, this.source);

    try {
      // Arithmetic
      if (op === '+') {
        if (typeof lv === 'string' || typeof rv === 'string') {
          return createConstant(String(lv) + String(rv), 'string', line);
        }
        if (typeof lv === 'number' && typeof rv === 'number') {
          const result = lv + rv;
          return createConstant(result, Number.isInteger(result) ? 'int' : 'float', line);
        }
      }

      if (op === '-' && typeof lv === 'number' && typeof rv === 'number') {
        const result = lv - rv;
        return createConstant(result, Number.isInteger(result) ? 'int' : 'float', line);
      }

      if (op === '*' && typeof lv === 'number' && typeof rv === 'number') {
        const result = lv * rv;
        return createConstant(result, Number.isInteger(result) ? 'int' : 'float', line);
      }

      if (op === '/' && typeof lv === 'number' && typeof rv === 'number' && rv !== 0) {
        if (Number.isInteger(lv) && Number.isInteger(rv)) {
          return createConstant(Math.floor(lv / rv), 'int', line);
        }
        return createConstant(lv / rv, 'float', line);
      }

      if (op === '%' && typeof lv === 'number' && typeof rv === 'number' && rv !== 0) {
        return createConstant(lv % rv, 'int', line);
      }

      // Comparison
      if (op === '>' && typeof lv === 'number' && typeof rv === 'number') {
        return createConstant(lv > rv, 'bool', line);
      }

      if (op === '<' && typeof lv === 'number' && typeof rv === 'number') {
        return createConstant(lv < rv, 'bool', line);
      }

      if (op === '>=' && typeof lv === 'number' && typeof rv === 'number') {
        return createConstant(lv >= rv, 'bool', line);
      }

      if (op === '<=' && typeof lv === 'number' && typeof rv === 'number') {
        return createConstant(lv <= rv, 'bool', line);
      }

      if (op === '==') {
        return createConstant(lv === rv, 'bool', line);
      }

      if (op === '!=') {
        return createConstant(lv !== rv, 'bool', line);
      }

      // Logical
      if (op === '&&') {
        return createConstant(Boolean(lv) && Boolean(rv), 'bool', line);
      }

      if (op === '||') {
        return createConstant(Boolean(lv) || Boolean(rv), 'bool', line);
      }
    } catch {
      // Division by zero, etc.
    }

    return createUnknown(line);
  }

  private evaluateUnary(node: Node): ConstantValue {
    const line = getNodeLine(node);
    const operatorNode = node.childForFieldName('operator');
    const operandNode = node.childForFieldName('operand');

    if (!operatorNode || !operandNode) {
      return createUnknown(line);
    }

    const op = getNodeText(operatorNode, this.source);
    const operand = this.evaluate(operandNode);

    if (!isKnown(operand)) {
      return createUnknown(line);
    }

    if (op === '!' && typeof operand.value === 'boolean') {
      return createConstant(!operand.value, 'bool', line);
    }

    if (op === '-' && typeof operand.value === 'number') {
      return createConstant(-operand.value, operand.type as 'int' | 'float', line);
    }

    if (op === '+' && typeof operand.value === 'number') {
      return operand;
    }

    return createUnknown(line);
  }

  private evaluateTernary(node: Node): ConstantValue {
    const line = getNodeLine(node);
    const condition = node.childForFieldName('condition');
    const consequence = node.childForFieldName('consequence');
    const alternative = node.childForFieldName('alternative');

    if (!condition || !consequence || !alternative) {
      return createUnknown(line);
    }

    const condValue = this.evaluate(condition);

    if (isKnown(condValue) && condValue.type === 'bool') {
      if (condValue.value === true) {
        return this.evaluate(consequence);
      } else {
        return this.evaluate(alternative);
      }
    }

    return createUnknown(line);
  }

  private evaluateMethodCall(node: Node): ConstantValue {
    const line = getNodeLine(node);
    const objectNode = node.childForFieldName('object');
    const nameNode = node.childForFieldName('name');
    const argsNode = node.childForFieldName('arguments');

    if (!objectNode || !nameNode) {
      return createUnknown(line);
    }

    const objValue = this.evaluate(objectNode);
    const methodName = getNodeText(nameNode, this.source);

    if (!isKnown(objValue)) {
      return createUnknown(line);
    }

    // String methods
    if (objValue.type === 'string' && typeof objValue.value === 'string') {
      const s = objValue.value;

      if (methodName === 'charAt' && argsNode) {
        const argValues = this.getArgumentValues(argsNode);
        if (argValues.length > 0 && isKnown(argValues[0]) && argValues[0].type === 'int') {
          const idx = argValues[0].value as number;
          if (idx >= 0 && idx < s.length) {
            return createConstant(s[idx], 'char', line);
          }
        }
      }

      if (methodName === 'length') {
        return createConstant(s.length, 'int', line);
      }

      if (methodName === 'substring' && argsNode) {
        const argValues = this.getArgumentValues(argsNode);
        if (argValues.length === 1 && isKnown(argValues[0]) && argValues[0].type === 'int') {
          const start = argValues[0].value as number;
          return createConstant(s.substring(start), 'string', line);
        }
        if (argValues.length >= 2 && isKnown(argValues[0]) && isKnown(argValues[1])) {
          const start = argValues[0].value as number;
          const end = argValues[1].value as number;
          return createConstant(s.substring(start, end), 'string', line);
        }
      }

      if (methodName === 'equals' && argsNode) {
        const argValues = this.getArgumentValues(argsNode);
        if (argValues.length > 0 && isKnown(argValues[0]) && argValues[0].type === 'string') {
          return createConstant(s === argValues[0].value, 'bool', line);
        }
      }

      if (methodName === 'toUpperCase') {
        return createConstant(s.toUpperCase(), 'string', line);
      }

      if (methodName === 'toLowerCase') {
        return createConstant(s.toLowerCase(), 'string', line);
      }

      if (methodName === 'trim') {
        return createConstant(s.trim(), 'string', line);
      }
    }

    return createUnknown(line);
  }

  private evaluateFieldAccess(node: Node): ConstantValue {
    const line = getNodeLine(node);
    const text = getNodeText(node, this.source);

    // Common constants
    if (text === 'Integer.MAX_VALUE') {
      return createConstant(2147483647, 'int', line);
    }
    if (text === 'Integer.MIN_VALUE') {
      return createConstant(-2147483648, 'int', line);
    }

    return createUnknown(line);
  }

  /**
   * Get argument values from an argument list node.
   */
  getArgumentValues(argsNode: Node): ConstantValue[] {
    const values: ConstantValue[] = [];
    for (const child of argsNode.children) {
      if (child.type !== '(' && child.type !== ')' && child.type !== ',') {
        values.push(this.evaluate(child));
      }
    }
    return values;
  }

  private unescapeChar(char: string): string {
    switch (char) {
      case '\\n': return '\n';
      case '\\t': return '\t';
      case '\\r': return '\r';
      case '\\\\': return '\\';
      case "\\'": return "'";
      case '\\"': return '"';
      default: return char;
    }
  }
}
