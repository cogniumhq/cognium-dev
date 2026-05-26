/**
 * Type definitions for constant propagation analysis.
 */

export type ConstantType = 'string' | 'int' | 'float' | 'char' | 'bool' | 'null' | 'unknown';

export interface ConstantValue {
  value: string | number | boolean | null;
  type: ConstantType;
  sourceLine: number;
}

export interface ConstantPropagatorResult {
  /** Variable name → constant value mapping */
  symbols: Map<string, ConstantValue>;
  /** Set of tainted variable names */
  tainted: Set<string>;
  /** Set of unreachable line numbers (dead code) */
  unreachableLines: Set<number>;
  /** Collection taint tracking: collection name → tainted keys */
  taintedCollections: Map<string, Set<string>>;
  /** Array element taint tracking: array name → tainted indices (or '*' for whole array) */
  taintedArrayElements: Map<string, Set<string>>;
  /** Variables explicitly assigned from sanitizer calls */
  sanitizedVars: Set<string>;
  /** Conditional taint tracking: condition expression → set of variables tainted under that condition */
  conditionalTaints: Map<string, Set<string>>;
  /** Line condition tracking: line number → condition expression it's under */
  lineConditions: Map<number, string>;
  /** Synchronized block tracking: set of line numbers that are inside synchronized blocks */
  synchronizedLines: Set<number>;
  /** Instance field taint tracking: field name → taint info from constructor assignment */
  instanceFieldTaint: Map<string, FieldTaintInfo>;
}

export interface TaintedParameter {
  /** Name of the method containing the parameter */
  methodName: string;
  /** Name of the parameter */
  paramName: string;
}

/**
 * Tracks taint flowing from constructor parameters to instance fields.
 * This enables detection of taint through getters that return these fields.
 */
export interface FieldTaintInfo {
  /** Name of the field (without 'this.' prefix) */
  fieldName: string;
  /** Name of the class containing this field */
  className: string;
  /** Name of the constructor parameter that assigned this field */
  sourceParam: string;
  /** Position of the parameter in the constructor (0-indexed) */
  paramPosition: number;
  /** Type of taint source (e.g., 'http_param', 'interprocedural_param') */
  taintType: string;
  /** Line where the field assignment occurred */
  assignmentLine: number;
}

export interface ConstantPropagationOptions {
  /** Additional taint patterns for test harnesses */
  additionalTaintPatterns?: string[];
  /** Methods with @sanitizer annotation (from Javadoc) */
  sanitizerMethods?: string[];
  /** Method parameters to treat as initially tainted (for inter-procedural analysis) */
  taintedParameters?: TaintedParameter[];
}
