/**
 * Constant Propagation Engine
 *
 * This module re-exports from the modular constant-propagation/ directory.
 * For new code, import directly from './constant-propagation/index.js'.
 *
 * @module constant-propagation
 */

export {
  // Types
  type ConstantType,
  type ConstantValue,
  type ConstantPropagatorResult,
  type ConstantPropagationOptions,

  // Utilities
  isKnown,
  createUnknown,
  createConstant,
  getNodeText,
  getNodeLine,

  // Patterns
  TAINT_PATTERNS,
  TAINT_PATTERN_REGEX,
  SANITIZER_METHODS,
  PROPAGATOR_METHODS,

  // Classes
  ExpressionEvaluator,
  ConstantPropagator,

  // Functions
  analyzeConstantPropagation,
  isFalsePositive,
  isCorrelatedPredicateFP,
} from './constant-propagation/index.js';
