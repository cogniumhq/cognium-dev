/**
 * Analysis module index
 */

export {
  parseConfig,
  loadSourceConfigs,
  loadSinkConfigs,
  createTaintConfig,
  getDefaultConfig,
  DEFAULT_SOURCES,
  DEFAULT_SINKS,
  DEFAULT_SANITIZERS,
} from './config-loader.js';

export {
  analyzeTaint,
} from './taint-matcher.js';

export {
  detectUnresolved,
} from './unresolved.js';

export {
  generateFindings,
} from './findings.js';

export {
  propagateTaint,
  type TaintPropagationResult,
  type TaintedVariable,
  type TaintFlow,
} from './taint-propagation.js';

export {
  analyzeInterprocedural,
  getInterproceduralSummary,
  findTaintBridges,
  getMethodTaintPaths,
  hasMethod,
  getMethod,
  isMethodTainted,
  type InterproceduralResult,
  type MethodNode,
  type CallEdge,
} from './interprocedural.js';

export {
  analyzeConstantPropagation,
  isFalsePositive,
  isCorrelatedPredicateFP,
  ConstantPropagator,
  isKnown,
  createUnknown,
  createConstant,
  getNodeText,
  getNodeLine,
  type ConstantValue,
  type ConstantType,
  type ConstantPropagatorResult,
  type ConstantPropagationOptions,
} from './constant-propagation.js';

export {
  PathFinder,
  findTaintPaths,
  formatTaintPath,
  type TaintHop,
  type TaintPath,
  type PathFinderResult,
  type PathFinderConfig,
} from './path-finder.js';

export {
  DFGVerifier,
  verifyTaintFlow,
  type VerificationResult,
  type VerificationPath,
  type VerificationStep,
  type VerifierConfig,
} from './dfg-verifier.js';

export {
  parseVersion,
  compareVersions,
  semverSatisfies,
  isVersionVulnerable,
  type ParsedVersion,
} from './semver.js';
