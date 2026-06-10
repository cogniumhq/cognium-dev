/**
 * Core module index - re-exports parser and extractors
 */

// Parser
export {
  initParser,
  loadLanguage,
  createParser,
  createFreshParser,
  parse,
  disposeTree,
  walkTree,
  findNodes,
  findAncestor,
  getNodeText,
  collectAllNodes,
  getNodesFromCache,
  isInitialized,
  isLanguageLoaded,
  resetParser,
  type SupportedLanguage,
  type SyntaxNode,
  type Node,
  type NodeCache,
  type Language,
  type Tree,
} from './parser.js';

// Extractors
export {
  extractMeta,
  extractTypes,
  extractCalls,
  extractImports,
  extractExports,
  buildCFG,
  buildDFG,
} from './extractors/index.js';
