/**
 * Language Plugin System
 *
 * Provides multi-language support through a plugin architecture.
 * Each language (Java, JavaScript, Python, Rust, Bash, HTML) has its own plugin
 * that handles AST node types, taint patterns, and framework detection.
 */

// Type definitions
export type {
  SupportedLanguage,
  LanguageNodeTypes,
  LanguagePlugin,
  LanguageRegistry,
  ExtractionContext,
  FrameworkInfo,
  TaintSourcePattern,
  TaintSinkPattern,
} from './types.js';

// Registry functions
export {
  getLanguageRegistry,
  registerLanguage,
  getLanguagePlugin,
  getLanguageForFile,
  detectLanguage,
  isLanguageSupported,
} from './registry.js';

// Concrete plugins
export {
  JavaPlugin,
  JavaScriptPlugin,
  PythonPlugin,
  RustPlugin,
  HtmlPlugin,
  registerBuiltinPlugins,
} from './plugins/index.js';

// Base class for custom plugins
export { BaseLanguagePlugin } from './plugins/base.js';
