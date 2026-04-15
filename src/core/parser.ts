/**
 * Tree-sitter parser initialization and utilities
 *
 * This module provides a universal parser that works in Node.js, browsers, and Workers.
 */

import { Parser, Language, Tree, Node } from 'web-tree-sitter';

// Lazy-loaded Node.js modules for WASM path resolution
// These are only used in Node.js environments, not in browsers
let nodeModules: {
  fileURLToPath: (url: string | URL) => string;
  dirname: (path: string) => string;
  join: (...paths: string[]) => string;
  existsSync: (path: string) => boolean;
} | null = null;

let moduleDir: string | null = null;

/**
 * Initialize Node.js modules for path resolution (lazy, only in Node.js)
 */
async function getNodeModules() {
  if (nodeModules) return nodeModules;

  try {
    // Use Function constructor to hide imports from bundlers
    const dynamicImport = new Function('m', 'return import(m)');
    const [urlMod, pathMod, fsMod] = await Promise.all([
      dynamicImport('url'),
      dynamicImport('path'),
      dynamicImport('fs'),
    ]);
    nodeModules = {
      fileURLToPath: urlMod.fileURLToPath,
      dirname: pathMod.dirname,
      join: pathMod.join,
      existsSync: fsMod.existsSync,
    };
    // Calculate module directory
    moduleDir = nodeModules.dirname(nodeModules.fileURLToPath(import.meta.url));
    return nodeModules;
  } catch {
    // Not in Node.js environment (browser/worker)
    return null;
  }
}

// Re-export types using the correct names
export { Language, Tree };
export type { Node };
// Create type alias for backward compatibility
export type SyntaxNode = Node;

export type SupportedLanguage = 'java' | 'c' | 'cpp' | 'javascript' | 'typescript' | 'python' | 'rust' | 'bash' | 'html';

interface ParserOptions {
  /**
   * Custom path/URL to the tree-sitter.wasm file.
   * In Node.js, defaults to the web-tree-sitter package location.
   * In browsers/workers, must be provided.
   */
  wasmPath?: string;

  /**
   * Pre-compiled WebAssembly.Module for tree-sitter.wasm.
   * Use this for Cloudflare Workers where dynamic WASM compilation is blocked.
   * Takes precedence over wasmPath when provided.
   */
  wasmModule?: WebAssembly.Module;

  /**
   * Custom paths/URLs to language grammar WASM files.
   * Key is the language name, value is the path/URL.
   */
  languagePaths?: Partial<Record<SupportedLanguage, string>>;

  /**
   * Pre-compiled WebAssembly.Module for language grammars.
   * Use this for Cloudflare Workers where dynamic WASM compilation is blocked.
   * Takes precedence over languagePaths when provided.
   */
  languageModules?: Partial<Record<SupportedLanguage, WebAssembly.Module>>;
}

let parserInitialized = false;
let parserInitializing: Promise<void> | null = null;
const loadedLanguages = new Map<SupportedLanguage, Language>();
const loadingLanguages = new Map<SupportedLanguage, Promise<Language>>();
let configuredLanguagePaths: Partial<Record<SupportedLanguage, string>> = {};
let configuredLanguageModules: Partial<Record<SupportedLanguage, WebAssembly.Module>> = {};

/**
 * Initialize the Tree-sitter parser runtime.
 * Must be called before parsing any code.
 * Thread-safe: handles concurrent initialization attempts.
 */
export async function initParser(options: ParserOptions = {}): Promise<void> {
  if (parserInitialized) {
    return;
  }

  // If already initializing, wait for that to complete
  if (parserInitializing) {
    return parserInitializing;
  }

  // Store language paths/modules for later use in loadLanguage
  if (options.languagePaths) {
    configuredLanguagePaths = options.languagePaths;
  }
  if (options.languageModules) {
    configuredLanguageModules = options.languageModules;
  }

  // Create initialization promise and store it
  parserInitializing = (async () => {
    if (options.wasmModule) {
      // Use pre-compiled module (for Cloudflare Workers where dynamic WASM compilation is blocked)
      // instantiateWasm bypasses emscripten's default WebAssembly.instantiate(bytes) path
      await Parser.init({
        locateFile: () => 'web-tree-sitter.wasm',
        instantiateWasm(imports: WebAssembly.Imports, callback: (instance: WebAssembly.Instance, module?: WebAssembly.Module) => void) {
          const instance = new WebAssembly.Instance(options.wasmModule!, imports);
          // Emscripten's receiveInstance expects (instance, module) for getDylinkMetadata
          callback(instance, options.wasmModule!);
          return instance.exports;
        },
      });

    } else {
      const wasmPath = options.wasmPath ?? await getDefaultWasmPath();
      await Parser.init({
        locateFile: () => wasmPath,
      });
    }
    parserInitialized = true;
    parserInitializing = null;
  })();

  return parserInitializing;
}

/**
 * Load a language grammar for parsing.
 * Thread-safe: handles concurrent load attempts for the same language.
 */
export async function loadLanguage(
  language: SupportedLanguage,
  wasmPath?: string
): Promise<Language> {
  if (!parserInitialized) {
    throw new Error('Parser not initialized. Call initParser() first.');
  }

  // Check cache first
  const cached = loadedLanguages.get(language);
  if (cached) {
    return cached;
  }

  // If already loading this language, wait for that to complete
  const loading = loadingLanguages.get(language);
  if (loading) {
    return loading;
  }

  // Check for pre-compiled module first (Cloudflare Workers)
  const grammarName = language === 'typescript' ? 'javascript' : language;
  const wasmModule = configuredLanguageModules[language] ?? configuredLanguageModules[grammarName as SupportedLanguage];
  if (wasmModule) {
    const loadPromise = (async () => {
      // Pass WebAssembly.Module directly - web-tree-sitter's internal code
      // handles this via `binary instanceof WebAssembly.Module` check
      const lang = await Language.load(wasmModule as unknown as Uint8Array);
      loadedLanguages.set(language, lang);
      return lang;
    })();
    loadingLanguages.set(language, loadPromise);
    return loadPromise;
  }

  // Use explicit wasmPath, configured languagePaths, or default
  const path = wasmPath ?? configuredLanguagePaths[language] ?? await getDefaultLanguagePath(language);

  // Create loading promise and store it
  const loadPromise = (async () => {
    const lang = await Language.load(path);
    loadedLanguages.set(language, lang);
    loadingLanguages.delete(language);
    return lang;
  })();

  loadingLanguages.set(language, loadPromise);

  return loadPromise;
}

/**
 * Create a new parser instance configured for the specified language.
 */
export async function createParser(language: SupportedLanguage): Promise<Parser> {
  const lang = await loadLanguage(language);
  const parser = new Parser();
  parser.setLanguage(lang);
  return parser;
}

/**
 * Parse source code and return the syntax tree.
 */
export async function parse(
  code: string,
  language: SupportedLanguage
): Promise<Tree> {
  const parser = await createParser(language);
  const tree = parser.parse(code);
  if (!tree) {
    throw new Error('Failed to parse code');
  }
  return tree;
}

/**
 * Walk the syntax tree and call the visitor for each node.
 */
export function walkTree(
  node: Node,
  visitor: (node: Node) => void
): void {
  visitor(node);
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) {
      walkTree(child, visitor);
    }
  }
}

/**
 * Find all nodes of a specific type in the tree.
 */
export function findNodes(node: Node, type: string): Node[] {
  const results: Node[] = [];
  walkTree(node, (n) => {
    if (n.type === type) {
      results.push(n);
    }
  });
  return results;
}

/**
 * Cached node collection from a single tree traversal.
 * Use this to avoid multiple traversals of the same tree.
 */
export type NodeCache = Map<string, Node[]>;

/**
 * Collect all nodes of specified types in a single tree traversal.
 * Much more efficient than calling findNodes multiple times.
 */
export function collectAllNodes(node: Node, types: Set<string>): NodeCache {
  const cache: NodeCache = new Map();
  for (const type of types) {
    cache.set(type, []);
  }

  walkTree(node, (n) => {
    if (types.has(n.type)) {
      cache.get(n.type)!.push(n);
    }
  });

  return cache;
}

/**
 * Get nodes from cache, falling back to findNodes if not cached.
 */
export function getNodesFromCache(node: Node, type: string, cache?: NodeCache): Node[] {
  if (cache?.has(type)) {
    return cache.get(type)!;
  }
  return findNodes(node, type);
}

/**
 * Find the first ancestor of a node that matches the given type.
 */
export function findAncestor(node: Node, type: string): Node | null {
  let current = node.parent;
  while (current) {
    if (current.type === type) {
      return current;
    }
    current = current.parent;
  }
  return null;
}

/**
 * Get the text of a node from the source code.
 */
export function getNodeText(node: Node): string {
  return node.text;
}

/**
 * Get default WASM path for the Tree-sitter runtime.
 * This is environment-specific and may need to be overridden.
 */
async function getDefaultWasmPath(): Promise<string> {
  const mods = await getNodeModules();

  if (mods && moduleDir) {
    // In Node.js, resolve relative to this module's location
    // This works whether circle-ir is in node_modules or run from source
    const packageRoot = mods.join(moduleDir, '..', '..');

    // First, try the package's own dist/wasm/ directory (shipped with npm package).
    // This is the most reliable location when circle-ir is installed as a dependency,
    // since it doesn't depend on node_modules hoisting structure.
    const distWasmPath = mods.join(packageRoot, 'dist', 'wasm', 'web-tree-sitter.wasm');
    if (mods.existsSync(distWasmPath)) {
      return distWasmPath;
    }

    // Then try the package's node_modules (installed package)
    const packageNodeModulesPath = mods.join(packageRoot, 'node_modules', 'web-tree-sitter', 'web-tree-sitter.wasm');
    if (mods.existsSync(packageNodeModulesPath)) {
      return packageNodeModulesPath;
    }
  }

  // Fallback to CWD node_modules (development or browser)
  return 'node_modules/web-tree-sitter/web-tree-sitter.wasm';
}

/**
 * Get default path for a language grammar WASM file.
 */
async function getDefaultLanguagePath(language: SupportedLanguage): Promise<string> {
  // TypeScript uses the JavaScript grammar
  const grammarName = language === 'typescript' ? 'javascript' : language;

  const mods = await getNodeModules();

  if (mods && moduleDir) {
    // In Node.js, resolve relative to this module's location
    const packageRoot = mods.join(moduleDir, '..', '..');

    // First, try dist/wasm/ (shipped with npm package, works regardless of hoisting)
    const distWasmPath = mods.join(packageRoot, 'dist', 'wasm', `tree-sitter-${grammarName}.wasm`);
    if (mods.existsSync(distWasmPath)) {
      return distWasmPath;
    }

    // Then try the source wasm/ directory (development)
    const packageWasmPath = mods.join(packageRoot, 'wasm', `tree-sitter-${grammarName}.wasm`);
    if (mods.existsSync(packageWasmPath)) {
      return packageWasmPath;
    }
  }

  // Fallback to relative path (development or browser)
  return `wasm/tree-sitter-${grammarName}.wasm`;
}

/**
 * Check if the parser has been initialized.
 */
export function isInitialized(): boolean {
  return parserInitialized;
}

/**
 * Check if a language has been loaded.
 */
export function isLanguageLoaded(language: SupportedLanguage): boolean {
  return loadedLanguages.has(language);
}

/**
 * Reset the parser state (mainly for testing).
 */
export function resetParser(): void {
  parserInitialized = false;
  loadedLanguages.clear();
  configuredLanguagePaths = {};
}
