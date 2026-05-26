/**
 * Browser entry point for Circle-IR
 *
 * This module provides a browser-compatible API for code analysis.
 */

import {
  initAnalyzer,
  analyze,
  analyzeForAPI,
  isAnalyzerInitialized,
  type AnalyzerOptions,
} from './analyzer.js';
import type { CircleIR, AnalysisResponse } from './types/index.js';
import type { SupportedLanguage } from './core/index.js';

export interface BrowserAnalyzerOptions extends AnalyzerOptions {
  /**
   * URL to the tree-sitter.wasm file, or a pre-compiled WebAssembly.Module.
   * String URL for browser usage, WebAssembly.Module for Cloudflare Workers.
   */
  wasmUrl: string | WebAssembly.Module;

  /**
   * URLs to language grammar WASM files, or pre-compiled WebAssembly.Modules.
   * String URLs for browser usage, WebAssembly.Modules for Cloudflare Workers.
   */
  languageUrls?: Partial<Record<SupportedLanguage, string | WebAssembly.Module>>;
}

/**
 * Initialize the analyzer for browser/worker usage.
 */
export async function init(options: BrowserAnalyzerOptions): Promise<void> {
  const initOptions: Parameters<typeof initAnalyzer>[0] = {
    taintConfig: options.taintConfig,
  };

  if (typeof options.wasmUrl === 'string') {
    initOptions.wasmPath = options.wasmUrl;
  } else {
    initOptions.wasmModule = options.wasmUrl;
  }

  if (options.languageUrls) {
    const paths: Partial<Record<SupportedLanguage, string>> = {};
    const modules: Partial<Record<SupportedLanguage, WebAssembly.Module>> = {};

    for (const [lang, value] of Object.entries(options.languageUrls)) {
      if (typeof value === 'string') {
        paths[lang as SupportedLanguage] = value;
      } else if (value) {
        modules[lang as SupportedLanguage] = value;
      }
    }

    if (Object.keys(paths).length > 0) initOptions.languagePaths = paths;
    if (Object.keys(modules).length > 0) initOptions.languageModules = modules;
  }

  await initAnalyzer(initOptions);
}

/**
 * Analyze source code and return full Circle-IR output.
 */
export async function analyzeCode(
  code: string,
  options: {
    filePath?: string;
    language?: SupportedLanguage;
  } = {}
): Promise<CircleIR> {
  const filePath = options.filePath ?? 'input.java';
  const language = options.language ?? 'java';

  if (!isAnalyzerInitialized()) {
    throw new Error('Analyzer not initialized. Call init() first.');
  }

  return analyze(code, filePath, language);
}

/**
 * Analyze source code and return simplified API response.
 */
export async function analyzeCodeForAPI(
  code: string,
  options: {
    filePath?: string;
    language?: SupportedLanguage;
  } = {}
): Promise<AnalysisResponse> {
  const filePath = options.filePath ?? 'input.java';
  const language = options.language ?? 'java';

  if (!isAnalyzerInitialized()) {
    throw new Error('Analyzer not initialized. Call init() first.');
  }

  return analyzeForAPI(code, filePath, language);
}

// Re-export types for convenience
export type {
  CircleIR,
  AnalysisResponse,
  Vulnerability,
  TaintSource,
  TaintSink,
  SupportedLanguage,
} from './index.js';
