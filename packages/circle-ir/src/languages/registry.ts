/**
 * Language Plugin Registry
 *
 * Manages registration and lookup of language plugins.
 */

import type {
  LanguagePlugin,
  LanguageRegistry,
  SupportedLanguage,
} from './types.js';

/**
 * Default language registry implementation
 */
class DefaultLanguageRegistry implements LanguageRegistry {
  private plugins: Map<SupportedLanguage, LanguagePlugin> = new Map();
  private extensionMap: Map<string, LanguagePlugin> = new Map();

  register(plugin: LanguagePlugin): void {
    this.plugins.set(plugin.id, plugin);

    // Map extensions to plugin
    for (const ext of plugin.extensions) {
      const normalizedExt = ext.startsWith('.') ? ext : `.${ext}`;
      this.extensionMap.set(normalizedExt, plugin);
    }
  }

  get(language: SupportedLanguage): LanguagePlugin | undefined {
    return this.plugins.get(language);
  }

  getForFile(filePath: string): LanguagePlugin | undefined {
    // Extract extension
    const lastDot = filePath.lastIndexOf('.');
    if (lastDot === -1) return undefined;

    const ext = filePath.substring(lastDot).toLowerCase();
    return this.extensionMap.get(ext);
  }

  getAll(): LanguagePlugin[] {
    return Array.from(this.plugins.values());
  }

  getSupportedLanguages(): SupportedLanguage[] {
    return Array.from(this.plugins.keys());
  }
}

// Singleton registry instance
let globalRegistry: LanguageRegistry | null = null;

/**
 * Get the global language registry
 */
export function getLanguageRegistry(): LanguageRegistry {
  if (!globalRegistry) {
    globalRegistry = new DefaultLanguageRegistry();
  }
  return globalRegistry;
}

/**
 * Register a language plugin in the global registry
 */
export function registerLanguage(plugin: LanguagePlugin): void {
  getLanguageRegistry().register(plugin);
}

/**
 * Get a language plugin by language ID
 */
export function getLanguagePlugin(language: SupportedLanguage): LanguagePlugin | undefined {
  return getLanguageRegistry().get(language);
}

/**
 * Get a language plugin for a file path
 */
export function getLanguageForFile(filePath: string): LanguagePlugin | undefined {
  return getLanguageRegistry().getForFile(filePath);
}

/**
 * Detect language from file path
 */
export function detectLanguage(filePath: string): SupportedLanguage | undefined {
  const plugin = getLanguageForFile(filePath);
  return plugin?.id;
}

/**
 * Check if a language is supported
 */
export function isLanguageSupported(language: string): language is SupportedLanguage {
  return getLanguageRegistry().getSupportedLanguages().includes(language as SupportedLanguage);
}
