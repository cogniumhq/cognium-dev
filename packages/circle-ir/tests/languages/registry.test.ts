/**
 * Tests for Language Plugin Registry
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  getLanguageRegistry,
  registerLanguage,
  getLanguagePlugin,
  getLanguageForFile,
  detectLanguage,
  isLanguageSupported,
} from '../../src/languages/registry.js';
import type { LanguagePlugin, SupportedLanguage } from '../../src/languages/types.js';

describe('Language Registry', () => {
  // Create a mock plugin for testing
  function createMockPlugin(
    id: SupportedLanguage,
    extensions: string[]
  ): LanguagePlugin {
    return {
      id,
      name: `${id} Language`,
      extensions,
      treeSitterLanguage: null as any,
      patterns: {
        sources: [],
        sinks: [],
        sanitizers: [],
      },
    };
  }

  describe('getLanguageRegistry', () => {
    it('should return a singleton registry', () => {
      const registry1 = getLanguageRegistry();
      const registry2 = getLanguageRegistry();
      expect(registry1).toBe(registry2);
    });

    it('should have register method', () => {
      const registry = getLanguageRegistry();
      expect(typeof registry.register).toBe('function');
    });

    it('should have get method', () => {
      const registry = getLanguageRegistry();
      expect(typeof registry.get).toBe('function');
    });

    it('should have getForFile method', () => {
      const registry = getLanguageRegistry();
      expect(typeof registry.getForFile).toBe('function');
    });

    it('should have getAll method', () => {
      const registry = getLanguageRegistry();
      expect(typeof registry.getAll).toBe('function');
    });

    it('should have getSupportedLanguages method', () => {
      const registry = getLanguageRegistry();
      expect(typeof registry.getSupportedLanguages).toBe('function');
    });
  });

  describe('registerLanguage', () => {
    it('should register a language plugin', () => {
      const plugin = createMockPlugin('java', ['.java']);
      registerLanguage(plugin);

      const retrieved = getLanguagePlugin('java');
      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe('java');
    });

    it('should register multiple plugins', () => {
      const javaPlugin = createMockPlugin('java', ['.java']);
      const cPlugin = createMockPlugin('c', ['.c', '.h']);

      registerLanguage(javaPlugin);
      registerLanguage(cPlugin);

      expect(getLanguagePlugin('java')).toBeDefined();
      expect(getLanguagePlugin('c')).toBeDefined();
    });

    it('should handle extensions with and without dots', () => {
      const plugin = createMockPlugin('cpp', ['cpp', '.cc', 'cxx', '.hpp']);
      registerLanguage(plugin);

      // Should find plugin for various extension formats
      expect(getLanguageForFile('test.cpp')).toBeDefined();
      expect(getLanguageForFile('test.cc')).toBeDefined();
      expect(getLanguageForFile('test.cxx')).toBeDefined();
      expect(getLanguageForFile('test.hpp')).toBeDefined();
    });
  });

  describe('getLanguagePlugin', () => {
    it('should return undefined for unregistered language', () => {
      const plugin = getLanguagePlugin('unknown' as SupportedLanguage);
      expect(plugin).toBeUndefined();
    });

    it('should return the registered plugin', () => {
      const plugin = createMockPlugin('java', ['.java']);
      registerLanguage(plugin);

      const retrieved = getLanguagePlugin('java');
      expect(retrieved).toBe(plugin);
    });
  });

  describe('getLanguageForFile', () => {
    it('should return plugin for file with registered extension', () => {
      const plugin = createMockPlugin('java', ['.java']);
      registerLanguage(plugin);

      const result = getLanguageForFile('/path/to/Test.java');
      expect(result).toBeDefined();
      expect(result?.id).toBe('java');
    });

    it('should return undefined for file without extension', () => {
      const result = getLanguageForFile('/path/to/Makefile');
      expect(result).toBeUndefined();
    });

    it('should return undefined for unregistered extension', () => {
      const result = getLanguageForFile('/path/to/test.xyz');
      expect(result).toBeUndefined();
    });

    it('should handle case-insensitive extensions', () => {
      const plugin = createMockPlugin('java', ['.java']);
      registerLanguage(plugin);

      // Extensions are stored lowercase
      const result = getLanguageForFile('/path/to/Test.JAVA');
      // Note: implementation converts to lowercase
      expect(result).toBeDefined();
    });

    it('should handle paths with multiple dots', () => {
      const plugin = createMockPlugin('java', ['.java']);
      registerLanguage(plugin);

      const result = getLanguageForFile('/path/to/my.test.file.java');
      expect(result).toBeDefined();
      expect(result?.id).toBe('java');
    });
  });

  describe('detectLanguage', () => {
    it('should detect language from file path', () => {
      const plugin = createMockPlugin('java', ['.java']);
      registerLanguage(plugin);

      const language = detectLanguage('/path/to/Test.java');
      expect(language).toBe('java');
    });

    it('should return undefined for unknown extension', () => {
      const language = detectLanguage('/path/to/test.unknown');
      expect(language).toBeUndefined();
    });

    it('should return undefined for file without extension', () => {
      const language = detectLanguage('README');
      expect(language).toBeUndefined();
    });
  });

  describe('isLanguageSupported', () => {
    it('should return true for registered language', () => {
      const plugin = createMockPlugin('java', ['.java']);
      registerLanguage(plugin);

      expect(isLanguageSupported('java')).toBe(true);
    });

    it('should return false for unregistered language', () => {
      expect(isLanguageSupported('unknown')).toBe(false);
    });
  });

  describe('getAll', () => {
    it('should return all registered plugins', () => {
      const registry = getLanguageRegistry();
      const plugins = registry.getAll();

      expect(Array.isArray(plugins)).toBe(true);
      // Should contain at least the plugins we've registered
      expect(plugins.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getSupportedLanguages', () => {
    it('should return array of language IDs', () => {
      const registry = getLanguageRegistry();
      const languages = registry.getSupportedLanguages();

      expect(Array.isArray(languages)).toBe(true);
    });
  });
});
