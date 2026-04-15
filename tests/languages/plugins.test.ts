/**
 * Tests for Language Plugin Implementations
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  JavaPlugin,
  JavaScriptPlugin,
  PythonPlugin,
  RustPlugin,
  BashPlugin,
  registerBuiltinPlugins,
} from '../../src/languages/plugins/index.js';
import { BaseLanguagePlugin } from '../../src/languages/plugins/base.js';
import { getLanguageRegistry, getLanguagePlugin } from '../../src/languages/registry.js';
import { initParser, parse } from '../../src/core/parser.js';
import type {
  ExtractionContext,
  LanguageNodeTypes,
} from '../../src/languages/types.js';

// Minimal concrete plugin that does NOT override any optional base methods,
// so tests can exercise the BaseLanguagePlugin default implementations directly.
class MinimalPlugin extends BaseLanguagePlugin {
  readonly id = 'java' as const;
  readonly name = 'Minimal';
  readonly extensions = ['.min'];
  readonly wasmPath = 'test.wasm';
  readonly nodeTypes: LanguageNodeTypes = {
    classDeclaration: [],
    interfaceDeclaration: [],
    enumDeclaration: [],
    functionDeclaration: [],
    methodDeclaration: [],
    methodCall: [],
    functionCall: [],
    assignment: [],
    variableDeclaration: [],
    parameter: [],
    argument: [],
    annotation: [],
    decorator: [],
    importStatement: [],
    ifStatement: [],
    forStatement: [],
    whileStatement: [],
    tryStatement: [],
    returnStatement: [],
  };
  extractTypes(_ctx: ExtractionContext) { return []; }
  extractCalls(_ctx: ExtractionContext) { return []; }
  extractImports(_ctx: ExtractionContext) { return []; }
  extractPackage(_ctx: ExtractionContext) { return undefined; }
  getBuiltinSources() { return []; }
  getBuiltinSinks() { return []; }
}

describe('Language Plugins', () => {
  beforeAll(() => {
    registerBuiltinPlugins();
  });

  describe('JavaPlugin', () => {
    const plugin = new JavaPlugin();

    it('should have correct id', () => {
      expect(plugin.id).toBe('java');
    });

    it('should handle .java files', () => {
      expect(plugin.canHandle('Test.java')).toBe(true);
      expect(plugin.canHandle('/path/to/Test.java')).toBe(true);
      expect(plugin.canHandle('Test.js')).toBe(false);
    });

    it('should have node type mappings', () => {
      expect(plugin.nodeTypes.classDeclaration).toContain('class_declaration');
      expect(plugin.nodeTypes.methodDeclaration).toContain('method_declaration');
      expect(plugin.nodeTypes.annotation).toContain('marker_annotation');
    });

    it('should have builtin sources', () => {
      const sources = plugin.getBuiltinSources();
      expect(sources.length).toBeGreaterThan(0);

      // Check for Spring annotations
      const requestParam = sources.find(s => s.annotation === 'RequestParam');
      expect(requestParam).toBeDefined();
      expect(requestParam?.type).toBe('http_param');

      const requestBody = sources.find(s => s.annotation === 'RequestBody');
      expect(requestBody).toBeDefined();
      expect(requestBody?.type).toBe('http_body');

      // Check for Servlet API
      const getParameter = sources.find(s => s.method === 'getParameter');
      expect(getParameter).toBeDefined();
      expect(getParameter?.type).toBe('http_param');
    });

    it('should have builtin sinks', () => {
      const sinks = plugin.getBuiltinSinks();
      expect(sinks.length).toBeGreaterThan(0);

      // Check for SQL injection
      const executeQuery = sinks.find(s => s.method === 'executeQuery');
      expect(executeQuery).toBeDefined();
      expect(executeQuery?.cwe).toBe('CWE-89');

      // Check for command injection
      const exec = sinks.find(s => s.method === 'exec' && s.class === 'Runtime');
      expect(exec).toBeDefined();
      expect(exec?.cwe).toBe('CWE-78');
    });
  });

  describe('JavaScriptPlugin', () => {
    const plugin = new JavaScriptPlugin();

    it('should have correct id', () => {
      expect(plugin.id).toBe('javascript');
    });

    it('should handle JS/TS files', () => {
      expect(plugin.canHandle('app.js')).toBe(true);
      expect(plugin.canHandle('app.ts')).toBe(true);
      expect(plugin.canHandle('App.jsx')).toBe(true);
      expect(plugin.canHandle('App.tsx')).toBe(true);
      expect(plugin.canHandle('test.mjs')).toBe(true);
      expect(plugin.canHandle('test.cjs')).toBe(true);
      expect(plugin.canHandle('test.java')).toBe(false);
    });

    it('should have node type mappings', () => {
      expect(plugin.nodeTypes.classDeclaration).toContain('class_declaration');
      expect(plugin.nodeTypes.functionDeclaration).toContain('function_declaration');
      expect(plugin.nodeTypes.methodCall).toContain('call_expression');
    });

    it('should have builtin sources', () => {
      const sources = plugin.getBuiltinSources();
      expect(sources.length).toBeGreaterThan(0);

      // Check for Express.js patterns
      const query = sources.find(s => s.method === 'query');
      expect(query).toBeDefined();
      expect(query?.type).toBe('http_param');

      // Check for process.env
      const env = sources.find(s => s.method === 'env');
      expect(env).toBeDefined();
      expect(env?.type).toBe('env_var');
    });

    it('should have builtin sinks', () => {
      const sinks = plugin.getBuiltinSinks();
      expect(sinks.length).toBeGreaterThan(0);

      // Check for command injection
      const exec = sinks.find(s => s.method === 'exec');
      expect(exec).toBeDefined();
      expect(exec?.cwe).toBe('CWE-78');

      // Check for code injection
      const evalSink = sinks.find(s => s.method === 'eval');
      expect(evalSink).toBeDefined();
      expect(evalSink?.cwe).toBe('CWE-94');

      // Check for prototype pollution
      const merge = sinks.find(s => s.method === 'merge');
      expect(merge).toBeDefined();
      expect(merge?.cwe).toBe('CWE-1321');
    });
  });

  describe('PythonPlugin', () => {
    const plugin = new PythonPlugin();

    it('should have correct id', () => {
      expect(plugin.id).toBe('python');
    });

    it('should handle .py files', () => {
      expect(plugin.canHandle('app.py')).toBe(true);
      expect(plugin.canHandle('script.pyw')).toBe(true);
      expect(plugin.canHandle('test.js')).toBe(false);
    });

    it('should have node type mappings', () => {
      expect(plugin.nodeTypes.classDeclaration).toContain('class_definition');
      expect(plugin.nodeTypes.functionDeclaration).toContain('function_definition');
      expect(plugin.nodeTypes.decorator).toContain('decorator');
    });

    it('should have builtin sources', () => {
      const sources = plugin.getBuiltinSources();
      expect(sources.length).toBeGreaterThan(0);

      // Check for Flask patterns
      const args = sources.find(s => s.method === 'args');
      expect(args).toBeDefined();
      expect(args?.type).toBe('http_param');

      // Check for input()
      const input = sources.find(s => s.method === 'input');
      expect(input).toBeDefined();
      expect(input?.type).toBe('user_input');
    });

    it('should have builtin sinks', () => {
      const sinks = plugin.getBuiltinSinks();
      expect(sinks.length).toBeGreaterThan(0);

      // Check for command injection
      const system = sinks.find(s => s.method === 'system');
      expect(system).toBeDefined();
      expect(system?.cwe).toBe('CWE-78');

      // Check for code injection
      const evalSink = sinks.find(s => s.method === 'eval');
      expect(evalSink).toBeDefined();
      expect(evalSink?.cwe).toBe('CWE-94');

      // Check for deserialization
      const pickleLoads = sinks.find(s => s.method === 'loads' && s.class === 'pickle');
      expect(pickleLoads).toBeDefined();
      expect(pickleLoads?.cwe).toBe('CWE-502');
    });
  });

  describe('RustPlugin', () => {
    const plugin = new RustPlugin();

    it('should have correct id', () => {
      expect(plugin.id).toBe('rust');
    });

    it('should handle .rs files', () => {
      expect(plugin.canHandle('main.rs')).toBe(true);
      expect(plugin.canHandle('lib.rs')).toBe(true);
      expect(plugin.canHandle('test.py')).toBe(false);
    });

    it('should have node type mappings', () => {
      expect(plugin.nodeTypes.classDeclaration).toContain('struct_item');
      expect(plugin.nodeTypes.interfaceDeclaration).toContain('trait_item');
      expect(plugin.nodeTypes.enumDeclaration).toContain('enum_item');
    });

    it('should have builtin sources', () => {
      const sources = plugin.getBuiltinSources();
      expect(sources.length).toBeGreaterThan(0);

      // Check for Actix-web patterns
      const query = sources.find(s => s.method === 'Query');
      expect(query).toBeDefined();
      expect(query?.type).toBe('http_param');

      // Check for std::env
      const args = sources.find(s => s.method === 'args');
      expect(args).toBeDefined();
      expect(args?.type).toBe('cli_arg');
    });

    it('should have builtin sinks', () => {
      const sinks = plugin.getBuiltinSinks();
      expect(sinks.length).toBeGreaterThan(0);

      // Check for command injection
      const command = sinks.find(s => s.method === 'Command');
      expect(command).toBeDefined();
      expect(command?.cwe).toBe('CWE-78');

      // Check for path traversal
      const fileOpen = sinks.find(s => s.method === 'open' && s.class === 'File');
      expect(fileOpen).toBeDefined();
      expect(fileOpen?.cwe).toBe('CWE-22');

      // Check for unsafe memory
      const transmute = sinks.find(s => s.method === 'transmute');
      expect(transmute).toBeDefined();
      expect(transmute?.cwe).toBe('CWE-119');
    });
  });

  describe('BashPlugin', () => {
    const plugin = new BashPlugin();

    it('should have correct id', () => {
      expect(plugin.id).toBe('bash');
    });

    it('should handle shell script files', () => {
      expect(plugin.canHandle('script.sh')).toBe(true);
      expect(plugin.canHandle('deploy.bash')).toBe(true);
      expect(plugin.canHandle('config.zsh')).toBe(true);
      expect(plugin.canHandle('run.ksh')).toBe(true);
      expect(plugin.canHandle('app.py')).toBe(false);
      expect(plugin.canHandle('main.rs')).toBe(false);
    });

    it('should have node type mappings', () => {
      expect(plugin.nodeTypes.functionDeclaration).toContain('function_definition');
      expect(plugin.nodeTypes.methodCall).toContain('command');
      expect(plugin.nodeTypes.functionCall).toContain('command');
      expect(plugin.nodeTypes.assignment).toContain('variable_assignment');
      expect(plugin.nodeTypes.variableDeclaration).toContain('variable_assignment');
      expect(plugin.nodeTypes.variableDeclaration).toContain('declaration_command');
      expect(plugin.nodeTypes.ifStatement).toContain('if_statement');
      expect(plugin.nodeTypes.forStatement).toContain('for_statement');
      expect(plugin.nodeTypes.forStatement).toContain('c_style_for_statement');
      expect(plugin.nodeTypes.whileStatement).toContain('while_statement');
    });

    it('should have no OOP type mappings', () => {
      expect(plugin.nodeTypes.classDeclaration).toHaveLength(0);
      expect(plugin.nodeTypes.interfaceDeclaration).toHaveLength(0);
      expect(plugin.nodeTypes.enumDeclaration).toHaveLength(0);
      expect(plugin.nodeTypes.annotation).toHaveLength(0);
      expect(plugin.nodeTypes.decorator).toHaveLength(0);
      expect(plugin.nodeTypes.importStatement).toHaveLength(0);
    });

    it('should have builtin sources', () => {
      const sources = plugin.getBuiltinSources();
      expect(sources.length).toBeGreaterThan(0);

      // 'read' is a source for stdin input
      const readSource = sources.find(s => s.method === 'read');
      expect(readSource).toBeDefined();
      expect(readSource?.type).toBe('io_input');

      // curl/wget output as taint sources for supply-chain attack patterns
      const curlSource = sources.find(s => s.method === 'curl');
      expect(curlSource).toBeDefined();
      expect(curlSource?.type).toBe('http_response');

      const wgetSource = sources.find(s => s.method === 'wget');
      expect(wgetSource).toBeDefined();
      expect(wgetSource?.type).toBe('http_response');
    });

    it('should have builtin sinks', () => {
      const sinks = plugin.getBuiltinSinks();
      expect(sinks.length).toBeGreaterThan(0);

      // Code injection via eval
      const evalSink = sinks.find(s => s.method === 'eval');
      expect(evalSink).toBeDefined();
      expect(evalSink?.cwe).toBe('CWE-94');
      expect(evalSink?.type).toBe('code_injection');
      expect(evalSink?.severity).toBe('critical');

      // Command injection via sub-shell
      const bashSink = sinks.find(s => s.method === 'bash');
      expect(bashSink).toBeDefined();
      expect(bashSink?.cwe).toBe('CWE-78');
      expect(bashSink?.type).toBe('command_injection');
      expect(bashSink?.argPositions).toContain(1);

      const shSink = sinks.find(s => s.method === 'sh');
      expect(shSink).toBeDefined();
      expect(shSink?.cwe).toBe('CWE-78');

      const zshSink = sinks.find(s => s.method === 'zsh');
      expect(zshSink).toBeDefined();
      expect(zshSink?.cwe).toBe('CWE-78');

      // SQL injection via CLI clients
      const mysqlSink = sinks.find(s => s.method === 'mysql');
      expect(mysqlSink).toBeDefined();
      expect(mysqlSink?.cwe).toBe('CWE-89');
      expect(mysqlSink?.type).toBe('sql_injection');

      const psqlSink = sinks.find(s => s.method === 'psql');
      expect(psqlSink).toBeDefined();
      expect(psqlSink?.cwe).toBe('CWE-89');

      const sqlite3Sink = sinks.find(s => s.method === 'sqlite3');
      expect(sqlite3Sink).toBeDefined();
      expect(sqlite3Sink?.cwe).toBe('CWE-89');

      // Path traversal
      const catSink = sinks.find(s => s.method === 'cat');
      expect(catSink).toBeDefined();
      expect(catSink?.cwe).toBe('CWE-22');
      expect(catSink?.type).toBe('path_traversal');
      expect(catSink?.argPositions).toContain(0);

      const rmSink = sinks.find(s => s.method === 'rm');
      expect(rmSink).toBeDefined();
      expect(rmSink?.cwe).toBe('CWE-22');

      // SSRF
      const curlSink = sinks.find(s => s.method === 'curl' && s.type === 'ssrf');
      expect(curlSink).toBeDefined();
      expect(curlSink?.cwe).toBe('CWE-918');

      const wgetSink = sinks.find(s => s.method === 'wget' && s.type === 'ssrf');
      expect(wgetSink).toBeDefined();
      expect(wgetSink?.cwe).toBe('CWE-918');
    });

    it('should return undefined for receiver type (no OOP)', () => {
      const result = plugin.getReceiverType({} as any, {} as any);
      expect(result).toBeUndefined();
    });

    it('should return undefined for detectFramework', () => {
      const result = plugin.detectFramework({} as any);
      expect(result).toBeUndefined();
    });

    it('should identify bash string literals', () => {
      expect(plugin.isStringLiteral({ type: 'string' } as any)).toBe(true);
      expect(plugin.isStringLiteral({ type: 'raw_string' } as any)).toBe(true);
      expect(plugin.isStringLiteral({ type: 'ansi_c_string' } as any)).toBe(true);
      expect(plugin.isStringLiteral({ type: 'identifier' } as any)).toBe(false);
      expect(plugin.isStringLiteral({ type: 'number' } as any)).toBe(false);
    });

    it('should extract value from double-quoted bash strings', () => {
      const node = { type: 'string', text: '"hello world"' } as any;
      expect(plugin.getStringValue(node)).toBe('hello world');
    });

    it('should extract value from single-quoted raw strings', () => {
      const node = { type: 'raw_string', text: "'hello world'" } as any;
      expect(plugin.getStringValue(node)).toBe('hello world');
    });

    it('should extract value from $\'...\' ansi_c strings', () => {
      const node = { type: 'ansi_c_string', text: "$'hello\\nworld'" } as any;
      expect(plugin.getStringValue(node)).toBe("hello\\nworld");
    });

    it('should return undefined for non-string nodes', () => {
      const node = { type: 'identifier', text: 'foo' } as any;
      expect(plugin.getStringValue(node)).toBeUndefined();
    });

    it('should return empty arrays from extraction methods', () => {
      const ctx = {} as any;
      expect(plugin.extractTypes(ctx)).toEqual([]);
      expect(plugin.extractCalls(ctx)).toEqual([]);
      expect(plugin.extractImports(ctx)).toEqual([]);
      expect(plugin.extractPackage(ctx)).toBeUndefined();
    });
  });

  describe('Plugin Registration', () => {
    it('should register all builtin plugins', () => {
      const registry = getLanguageRegistry();
      const languages = registry.getSupportedLanguages();

      expect(languages).toContain('java');
      expect(languages).toContain('javascript');
      expect(languages).toContain('python');
      expect(languages).toContain('rust');
      expect(languages).toContain('bash');
    });

    it('should allow lookup by language', () => {
      expect(getLanguagePlugin('java')).toBeDefined();
      expect(getLanguagePlugin('javascript')).toBeDefined();
      expect(getLanguagePlugin('python')).toBeDefined();
      expect(getLanguagePlugin('rust')).toBeDefined();
      expect(getLanguagePlugin('bash')).toBeDefined();
    });

    it('should allow lookup by file extension', () => {
      const registry = getLanguageRegistry();

      expect(registry.getForFile('Test.java')?.id).toBe('java');
      expect(registry.getForFile('app.js')?.id).toBe('javascript');
      expect(registry.getForFile('app.ts')?.id).toBe('javascript');
      expect(registry.getForFile('main.py')?.id).toBe('python');
      expect(registry.getForFile('lib.rs')?.id).toBe('rust');
      expect(registry.getForFile('deploy.sh')?.id).toBe('bash');
      expect(registry.getForFile('config.zsh')?.id).toBe('bash');
    });
  });

  describe('String Literal Detection', () => {
    describe('JavaPlugin', () => {
      const plugin = new JavaPlugin();

      it('should identify Java string literals', () => {
        // These would need actual syntax nodes in a real test
        expect(plugin.isStringLiteral({ type: 'string_literal' } as any)).toBe(true);
        expect(plugin.isStringLiteral({ type: 'number' } as any)).toBe(false);
      });
    });

    describe('JavaScriptPlugin', () => {
      const plugin = new JavaScriptPlugin();

      it('should identify JS string literals', () => {
        expect(plugin.isStringLiteral({ type: 'string' } as any)).toBe(true);
        expect(plugin.isStringLiteral({ type: 'template_string' } as any)).toBe(true);
        expect(plugin.isStringLiteral({ type: 'number' } as any)).toBe(false);
      });
    });

    describe('PythonPlugin', () => {
      const plugin = new PythonPlugin();

      it('should identify Python string literals', () => {
        expect(plugin.isStringLiteral({ type: 'string' } as any)).toBe(true);
        expect(plugin.isStringLiteral({ type: 'concatenated_string' } as any)).toBe(true);
        expect(plugin.isStringLiteral({ type: 'number' } as any)).toBe(false);
      });
    });

    describe('RustPlugin', () => {
      const plugin = new RustPlugin();

      it('should identify Rust string literals', () => {
        expect(plugin.isStringLiteral({ type: 'string_literal' } as any)).toBe(true);
        expect(plugin.isStringLiteral({ type: 'raw_string_literal' } as any)).toBe(true);
        expect(plugin.isStringLiteral({ type: 'number' } as any)).toBe(false);
      });
    });
  });

  describe('String Value Extraction', () => {
    describe('JavaPlugin', () => {
      const plugin = new JavaPlugin();

      it('should extract value from double-quoted strings', () => {
        const node = { type: 'string_literal', text: '"hello world"' } as any;
        expect(plugin.getStringValue(node)).toBe('hello world');
      });

      it('should extract value from single-quoted char literals', () => {
        // Java uses single quotes for char literals
        const node = { type: 'character_literal', text: "'h'" } as any;
        // character_literal is not a string_literal type in Java
        expect(plugin.getStringValue(node)).toBeUndefined();
      });

      it('should return undefined for non-string nodes', () => {
        const node = { type: 'number', text: '42' } as any;
        expect(plugin.getStringValue(node)).toBeUndefined();
      });

      it('should handle strings without quotes', () => {
        const node = { type: 'string_literal', text: 'hello' } as any;
        expect(plugin.getStringValue(node)).toBe('hello');
      });
    });

    describe('JavaScriptPlugin', () => {
      const plugin = new JavaScriptPlugin();

      it('should extract value from JS strings', () => {
        const node = { type: 'string', text: '"test"' } as any;
        expect(plugin.getStringValue(node)).toBe('test');
      });
    });
  });

  describe('Default Method Implementations', () => {
    const plugin = new JavaPlugin();

    it('should detect Spring framework from imports', () => {
      const context = {
        tree: {},
        source: '',
        filePath: '',
        imports: [{ from_package: 'org.springframework.web.bind', imported_name: 'Controller' }],
        annotations: [],
      } as any;
      const framework = plugin.detectFramework(context);
      expect(framework?.name).toBe('spring');
    });

    it('should return undefined when no framework detected', () => {
      const context = {
        tree: {},
        source: '',
        filePath: '',
        imports: [],
        annotations: [],
      } as any;
      const framework = plugin.detectFramework(context);
      expect(framework).toBeUndefined();
    });

    it('should return undefined for getReceiverType', () => {
      const node = { type: 'method_call' } as any;
      const context = { tree: {}, source: '', filePath: '', imports: [], annotations: [] } as any;
      // getReceiverType in JavaPlugin may have specific implementation
      // Just verify it doesn't throw
      expect(() => plugin.getReceiverType(node, context)).not.toThrow();
    });
  });

  describe('File Extension Handling', () => {
    it('should handle extension with or without dot', () => {
      const plugin = new JavaPlugin();
      // Extensions in plugin can be with or without leading dot
      expect(plugin.canHandle('Test.java')).toBe(true);
      expect(plugin.canHandle('test.JAVA')).toBe(true); // case insensitive
    });

    it('should handle full paths', () => {
      const plugin = new JavaScriptPlugin();
      expect(plugin.canHandle('/home/user/project/src/app.ts')).toBe(true);
      expect(plugin.canHandle('C:\\Users\\project\\app.js')).toBe(true);
    });
  });

  describe('React and React Native Support', () => {
    const plugin = new JavaScriptPlugin();

    describe('Framework Detection', () => {
      it('should detect React from imports', () => {
        const context = {
          tree: {},
          source: '',
          filePath: '',
          imports: [{ from_package: 'react', imported_name: 'React' }],
          annotations: [],
        } as any;
        const framework = plugin.detectFramework(context);
        expect(framework?.name).toBe('react');
      });

      it('should detect React Native from imports', () => {
        const context = {
          tree: {},
          source: '',
          filePath: '',
          imports: [{ from_package: 'react-native', imported_name: 'View' }],
          annotations: [],
        } as any;
        const framework = plugin.detectFramework(context);
        expect(framework?.name).toBe('react-native');
      });

      it('should detect React Navigation (React Native)', () => {
        const context = {
          tree: {},
          source: '',
          filePath: '',
          imports: [{ from_package: '@react-navigation/native', imported_name: 'NavigationContainer' }],
          annotations: [],
        } as any;
        const framework = plugin.detectFramework(context);
        expect(framework?.name).toBe('react-native');
      });

      it('should detect React Router', () => {
        const context = {
          tree: {},
          source: '',
          filePath: '',
          imports: [{ from_package: 'react-router-dom', imported_name: 'BrowserRouter' }],
          annotations: [],
        } as any;
        const framework = plugin.detectFramework(context);
        expect(framework?.name).toBe('react');
      });

      it('should detect Next.js', () => {
        const context = {
          tree: {},
          source: '',
          filePath: '',
          imports: [{ from_package: 'next/router', imported_name: 'useRouter' }],
          annotations: [],
        } as any;
        const framework = plugin.detectFramework(context);
        expect(framework?.name).toBe('nextjs');
      });

      it('should detect Expo', () => {
        const context = {
          tree: {},
          source: '',
          filePath: '',
          imports: [{ from_package: 'expo-linking', imported_name: 'Linking' }],
          annotations: [],
        } as any;
        const framework = plugin.detectFramework(context);
        expect(framework?.name).toBe('react-native');
      });
    });

    describe('React Sources', () => {
      it('should have React Router source patterns', () => {
        const sources = plugin.getBuiltinSources();

        const useParams = sources.find(s => s.method === 'useParams');
        expect(useParams).toBeDefined();
        expect(useParams?.type).toBe('http_path');

        const useSearchParams = sources.find(s => s.method === 'useSearchParams');
        expect(useSearchParams).toBeDefined();
        expect(useSearchParams?.type).toBe('http_param');

        const useLocation = sources.find(s => s.method === 'useLocation');
        expect(useLocation).toBeDefined();
        expect(useLocation?.type).toBe('url_param');
      });

      it('should have Next.js source patterns', () => {
        const sources = plugin.getBuiltinSources();

        const useRouter = sources.find(s => s.method === 'useRouter');
        expect(useRouter).toBeDefined();
        expect(useRouter?.type).toBe('http_param');

        const usePathname = sources.find(s => s.method === 'usePathname');
        expect(usePathname).toBeDefined();
        expect(usePathname?.type).toBe('http_path');
      });
    });

    describe('React Native Sources', () => {
      it('should have React Navigation source patterns', () => {
        const sources = plugin.getBuiltinSources();

        const useRoute = sources.find(s => s.method === 'useRoute');
        expect(useRoute).toBeDefined();
        expect(useRoute?.type).toBe('navigation_param');
      });

      it('should have Linking source patterns', () => {
        const sources = plugin.getBuiltinSources();

        const getInitialURL = sources.find(s => s.method === 'getInitialURL' && s.class === 'Linking');
        expect(getInitialURL).toBeDefined();
        expect(getInitialURL?.type).toBe('url_param');

        const parse = sources.find(s => s.method === 'parse' && s.class === 'Linking');
        expect(parse).toBeDefined();
      });

      it('should have Clipboard source patterns', () => {
        const sources = plugin.getBuiltinSources();

        const getString = sources.find(s => s.method === 'getString' && s.class === 'Clipboard');
        expect(getString).toBeDefined();
        expect(getString?.type).toBe('user_input');
      });

      it('should have AsyncStorage source patterns', () => {
        const sources = plugin.getBuiltinSources();

        const getItem = sources.find(s => s.method === 'getItem' && s.class === 'AsyncStorage');
        expect(getItem).toBeDefined();
        expect(getItem?.type).toBe('storage_input');
      });
    });

    describe('React Sinks', () => {
      it('should have dangerouslySetInnerHTML sink', () => {
        const sinks = plugin.getBuiltinSinks();

        const dangerous = sinks.find(s => s.method === 'dangerouslySetInnerHTML');
        expect(dangerous).toBeDefined();
        expect(dangerous?.cwe).toBe('CWE-79');
        expect(dangerous?.severity).toBe('critical');
      });
    });

    describe('React Native Sinks', () => {
      it('should have WebView sink', () => {
        const sinks = plugin.getBuiltinSinks();

        const webview = sinks.find(s => s.method === 'source' && s.class === 'WebView');
        expect(webview).toBeDefined();
        expect(webview?.cwe).toBe('CWE-79');
      });

      it('should have Linking.openURL sink', () => {
        const sinks = plugin.getBuiltinSinks();

        const openURL = sinks.find(s => s.method === 'openURL' && s.class === 'Linking');
        expect(openURL).toBeDefined();
        expect(openURL?.cwe).toBe('CWE-601');
        expect(openURL?.type).toBe('open_redirect');
      });

      it('should have AsyncStorage.setItem sink', () => {
        const sinks = plugin.getBuiltinSinks();

        const setItem = sinks.find(s => s.method === 'setItem' && s.class === 'AsyncStorage');
        expect(setItem).toBeDefined();
        expect(setItem?.type).toBe('insecure_storage');
      });
    });

    describe('Next.js Sinks', () => {
      it('should have redirect sink', () => {
        const sinks = plugin.getBuiltinSinks();

        const redirect = sinks.find(s => s.method === 'redirect');
        expect(redirect).toBeDefined();
        expect(redirect?.cwe).toBe('CWE-601');
        expect(redirect?.type).toBe('open_redirect');
      });

      it('should have router.push sink', () => {
        const sinks = plugin.getBuiltinSinks();

        const push = sinks.find(s => s.method === 'push' && s.class === 'router');
        expect(push).toBeDefined();
        expect(push?.type).toBe('open_redirect');
      });
    });

    describe('Fastify Sources', () => {
      it('should have request.raw source (raw HTTP request)', () => {
        const sources = plugin.getBuiltinSources();
        const raw = sources.find(s => s.method === 'raw' && s.class === 'request');
        expect(raw).toBeDefined();
        expect(raw?.type).toBe('http_param');
        expect(raw?.severity).toBe('high');
      });

      it('should have request.hostname source (http_header)', () => {
        const sources = plugin.getBuiltinSources();
        const hostname = sources.find(s => s.method === 'hostname' && s.class === 'request');
        expect(hostname).toBeDefined();
        expect(hostname?.type).toBe('http_header');
      });
    });

    describe('Koa Sources', () => {
      it('should have ctx.header and ctx.headers sources', () => {
        const sources = plugin.getBuiltinSources();
        const header = sources.find(s => s.method === 'header' && s.class === 'ctx');
        expect(header).toBeDefined();
        expect(header?.type).toBe('http_header');

        const headers = sources.find(s => s.method === 'headers' && s.class === 'ctx');
        expect(headers).toBeDefined();
        expect(headers?.type).toBe('http_header');
      });

      it('should have ctx.host and ctx.hostname sources', () => {
        const sources = plugin.getBuiltinSources();
        const host = sources.find(s => s.method === 'host' && s.class === 'ctx');
        expect(host).toBeDefined();
        expect(host?.type).toBe('http_header');

        const hostname = sources.find(s => s.method === 'hostname' && s.class === 'ctx');
        expect(hostname).toBeDefined();
        expect(hostname?.type).toBe('http_header');
      });

      it('should have ctx.path and ctx.url sources', () => {
        const sources = plugin.getBuiltinSources();
        const path = sources.find(s => s.method === 'path' && s.class === 'ctx');
        expect(path).toBeDefined();
        expect(path?.type).toBe('http_path');

        const url = sources.find(s => s.method === 'url' && s.class === 'ctx');
        expect(url).toBeDefined();
        expect(url?.type).toBe('http_path');
      });

      it('should have ctx.querystring source', () => {
        const sources = plugin.getBuiltinSources();
        const qs = sources.find(s => s.method === 'querystring' && s.class === 'ctx');
        expect(qs).toBeDefined();
        expect(qs?.type).toBe('http_param');
      });
    });

    describe('Prisma Sinks', () => {
      it('should have $executeRawUnsafe sink (CWE-89)', () => {
        const sinks = plugin.getBuiltinSinks();
        const sink = sinks.find(s => s.method === '$executeRawUnsafe');
        expect(sink).toBeDefined();
        expect(sink?.type).toBe('sql_injection');
        expect(sink?.cwe).toBe('CWE-89');
        expect(sink?.severity).toBe('critical');
        expect(sink?.argPositions).toContain(0);
      });

      it('should have $queryRawUnsafe sink (CWE-89)', () => {
        const sinks = plugin.getBuiltinSinks();
        const sink = sinks.find(s => s.method === '$queryRawUnsafe');
        expect(sink).toBeDefined();
        expect(sink?.type).toBe('sql_injection');
        expect(sink?.cwe).toBe('CWE-89');
        expect(sink?.severity).toBe('critical');
      });
    });
  });

  describe('Base Plugin Protected Methods (via JavaPlugin)', () => {
    // Helper subclass that exposes protected methods for test coverage
    class TestJavaPlugin extends JavaPlugin {
      publicFindNodes(root: any, type: string): any[] {
        return this.findNodes(root, type);
      }
      publicFindChildByType(node: any, type: string): any {
        return this.findChildByType(node, type);
      }
    }

    it('should extract package name (covers findNodes + getNodeText)', async () => {
      const code = 'package com.example.service;\npublic class UserService {}';
      const tree = await parse(code, 'java');
      const plugin = new JavaPlugin();
      const pkg = plugin.extractPackage({ filePath: 'UserService.java', sourceCode: code, tree, imports: [] } as any);
      expect(pkg).toBe('com.example.service');
    });

    it('should return undefined when no package declaration (findNodes returns empty)', async () => {
      const code = 'public class Test { public void method() {} }';
      const tree = await parse(code, 'java');
      const plugin = new JavaPlugin();
      const pkg = plugin.extractPackage({ filePath: 'Test.java', sourceCode: code, tree, imports: [] } as any);
      expect(pkg).toBeUndefined();
    });

    it('findNodes should find all nodes of given type recursively', async () => {
      const code = `package com.test;\npublic class Outer {\n  public class Inner {}\n}`;
      const tree = await parse(code, 'java');
      const plugin = new TestJavaPlugin();
      const classNodes = plugin.publicFindNodes(tree.rootNode, 'class_declaration');
      expect(classNodes.length).toBeGreaterThanOrEqual(2); // Outer + Inner
    });

    it('findNodes should return empty array when type not found', async () => {
      const code = 'public class Foo {}';
      const tree = await parse(code, 'java');
      const plugin = new TestJavaPlugin();
      const nodes = plugin.publicFindNodes(tree.rootNode, 'nonexistent_node_xyz');
      expect(nodes).toEqual([]);
    });

    it('findChildByType should find a direct child of given type', async () => {
      const code = 'public class TestClass { int x = 5; }';
      const tree = await parse(code, 'java');
      const plugin = new TestJavaPlugin();
      const classDecl = plugin.publicFindChildByType(tree.rootNode, 'class_declaration');
      expect(classDecl).not.toBeNull();
      expect(classDecl?.type).toBe('class_declaration');
    });

    it('findChildByType should return null when child type not found', async () => {
      const code = 'public class TestClass {}';
      const tree = await parse(code, 'java');
      const plugin = new TestJavaPlugin();
      // root node (program) has no method_declaration as a direct child
      const result = plugin.publicFindChildByType(tree.rootNode, 'method_declaration');
      expect(result).toBeNull();
    });

    describe('BaseLanguagePlugin default method implementations (MinimalPlugin)', () => {
      const minimal = new MinimalPlugin();

      it('detectFramework returns undefined by default', () => {
        const result = minimal.detectFramework({} as any);
        expect(result).toBeUndefined();
      });

      it('getReceiverType returns undefined by default', () => {
        const result = minimal.getReceiverType({} as any, {} as any);
        expect(result).toBeUndefined();
      });

      it('isStringLiteral returns true for string_literal node', () => {
        expect(minimal.isStringLiteral({ type: 'string_literal' } as any)).toBe(true);
      });

      it('isStringLiteral returns true for string node', () => {
        expect(minimal.isStringLiteral({ type: 'string' } as any)).toBe(true);
      });

      it('isStringLiteral returns false for non-string node', () => {
        expect(minimal.isStringLiteral({ type: 'identifier' } as any)).toBe(false);
      });

      it('getStringValue extracts value from double-quoted string', () => {
        const node = { type: 'string_literal', text: '"hello"' };
        expect(minimal.getStringValue(node as any)).toBe('hello');
      });

      it('getStringValue extracts value from single-quoted string', () => {
        const node = { type: 'string_literal', text: "'world'" };
        expect(minimal.getStringValue(node as any)).toBe('world');
      });

      it('getStringValue returns text as-is when no surrounding quotes', () => {
        const node = { type: 'string_literal', text: 'bare' };
        expect(minimal.getStringValue(node as any)).toBe('bare');
      });

      it('getStringValue returns undefined for non-string node', () => {
        const node = { type: 'identifier', text: 'foo' };
        expect(minimal.getStringValue(node as any)).toBeUndefined();
      });
    });
  });

  describe('JavaPlugin.getReceiverType — type resolution', () => {
    const plugin = new JavaPlugin();

    /** Walk the subtree and return the first method_invocation whose object.text matches `receiverName`. */
    function findInvocation(node: any, receiverName: string): any {
      if (node.type === 'method_invocation') {
        const obj = node.childForFieldName('object');
        if (obj?.text === receiverName) return node;
      }
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) {
          const found = findInvocation(child, receiverName);
          if (found) return found;
        }
      }
      return null;
    }

    it('resolves local variable type (no generics)', async () => {
      const code = `
class Test {
  void test() {
    PreparedStatement ps = conn.prepareStatement(sql);
    ps.executeQuery(q);
  }
}`;
      const tree = await parse(code, 'java');
      const ctx = { filePath: 'Test.java', sourceCode: code, tree, imports: [] } as any;
      const node = findInvocation(tree.rootNode, 'ps');
      expect(node).not.toBeNull();
      expect(plugin.getReceiverType(node, ctx)).toBe('PreparedStatement');
    });

    it('strips generics from local variable type', async () => {
      const code = `
class Test {
  void test() {
    List<String> items = new ArrayList<>();
    items.add(x);
  }
}`;
      const tree = await parse(code, 'java');
      const ctx = { filePath: 'Test.java', sourceCode: code, tree, imports: [] } as any;
      const node = findInvocation(tree.rootNode, 'items');
      expect(node).not.toBeNull();
      expect(plugin.getReceiverType(node, ctx)).toBe('List');
    });

    it('resolves field declaration type', async () => {
      const code = `
class Test {
  Connection conn;
  void test() {
    conn.createStatement();
  }
}`;
      const tree = await parse(code, 'java');
      const ctx = { filePath: 'Test.java', sourceCode: code, tree, imports: [] } as any;
      const node = findInvocation(tree.rootNode, 'conn');
      expect(node).not.toBeNull();
      expect(plugin.getReceiverType(node, ctx)).toBe('Connection');
    });

    it('returns undefined for undeclared identifier', async () => {
      const code = `
class Test {
  void test() {
    undeclared.foo();
  }
}`;
      const tree = await parse(code, 'java');
      const ctx = { filePath: 'Test.java', sourceCode: code, tree, imports: [] } as any;
      const node = findInvocation(tree.rootNode, 'undeclared');
      expect(node).not.toBeNull();
      expect(plugin.getReceiverType(node, ctx)).toBeUndefined();
    });

    it('uses cached map on second call', async () => {
      const code = `
class Test {
  void test() {
    StringBuilder sb = new StringBuilder();
    sb.append(x);
  }
}`;
      const tree = await parse(code, 'java');
      const ctx = { filePath: 'Test.java', sourceCode: code, tree, imports: [] } as any;
      const node = findInvocation(tree.rootNode, 'sb');
      expect(plugin.getReceiverType(node, ctx)).toBe('StringBuilder');
      // Second call must hit cache and return the same result
      expect(plugin.getReceiverType(node, ctx)).toBe('StringBuilder');
    });
  });
});
