/**
 * JavaScript/TypeScript Language Plugin
 *
 * Provides JS/TS-specific AST handling, taint patterns, and framework detection.
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type {
  TypeInfo,
  CallInfo,
  ImportInfo,
} from '../../types/index.js';
import type {
  LanguageNodeTypes,
  ExtractionContext,
  FrameworkInfo,
  TaintSourcePattern,
  TaintSinkPattern,
} from '../types.js';
import { BaseLanguagePlugin } from './base.js';

/**
 * JavaScript/TypeScript language plugin implementation.
 * Handles both JavaScript and TypeScript since they share the same tree-sitter grammar.
 */
export class JavaScriptPlugin extends BaseLanguagePlugin {
  readonly id = 'javascript' as const;
  readonly name = 'JavaScript/TypeScript';
  readonly extensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
  readonly wasmPath = 'tree-sitter-typescript.wasm';

  readonly nodeTypes: LanguageNodeTypes = {
    // Type declarations
    classDeclaration: ['class_declaration', 'class'],
    interfaceDeclaration: ['interface_declaration'],
    enumDeclaration: ['enum_declaration'],
    functionDeclaration: ['function_declaration', 'function', 'arrow_function'],
    methodDeclaration: ['method_definition'],

    // Expressions
    methodCall: ['call_expression'],
    functionCall: ['call_expression'],
    assignment: ['assignment_expression'],
    variableDeclaration: ['lexical_declaration', 'variable_declaration'],

    // Parameters and arguments
    parameter: ['formal_parameters', 'required_parameter', 'optional_parameter'],
    argument: ['arguments'],

    // Annotations/decorators
    annotation: [],
    decorator: ['decorator'],

    // Imports
    importStatement: ['import_statement'],

    // Control flow
    ifStatement: ['if_statement'],
    forStatement: ['for_statement', 'for_in_statement', 'for_of_statement'],
    whileStatement: ['while_statement'],
    tryStatement: ['try_statement'],
    returnStatement: ['return_statement'],
  };

  /**
   * Detect JavaScript frameworks from imports.
   */
  detectFramework(context: ExtractionContext): FrameworkInfo | undefined {
    const indicators: string[] = [];
    let framework: string | undefined;
    let confidence = 0;

    for (const imp of context.imports) {
      const path = imp.from_package || imp.imported_name;

      // Express.js
      if (path === 'express' || path.startsWith('express/')) {
        framework = 'express';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // Fastify
      if (path === 'fastify' || path.startsWith('fastify/')) {
        framework = 'fastify';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // Koa
      if (path === 'koa' || path.startsWith('koa/')) {
        framework = 'koa';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // Hapi
      if (path === '@hapi/hapi' || path.startsWith('@hapi/')) {
        framework = 'hapi';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // NestJS
      if (path.startsWith('@nestjs/')) {
        framework = 'nestjs';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // React
      if (path === 'react' || path.startsWith('react/') || path === 'react-dom') {
        framework = framework || 'react';
        confidence = Math.max(confidence, 0.8);
        indicators.push(`import: ${path}`);
      }

      // React Native
      if (path === 'react-native' || path.startsWith('react-native/') || path.startsWith('@react-native/')) {
        framework = 'react-native';
        confidence = Math.max(confidence, 0.95);
        indicators.push(`import: ${path}`);
      }

      // React Navigation (React Native)
      if (path.startsWith('@react-navigation/')) {
        framework = framework || 'react-native';
        confidence = Math.max(confidence, 0.9);
        indicators.push(`import: ${path}`);
      }

      // React Router
      if (path === 'react-router' || path === 'react-router-dom' || path.startsWith('react-router/')) {
        framework = framework || 'react';
        confidence = Math.max(confidence, 0.85);
        indicators.push(`import: ${path}`);
      }

      // Next.js
      if (path === 'next' || path.startsWith('next/')) {
        framework = 'nextjs';
        confidence = Math.max(confidence, 0.9);
        indicators.push(`import: ${path}`);
      }

      // Expo (React Native)
      if (path === 'expo' || path.startsWith('expo-')) {
        framework = framework || 'react-native';
        confidence = Math.max(confidence, 0.85);
        indicators.push(`import: ${path}`);
      }
    }

    if (framework) {
      return { name: framework, confidence, indicators };
    }

    return undefined;
  }

  /**
   * JavaScript/TypeScript taint source patterns.
   */
  getBuiltinSources(): TaintSourcePattern[] {
    return [
      // Express.js request object
      {
        method: 'query',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'body',
        type: 'http_body',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'params',
        type: 'http_path',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'headers',
        type: 'http_header',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'cookies',
        type: 'http_cookie',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },

      // URL/URLSearchParams
      {
        method: 'get',
        class: 'URLSearchParams',
        type: 'http_param',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },

      // Fastify-specific sources (request object)
      {
        method: 'raw',
        class: 'request',
        type: 'http_param',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'hostname',
        class: 'request',
        type: 'http_header',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },

      // Koa context sources (ctx.* and ctx.request.*)
      {
        method: 'header',
        class: 'ctx',
        type: 'http_header',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'headers',
        class: 'ctx',
        type: 'http_header',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'host',
        class: 'ctx',
        type: 'http_header',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'hostname',
        class: 'ctx',
        type: 'http_header',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'path',
        class: 'ctx',
        type: 'http_path',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'url',
        class: 'ctx',
        type: 'http_path',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'querystring',
        class: 'ctx',
        type: 'http_param',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },

      // DOM sources (for browser code)
      {
        method: 'location',
        type: 'url_param',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'document.URL',
        type: 'url_param',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'document.referrer',
        type: 'url_param',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },

      // Node.js process
      {
        method: 'argv',
        class: 'process',
        type: 'cli_arg',
        severity: 'medium',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'env',
        class: 'process',
        type: 'env_var',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },

      // File system
      {
        method: 'readFileSync',
        class: 'fs',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },
      {
        method: 'readFile',
        class: 'fs',
        type: 'file_input',
        severity: 'medium',
        confidence: 0.8,
        returnTainted: true,
      },

      // =========================================================
      // React Router Sources
      // =========================================================
      {
        method: 'useParams',
        type: 'http_path',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'useSearchParams',
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'useLocation',
        type: 'url_param',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },

      // =========================================================
      // Next.js Sources
      // =========================================================
      {
        method: 'useRouter',
        type: 'http_param',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,  // router.query, router.asPath
      },
      {
        method: 'useSearchParams',  // Next.js App Router
        type: 'http_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'usePathname',
        type: 'http_path',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        // getServerSideProps/getStaticProps context.params
        method: 'params',
        type: 'http_path',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },

      // =========================================================
      // React Native Sources
      // =========================================================
      {
        // React Navigation route params
        method: 'useRoute',
        type: 'navigation_param',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        // Deep linking
        method: 'getInitialURL',
        class: 'Linking',
        type: 'url_param',
        severity: 'high',
        confidence: 0.95,
        returnTainted: true,
      },
      {
        method: 'addEventListener',
        class: 'Linking',
        type: 'url_param',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        method: 'parse',
        class: 'Linking',
        type: 'url_param',
        severity: 'high',
        confidence: 0.9,
        returnTainted: true,
      },
      {
        // Clipboard content
        method: 'getString',
        class: 'Clipboard',
        type: 'user_input',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        method: 'getStringAsync',
        class: 'Clipboard',
        type: 'user_input',
        severity: 'medium',
        confidence: 0.85,
        returnTainted: true,
      },
      {
        // AsyncStorage (may contain user data)
        method: 'getItem',
        class: 'AsyncStorage',
        type: 'storage_input',
        severity: 'medium',
        confidence: 0.7,
        returnTainted: true,
      },
      {
        method: 'multiGet',
        class: 'AsyncStorage',
        type: 'storage_input',
        severity: 'medium',
        confidence: 0.7,
        returnTainted: true,
      },
      {
        // SecureStore (Expo)
        method: 'getItemAsync',
        class: 'SecureStore',
        type: 'storage_input',
        severity: 'medium',
        confidence: 0.7,
        returnTainted: true,
      },

      // =========================================================
      // Browser/DOM Sources (React web apps)
      // =========================================================
      {
        method: 'localStorage.getItem',
        type: 'storage_input',
        severity: 'medium',
        confidence: 0.7,
        returnTainted: true,
      },
      {
        method: 'sessionStorage.getItem',
        type: 'storage_input',
        severity: 'medium',
        confidence: 0.7,
        returnTainted: true,
      },
      {
        method: 'postMessage',
        type: 'message_input',
        severity: 'high',
        confidence: 0.85,
        returnTainted: true,
      },
    ];
  }

  /**
   * JavaScript/TypeScript taint sink patterns.
   */
  getBuiltinSinks(): TaintSinkPattern[] {
    return [
      // Command Injection
      {
        method: 'exec',
        class: 'child_process',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'execSync',
        class: 'child_process',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'spawn',
        class: 'child_process',
        type: 'command_injection',
        cwe: 'CWE-78',
        severity: 'critical',
        argPositions: [0, 1],
      },

      // Code Injection
      {
        method: 'eval',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'Function',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'setTimeout',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'high',
        argPositions: [0],  // When first arg is string
      },
      {
        method: 'setInterval',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'high',
        argPositions: [0],  // When first arg is string
      },

      // Path Traversal
      {
        method: 'readFileSync',
        class: 'fs',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'writeFileSync',
        class: 'fs',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'createReadStream',
        class: 'fs',
        type: 'path_traversal',
        cwe: 'CWE-22',
        severity: 'high',
        argPositions: [0],
      },

      // XSS (DOM)
      {
        method: 'innerHTML',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'outerHTML',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'document.write',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },

      // jQuery XSS
      {
        method: 'html',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: '$',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'jQuery',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'append',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'prepend',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },

      // SQL Injection
      {
        method: 'query',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'raw',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      // Prisma ORM - unsafe raw query methods ($executeRaw/$queryRaw with template literals are safe/parameterized)
      {
        method: '$executeRawUnsafe',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: '$queryRawUnsafe',
        type: 'sql_injection',
        cwe: 'CWE-89',
        severity: 'critical',
        argPositions: [0],
      },

      // SSRF
      {
        method: 'fetch',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'get',
        class: 'axios',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'request',
        class: 'http',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'high',
        argPositions: [0],
      },

      // NoSQL Injection
      {
        method: 'find',
        type: 'nosql_injection',
        cwe: 'CWE-943',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'findOne',
        type: 'nosql_injection',
        cwe: 'CWE-943',
        severity: 'high',
        argPositions: [0],
      },

      // Prototype Pollution (JS-specific)
      {
        method: 'merge',
        type: 'prototype_pollution',
        cwe: 'CWE-1321',
        severity: 'high',
        argPositions: [0, 1],
      },
      {
        method: 'extend',
        type: 'prototype_pollution',
        cwe: 'CWE-1321',
        severity: 'high',
        argPositions: [0, 1],
      },

      // =========================================================
      // React XSS Sinks
      // =========================================================
      {
        // Most common React XSS vector
        method: 'dangerouslySetInnerHTML',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'critical',
        argPositions: [0],  // The __html property value
      },
      {
        // Rendering user-controlled href with javascript:
        method: 'href',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },
      {
        // createRef().current.innerHTML
        method: 'current.innerHTML',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        argPositions: [0],
      },

      // =========================================================
      // React Native Sinks
      // =========================================================
      {
        // WebView with user-controlled source
        method: 'source',
        class: 'WebView',
        type: 'xss',
        cwe: 'CWE-79',
        severity: 'critical',
        argPositions: [0],  // { html: userInput } or { uri: userInput }
      },
      {
        // Open arbitrary URLs
        method: 'openURL',
        class: 'Linking',
        type: 'open_redirect',
        cwe: 'CWE-601',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'canOpenURL',
        class: 'Linking',
        type: 'ssrf',
        cwe: 'CWE-918',
        severity: 'medium',
        argPositions: [0],
      },
      {
        // Expo WebBrowser
        method: 'openBrowserAsync',
        class: 'WebBrowser',
        type: 'open_redirect',
        cwe: 'CWE-601',
        severity: 'high',
        argPositions: [0],
      },
      {
        method: 'openAuthSessionAsync',
        class: 'WebBrowser',
        type: 'open_redirect',
        cwe: 'CWE-601',
        severity: 'high',
        argPositions: [0],
      },

      // =========================================================
      // Next.js Sinks
      // =========================================================
      {
        // Server-side redirect
        method: 'redirect',
        type: 'open_redirect',
        cwe: 'CWE-601',
        severity: 'high',
        argPositions: [0],
      },
      {
        // Router push with user-controlled URL
        method: 'push',
        class: 'router',
        type: 'open_redirect',
        cwe: 'CWE-601',
        severity: 'medium',
        argPositions: [0],
      },
      {
        method: 'replace',
        class: 'router',
        type: 'open_redirect',
        cwe: 'CWE-601',
        severity: 'medium',
        argPositions: [0],
      },

      // =========================================================
      // React/General JS Security Sinks
      // =========================================================
      {
        // Dynamic component loading
        method: 'createElement',
        class: 'React',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'high',
        argPositions: [0],  // When first arg is user-controlled string
      },
      {
        // Importing user-controlled modules
        method: 'import',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        argPositions: [0],
      },
      {
        method: 'require',
        type: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        argPositions: [0],
      },

      // =========================================================
      // Data Exposure Sinks (React Native)
      // =========================================================
      // NOTE: console.log removed as a sink — too noisy for general-purpose analysis.
      // console.log is ubiquitous and rarely a true vulnerability outside mobile contexts.
      {
        // Storing sensitive data insecurely
        method: 'setItem',
        class: 'AsyncStorage',
        type: 'insecure_storage',
        cwe: 'CWE-922',
        severity: 'medium',
        argPositions: [1],
      },
    ];
  }

  /**
   * Get receiver type from a call expression.
   */
  getReceiverType(node: SyntaxNode, context: ExtractionContext): string | undefined {
    if (node.type !== 'call_expression') return undefined;

    const callee = node.childForFieldName('function');
    if (!callee) return undefined;

    // For member expressions like obj.method()
    if (callee.type === 'member_expression') {
      const object = callee.childForFieldName('object');
      if (object) {
        return object.text;
      }
    }

    return undefined;
  }

  /**
   * Check if node is a JavaScript string literal.
   */
  isStringLiteral(node: SyntaxNode): boolean {
    return node.type === 'string' ||
           node.type === 'template_string' ||
           node.type === 'string_fragment';
  }

  /**
   * Get string value from JavaScript string literal.
   */
  getStringValue(node: SyntaxNode): string | undefined {
    if (!this.isStringLiteral(node)) return undefined;

    const text = node.text;

    // Handle template strings
    if (text.startsWith('`') && text.endsWith('`')) {
      return text.slice(1, -1);
    }

    // Handle regular strings
    if ((text.startsWith('"') && text.endsWith('"')) ||
        (text.startsWith("'") && text.endsWith("'"))) {
      return text.slice(1, -1);
    }

    return text;
  }

  // Extraction methods - delegate to existing extractors for now

  extractTypes(context: ExtractionContext): TypeInfo[] {
    return [];
  }

  extractCalls(context: ExtractionContext): CallInfo[] {
    return [];
  }

  extractImports(context: ExtractionContext): ImportInfo[] {
    return [];
  }

  extractPackage(context: ExtractionContext): string | undefined {
    // JavaScript doesn't have package declarations
    // Could look for package.json in parent directories
    return undefined;
  }
}
