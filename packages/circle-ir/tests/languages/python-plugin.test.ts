/**
 * Comprehensive tests for PythonPlugin
 * (detectFramework, getBuiltinSources, getBuiltinSinks, isStringLiteral, getStringValue)
 */

import { describe, it, expect } from 'vitest';
import { PythonPlugin } from '../../src/languages/plugins/python.js';
import type { Node as SyntaxNode } from 'web-tree-sitter';
import type { ImportInfo } from '../../src/types/index.js';
import type { ExtractionContext } from '../../src/languages/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeImport(from_package: string, imported_name = ''): ImportInfo {
  return {
    imported_name,
    from_package,
    alias: undefined,
    imported_names: [],
    line: 1,
    is_wildcard: false,
  };
}

function makeCtx(imports: ImportInfo[] = []): ExtractionContext {
  return {
    filePath: 'test.py',
    sourceCode: '',
    tree: {} as ReturnType<typeof import('web-tree-sitter')['default']['prototype']['parse']>,
    imports,
  };
}

function makeNode(type: string, text: string): SyntaxNode {
  return { type, text } as unknown as SyntaxNode;
}

const plugin = new PythonPlugin();

// ---------------------------------------------------------------------------
// detectFramework
// ---------------------------------------------------------------------------

describe('PythonPlugin.detectFramework()', () => {
  it('detects Flask by exact package name', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('flask')]));
    expect(result).toBeDefined();
    expect(result!.name).toBe('flask');
    expect(result!.confidence).toBe(0.95);
    expect(result!.indicators).toHaveLength(1);
  });

  it('detects Flask by submodule (flask.views)', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('flask.views')]));
    expect(result!.name).toBe('flask');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects Django by submodule (django.db)', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('django.db')]));
    expect(result).toBeDefined();
    expect(result!.name).toBe('django');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects Django by exact package name', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('django')]));
    expect(result!.name).toBe('django');
  });

  it('detects FastAPI by exact package name', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('fastapi')]));
    expect(result!.name).toBe('fastapi');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects FastAPI by submodule (fastapi.routing)', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('fastapi.routing')]));
    expect(result!.name).toBe('fastapi');
  });

  it('detects Tornado by submodule (tornado.web)', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('tornado.web')]));
    expect(result!.name).toBe('tornado');
    expect(result!.confidence).toBe(0.9);
  });

  it('detects aiohttp by exact name', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('aiohttp')]));
    expect(result!.name).toBe('aiohttp');
    expect(result!.confidence).toBe(0.9);
  });

  it('detects aiohttp by submodule (aiohttp.web)', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('aiohttp.web')]));
    expect(result!.name).toBe('aiohttp');
  });

  it('detects Pyramid by submodule (pyramid.view)', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('pyramid.view')]));
    expect(result!.name).toBe('pyramid');
    expect(result!.confidence).toBe(0.9);
  });

  it('returns undefined for unknown imports', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('numpy')]));
    expect(result).toBeUndefined();
  });

  it('returns undefined for empty imports', () => {
    const result = plugin.detectFramework(makeCtx([]));
    expect(result).toBeUndefined();
  });

  it('picks up framework from imported_name when from_package is empty', () => {
    const imp: ImportInfo = { ...makeImport(''), imported_name: 'flask' };
    const result = plugin.detectFramework(makeCtx([imp]));
    expect(result!.name).toBe('flask');
  });

  it('accumulates multiple indicators for repeated imports', () => {
    const result = plugin.detectFramework(makeCtx([
      makeImport('flask'),
      makeImport('flask.views'),
    ]));
    expect(result!.indicators.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// getBuiltinSources
// ---------------------------------------------------------------------------

describe('PythonPlugin.getBuiltinSources()', () => {
  const sources = plugin.getBuiltinSources();

  it('returns a non-empty array', () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  it('includes Flask request.args as http_param', () => {
    const s = sources.find(x => x.method === 'args' && x.class === 'request');
    expect(s).toBeDefined();
    expect(s!.type).toBe('http_param');
    expect(s!.severity).toBe('high');
    expect(s!.returnTainted).toBe(true);
  });

  it('includes Flask request.form as http_body', () => {
    const s = sources.find(x => x.method === 'form' && x.class === 'request');
    expect(s!.type).toBe('http_body');
  });

  it('includes Flask request.json as http_body', () => {
    const s = sources.find(x => x.method === 'json' && x.class === 'request');
    expect(s!.type).toBe('http_body');
  });

  it('includes Flask request.data as http_body', () => {
    const s = sources.find(x => x.method === 'data' && x.class === 'request');
    expect(s!.type).toBe('http_body');
  });

  it('includes Flask request.headers as http_header', () => {
    const s = sources.find(x => x.method === 'headers' && x.class === 'request');
    expect(s!.type).toBe('http_header');
  });

  it('includes Flask request.cookies as http_cookie', () => {
    const s = sources.find(x => x.method === 'cookies' && x.class === 'request');
    expect(s!.type).toBe('http_cookie');
  });

  it('includes Flask request.files as file_upload', () => {
    const s = sources.find(x => x.method === 'files' && x.class === 'request');
    expect(s!.type).toBe('file_upload');
  });

  it('includes Django request.GET as http_param', () => {
    const s = sources.find(x => x.method === 'GET');
    expect(s!.type).toBe('http_param');
  });

  it('includes Django request.POST as http_body', () => {
    const s = sources.find(x => x.method === 'POST');
    expect(s!.type).toBe('http_body');
  });

  it('includes Django request.META as http_header', () => {
    const s = sources.find(x => x.method === 'META');
    expect(s!.type).toBe('http_header');
  });

  it('includes input() as user_input', () => {
    const s = sources.find(x => x.method === 'input');
    expect(s!.type).toBe('user_input');
    expect(s!.severity).toBe('high');
    expect(s!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('includes sys.argv as cli_arg', () => {
    const s = sources.find(x => x.method === 'argv' && x.class === 'sys');
    expect(s!.type).toBe('cli_arg');
    expect(s!.severity).toBe('medium');
  });

  it('includes os.environ as env_var', () => {
    const s = sources.find(x => x.method === 'environ' && x.class === 'os');
    expect(s!.type).toBe('env_var');
  });

  it('includes os.getenv as env_var', () => {
    const s = sources.find(x => x.method === 'getenv' && x.class === 'os');
    expect(s!.type).toBe('env_var');
  });

  it('includes file read() as file_input', () => {
    const s = sources.find(x => x.method === 'read' && !x.class);
    expect(s!.type).toBe('file_input');
  });

  it('includes readline() as file_input', () => {
    const s = sources.find(x => x.method === 'readline');
    expect(s!.type).toBe('file_input');
  });

  it('includes readlines() as file_input', () => {
    const s = sources.find(x => x.method === 'readlines');
    expect(s!.type).toBe('file_input');
  });
});

// ---------------------------------------------------------------------------
// getBuiltinSinks
// ---------------------------------------------------------------------------

describe('PythonPlugin.getBuiltinSinks()', () => {
  const sinks = plugin.getBuiltinSinks();

  it('returns a non-empty array', () => {
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('includes os.system as command_injection (CWE-78)', () => {
    const s = sinks.find(x => x.method === 'system' && x.class === 'os');
    expect(s!.type).toBe('command_injection');
    expect(s!.cwe).toBe('CWE-78');
    expect(s!.severity).toBe('critical');
    expect(s!.argPositions).toContain(0);
  });

  it('includes os.popen as command_injection', () => {
    const s = sinks.find(x => x.method === 'popen' && x.class === 'os');
    expect(s!.cwe).toBe('CWE-78');
  });

  it('includes subprocess.run as command_injection', () => {
    const s = sinks.find(x => x.method === 'run' && x.class === 'subprocess');
    expect(s!.type).toBe('command_injection');
  });

  it('includes subprocess.call as command_injection', () => {
    const s = sinks.find(x => x.method === 'call' && x.class === 'subprocess');
    expect(s!.type).toBe('command_injection');
  });

  it('includes subprocess.Popen as command_injection', () => {
    const s = sinks.find(x => x.method === 'Popen');
    expect(s!.cwe).toBe('CWE-78');
  });

  it('includes eval() as code_injection (CWE-94)', () => {
    const s = sinks.find(x => x.method === 'eval');
    expect(s!.type).toBe('code_injection');
    expect(s!.cwe).toBe('CWE-94');
    expect(s!.severity).toBe('critical');
  });

  it('includes exec() as code_injection', () => {
    const s = sinks.find(x => x.method === 'exec');
    expect(s!.type).toBe('code_injection');
    expect(s!.cwe).toBe('CWE-94');
  });

  it('includes compile() as code_injection', () => {
    const s = sinks.find(x => x.method === 'compile');
    expect(s!.type).toBe('code_injection');
  });

  it('includes execute() as sql_injection (CWE-89)', () => {
    const s = sinks.find(x => x.method === 'execute');
    expect(s!.type).toBe('sql_injection');
    expect(s!.cwe).toBe('CWE-89');
    expect(s!.severity).toBe('critical');
  });

  it('includes executemany() as sql_injection', () => {
    const s = sinks.find(x => x.method === 'executemany');
    expect(s!.type).toBe('sql_injection');
  });

  it('includes open() as path_traversal (CWE-22)', () => {
    const s = sinks.find(x => x.method === 'open' && !x.class);
    expect(s!.type).toBe('path_traversal');
    expect(s!.cwe).toBe('CWE-22');
  });

  it('includes requests.get as ssrf (CWE-918)', () => {
    const s = sinks.find(x => x.method === 'get' && x.class === 'requests');
    expect(s!.type).toBe('ssrf');
    expect(s!.cwe).toBe('CWE-918');
  });

  it('includes requests.post as ssrf', () => {
    const s = sinks.find(x => x.method === 'post' && x.class === 'requests');
    expect(s!.type).toBe('ssrf');
  });

  it('includes urllib.urlopen as ssrf', () => {
    const s = sinks.find(x => x.method === 'urlopen');
    expect(s!.type).toBe('ssrf');
  });

  it('includes pickle.loads as deserialization (CWE-502)', () => {
    const s = sinks.find(x => x.method === 'loads' && x.class === 'pickle');
    expect(s!.type).toBe('deserialization');
    expect(s!.cwe).toBe('CWE-502');
    expect(s!.severity).toBe('critical');
  });

  it('includes pickle.load as deserialization', () => {
    const s = sinks.find(x => x.method === 'load' && x.class === 'pickle');
    expect(s!.type).toBe('deserialization');
  });

  it('includes yaml.load as deserialization', () => {
    const s = sinks.find(x => x.method === 'load' && x.class === 'yaml');
    expect(s!.type).toBe('deserialization');
    expect(s!.severity).toBe('critical');
  });

  it('includes search_s() as ldap_injection (CWE-90)', () => {
    const s = sinks.find(x => x.method === 'search_s');
    expect(s!.type).toBe('ldap_injection');
    expect(s!.cwe).toBe('CWE-90');
  });
});

// ---------------------------------------------------------------------------
// isStringLiteral
// ---------------------------------------------------------------------------

describe('PythonPlugin.isStringLiteral()', () => {
  it('returns true for string node', () => {
    expect(plugin.isStringLiteral(makeNode('string', '"hello"'))).toBe(true);
  });

  it('returns true for concatenated_string node', () => {
    expect(plugin.isStringLiteral(makeNode('concatenated_string', '"a" "b"'))).toBe(true);
  });

  it('returns false for identifier node', () => {
    expect(plugin.isStringLiteral(makeNode('identifier', 'foo'))).toBe(false);
  });

  it('returns false for integer literal node', () => {
    expect(plugin.isStringLiteral(makeNode('integer', '42'))).toBe(false);
  });

  it('returns false for call node', () => {
    expect(plugin.isStringLiteral(makeNode('call', 'foo()'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// getStringValue
// ---------------------------------------------------------------------------

describe('PythonPlugin.getStringValue()', () => {
  it('extracts value from double-quoted string', () => {
    expect(plugin.getStringValue(makeNode('string', '"hello"'))).toBe('hello');
  });

  it('extracts value from single-quoted string', () => {
    expect(plugin.getStringValue(makeNode('string', "'hello'"))).toBe('hello');
  });

  it('extracts value from f-string', () => {
    expect(plugin.getStringValue(makeNode('string', 'f"hello"'))).toBe('hello');
  });

  it('extracts value from raw string r"..."', () => {
    expect(plugin.getStringValue(makeNode('string', 'r"hello"'))).toBe('hello');
  });

  it('extracts value from byte string b"..."', () => {
    expect(plugin.getStringValue(makeNode('string', 'b"hello"'))).toBe('hello');
  });

  it('extracts value from multi-prefix rb"..."', () => {
    expect(plugin.getStringValue(makeNode('string', 'rb"hello"'))).toBe('hello');
  });

  it('extracts value from uppercase prefix F"..."', () => {
    expect(plugin.getStringValue(makeNode('string', 'F"hello"'))).toBe('hello');
  });

  it('extracts value from triple-quoted string (greedy match, trailing quotes remain)', () => {
    // The regex ['"`]{1,3} is greedy on both ends; for """hello""" the capture is hello""
    const result = plugin.getStringValue(makeNode('string', '"""hello"""'));
    expect(result).not.toBeUndefined();
    expect(result).toContain('hello');
  });

  it('returns undefined for non-string nodes', () => {
    expect(plugin.getStringValue(makeNode('identifier', 'foo'))).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// canHandle (inherited from BaseLanguagePlugin)
// ---------------------------------------------------------------------------

describe('PythonPlugin.canHandle()', () => {
  it('handles .py files', () => expect(plugin.canHandle('app.py')).toBe(true));
  it('handles .pyw files', () => expect(plugin.canHandle('app.pyw')).toBe(true));
  it('rejects .js files', () => expect(plugin.canHandle('app.js')).toBe(false));
  it('rejects .java files', () => expect(plugin.canHandle('Main.java')).toBe(false));
});

// ---------------------------------------------------------------------------
// Extraction methods (stubs — return empty arrays / undefined)
// ---------------------------------------------------------------------------

describe('PythonPlugin extraction stubs', () => {
  it('extractTypes returns empty array', () => {
    expect(plugin.extractTypes(makeCtx([]))).toEqual([]);
  });

  it('extractCalls returns empty array', () => {
    expect(plugin.extractCalls(makeCtx([]))).toEqual([]);
  });

  it('extractImports returns empty array', () => {
    expect(plugin.extractImports(makeCtx([]))).toEqual([]);
  });

  it('extractPackage returns undefined', () => {
    expect(plugin.extractPackage(makeCtx([]))).toBeUndefined();
  });

  it('getReceiverType returns undefined for non-call nodes', () => {
    expect(plugin.getReceiverType(makeNode('identifier', 'foo'), makeCtx([]))).toBeUndefined();
  });

  it('getReceiverType returns undefined when function child is null', () => {
    const callNode = {
      type: 'call',
      text: 'foo()',
      childForFieldName: (_: string) => null,
    } as unknown as SyntaxNode;
    expect(plugin.getReceiverType(callNode, makeCtx([]))).toBeUndefined();
  });

  it('getReceiverType returns object text for attribute access', () => {
    const objectNode = { type: 'identifier', text: 'self', childForFieldName: () => null };
    const funcNode   = { type: 'attribute', text: 'self.method', childForFieldName: (_: string) => objectNode };
    const callNode   = { type: 'call', text: 'self.method()', childForFieldName: (_: string) => funcNode };
    expect(plugin.getReceiverType(callNode as unknown as SyntaxNode, makeCtx([]))).toBe('self');
  });
});
