/**
 * Comprehensive tests for RustPlugin
 * (detectFramework, getBuiltinSources, getBuiltinSinks, isStringLiteral, getStringValue)
 */

import { describe, it, expect } from 'vitest';
import { RustPlugin } from '../../src/languages/plugins/rust.js';
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
    filePath: 'main.rs',
    sourceCode: '',
    tree: {} as ReturnType<typeof import('web-tree-sitter')['default']['prototype']['parse']>,
    imports,
  };
}

function makeNode(type: string, text: string): SyntaxNode {
  return { type, text } as unknown as SyntaxNode;
}

const plugin = new RustPlugin();

// ---------------------------------------------------------------------------
// detectFramework
// ---------------------------------------------------------------------------

describe('RustPlugin.detectFramework()', () => {
  it('detects actix-web by prefix actix_web', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('actix_web')]));
    expect(result).toBeDefined();
    expect(result!.name).toBe('actix-web');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects actix-web by hyphenated prefix actix-web', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('actix-web')]));
    expect(result!.name).toBe('actix-web');
  });

  it('detects actix-web by submodule actix_web::web', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('actix_web::web')]));
    expect(result!.name).toBe('actix-web');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects Rocket by prefix rocket', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('rocket')]));
    expect(result!.name).toBe('rocket');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects Rocket by submodule rocket::routes', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('rocket::routes')]));
    expect(result!.name).toBe('rocket');
  });

  it('detects Axum by prefix axum', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('axum')]));
    expect(result!.name).toBe('axum');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects Axum by submodule axum::Router', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('axum::Router')]));
    expect(result!.name).toBe('axum');
  });

  it('detects Warp by prefix warp', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('warp')]));
    expect(result!.name).toBe('warp');
    expect(result!.confidence).toBe(0.95);
  });

  it('detects Hyper with lower confidence (0.85)', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('hyper')]));
    expect(result!.name).toBe('hyper');
    expect(result!.confidence).toBe(0.85);
  });

  it('detects Hyper by submodule hyper::service', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('hyper::service')]));
    expect(result!.name).toBe('hyper');
  });

  it('does NOT detect Tokio as a framework (only adds indicator)', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('tokio')]));
    // Tokio alone does not set a framework name
    expect(result).toBeUndefined();
  });

  it('returns undefined for unknown imports', () => {
    const result = plugin.detectFramework(makeCtx([makeImport('serde')]));
    expect(result).toBeUndefined();
  });

  it('returns undefined for empty imports', () => {
    expect(plugin.detectFramework(makeCtx([]))).toBeUndefined();
  });

  it('picks up framework from imported_name when from_package is empty', () => {
    const imp: ImportInfo = { ...makeImport(''), imported_name: 'axum' };
    const result = plugin.detectFramework(makeCtx([imp]));
    expect(result!.name).toBe('axum');
  });

  it('accumulates multiple indicators', () => {
    const result = plugin.detectFramework(makeCtx([
      makeImport('actix_web'),
      makeImport('actix_web::middleware'),
    ]));
    expect(result!.indicators.length).toBeGreaterThanOrEqual(2);
  });

  it('Tokio alongside Axum produces Axum framework', () => {
    const result = plugin.detectFramework(makeCtx([
      makeImport('tokio'),
      makeImport('axum'),
    ]));
    expect(result!.name).toBe('axum');
  });
});

// ---------------------------------------------------------------------------
// getBuiltinSources
// ---------------------------------------------------------------------------

describe('RustPlugin.getBuiltinSources()', () => {
  const sources = plugin.getBuiltinSources();

  it('returns a non-empty array', () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  it('includes Query extractor as http_param', () => {
    const s = sources.find(x => x.method === 'Query');
    expect(s!.type).toBe('http_param');
    expect(s!.severity).toBe('high');
    expect(s!.returnTainted).toBe(true);
  });

  it('includes Json extractor as http_body', () => {
    const s = sources.find(x => x.method === 'Json');
    expect(s!.type).toBe('http_body');
  });

  it('includes Path extractor as http_path', () => {
    const s = sources.find(x => x.method === 'Path');
    expect(s!.type).toBe('http_path');
  });

  it('includes Form extractor as http_body', () => {
    const s = sources.find(x => x.method === 'Form');
    expect(s!.type).toBe('http_body');
  });

  it('includes std::env::args as cli_arg', () => {
    const s = sources.find(x => x.method === 'args' && x.class === 'std::env');
    expect(s!.type).toBe('cli_arg');
    expect(s!.severity).toBe('medium');
  });

  it('includes std::env::var as env_var', () => {
    const s = sources.find(x => x.method === 'var' && x.class === 'std::env');
    expect(s!.type).toBe('env_var');
  });

  it('includes std::env::vars as env_var', () => {
    const s = sources.find(x => x.method === 'vars' && x.class === 'std::env');
    expect(s!.type).toBe('env_var');
  });

  it('includes std::fs::read_to_string as file_input', () => {
    const s = sources.find(x => x.method === 'read_to_string' && x.class === 'std::fs');
    expect(s!.type).toBe('file_input');
  });

  it('includes std::fs::read as file_input', () => {
    const s = sources.find(x => x.method === 'read' && x.class === 'std::fs');
    expect(s!.type).toBe('file_input');
  });

  it('includes BufRead::read_line as file_input', () => {
    const s = sources.find(x => x.method === 'read_line' && x.class === 'BufRead');
    expect(s!.type).toBe('file_input');
  });

  it('includes TcpStream::read as network_input', () => {
    const s = sources.find(x => x.method === 'read' && x.class === 'TcpStream');
    expect(s!.type).toBe('network_input');
    expect(s!.severity).toBe('high');
  });
});

// ---------------------------------------------------------------------------
// getBuiltinSinks
// ---------------------------------------------------------------------------

describe('RustPlugin.getBuiltinSinks()', () => {
  const sinks = plugin.getBuiltinSinks();

  it('returns a non-empty array', () => {
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('includes std::process::Command as command_injection (CWE-78)', () => {
    const s = sinks.find(x => x.method === 'Command' && x.class === 'std::process');
    expect(s!.type).toBe('command_injection');
    expect(s!.cwe).toBe('CWE-78');
    expect(s!.severity).toBe('critical');
  });

  it('includes Command::arg as command_injection', () => {
    const s = sinks.find(x => x.method === 'arg' && x.class === 'Command');
    expect(s!.type).toBe('command_injection');
  });

  it('includes Command::args as command_injection', () => {
    const s = sinks.find(x => x.method === 'args' && x.class === 'Command');
    expect(s!.type).toBe('command_injection');
  });

  it('includes execute() as sql_injection (CWE-89)', () => {
    const s = sinks.find(x => x.method === 'execute' && !x.class);
    expect(s!.type).toBe('sql_injection');
    expect(s!.cwe).toBe('CWE-89');
    expect(s!.severity).toBe('critical');
  });

  it('includes query() as sql_injection', () => {
    const s = sinks.find(x => x.method === 'query' && !x.class);
    expect(s!.type).toBe('sql_injection');
  });

  it('includes query_raw() as sql_injection', () => {
    const s = sinks.find(x => x.method === 'query_raw');
    expect(s!.type).toBe('sql_injection');
  });

  it('includes File::open as path_traversal (CWE-22)', () => {
    const s = sinks.find(x => x.method === 'open' && x.class === 'File');
    expect(s!.type).toBe('path_traversal');
    expect(s!.cwe).toBe('CWE-22');
  });

  it('includes File::create as path_traversal', () => {
    const s = sinks.find(x => x.method === 'create' && x.class === 'File');
    expect(s!.type).toBe('path_traversal');
  });

  it('includes std::fs::read_to_string as path_traversal', () => {
    const s = sinks.find(x => x.method === 'read_to_string' && x.class === 'std::fs');
    expect(s!.type).toBe('path_traversal');
  });

  it('includes std::fs::write as path_traversal', () => {
    const s = sinks.find(x => x.method === 'write' && x.class === 'std::fs');
    expect(s!.type).toBe('path_traversal');
  });

  it('includes transmute as unsafe_memory (CWE-119)', () => {
    const s = sinks.find(x => x.method === 'transmute');
    expect(s!.type).toBe('unsafe_memory');
    expect(s!.cwe).toBe('CWE-119');
    expect(s!.severity).toBe('critical');
  });

  it('includes from_raw_parts as unsafe_memory', () => {
    const s = sinks.find(x => x.method === 'from_raw_parts');
    expect(s!.type).toBe('unsafe_memory');
    expect(s!.cwe).toBe('CWE-119');
  });

  it('includes serde_json::from_str as deserialization (CWE-502)', () => {
    const s = sinks.find(x => x.method === 'from_str' && x.class === 'serde_json');
    expect(s!.type).toBe('deserialization');
    expect(s!.cwe).toBe('CWE-502');
  });

  it('includes serde_json::from_slice as deserialization', () => {
    const s = sinks.find(x => x.method === 'from_slice');
    expect(s!.type).toBe('deserialization');
  });

  it('includes reqwest::get as ssrf (CWE-918)', () => {
    const s = sinks.find(x => x.method === 'get' && x.class === 'reqwest');
    expect(s!.type).toBe('ssrf');
    expect(s!.cwe).toBe('CWE-918');
  });

  it('includes reqwest::post as ssrf', () => {
    const s = sinks.find(x => x.method === 'post' && x.class === 'reqwest');
    expect(s!.type).toBe('ssrf');
  });

  it('includes Regex::new as regex_dos (CWE-1333)', () => {
    const s = sinks.find(x => x.method === 'new' && x.class === 'Regex');
    expect(s!.type).toBe('regex_dos');
    expect(s!.cwe).toBe('CWE-1333');
  });
});

// ---------------------------------------------------------------------------
// isStringLiteral
// ---------------------------------------------------------------------------

describe('RustPlugin.isStringLiteral()', () => {
  it('returns true for string_literal node', () => {
    expect(plugin.isStringLiteral(makeNode('string_literal', '"hello"'))).toBe(true);
  });

  it('returns true for raw_string_literal node', () => {
    expect(plugin.isStringLiteral(makeNode('raw_string_literal', 'r"hello"'))).toBe(true);
  });

  it('returns false for identifier node', () => {
    expect(plugin.isStringLiteral(makeNode('identifier', 'foo'))).toBe(false);
  });

  it('returns false for integer literal', () => {
    expect(plugin.isStringLiteral(makeNode('integer_literal', '42'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// getStringValue
// ---------------------------------------------------------------------------

describe('RustPlugin.getStringValue()', () => {
  it('extracts value from regular double-quoted string', () => {
    expect(plugin.getStringValue(makeNode('string_literal', '"hello"'))).toBe('hello');
  });

  it('extracts value from raw string r"..."', () => {
    expect(plugin.getStringValue(makeNode('raw_string_literal', 'r"hello"'))).toBe('hello');
  });

  it('extracts value from raw string with one hash r#"..."#', () => {
    expect(plugin.getStringValue(makeNode('raw_string_literal', 'r#"hello"#'))).toBe('hello');
  });

  it('extracts value from raw string with multiple hashes r##"..."##', () => {
    expect(plugin.getStringValue(makeNode('raw_string_literal', 'r##"hello"##'))).toBe('hello');
  });

  it('returns text as-is when neither raw nor double-quoted pattern matches', () => {
    const node = makeNode('string_literal', 'no-quotes');
    const result = plugin.getStringValue(node);
    expect(result).toBe('no-quotes');
  });

  it('returns undefined for non-string nodes', () => {
    expect(plugin.getStringValue(makeNode('identifier', 'foo'))).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// canHandle (inherited from BaseLanguagePlugin)
// ---------------------------------------------------------------------------

describe('RustPlugin.canHandle()', () => {
  it('handles .rs files', () => expect(plugin.canHandle('main.rs')).toBe(true));
  it('rejects .py files', () => expect(plugin.canHandle('app.py')).toBe(false));
  it('rejects .java files', () => expect(plugin.canHandle('Main.java')).toBe(false));
});

// ---------------------------------------------------------------------------
// Extraction methods (stubs — return empty arrays / undefined)
// ---------------------------------------------------------------------------

describe('RustPlugin extraction stubs', () => {
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

  it('getReceiverType returns undefined for non-call_expression nodes', () => {
    expect(plugin.getReceiverType(makeNode('identifier', 'foo'), makeCtx([]))).toBeUndefined();
  });

  it('getReceiverType returns undefined when function child is null', () => {
    const callNode = {
      type: 'call_expression',
      text: 'foo()',
      childForFieldName: (_: string) => null,
    } as unknown as SyntaxNode;
    expect(plugin.getReceiverType(callNode, makeCtx([]))).toBeUndefined();
  });

  it('getReceiverType returns value text for field_expression (obj.method)', () => {
    const valueNode = { type: 'identifier', text: 'conn', childForFieldName: () => null };
    const funcNode  = { type: 'field_expression', text: 'conn.query', childForFieldName: (_: string) => valueNode };
    const callNode  = { type: 'call_expression', text: 'conn.query()', childForFieldName: (_: string) => funcNode };
    expect(plugin.getReceiverType(callNode as unknown as SyntaxNode, makeCtx([]))).toBe('conn');
  });

  it('getReceiverType returns path text for scoped_identifier (Module::fn)', () => {
    const pathNode = { type: 'identifier', text: 'std::fs', childForFieldName: () => null };
    const funcNode = { type: 'scoped_identifier', text: 'std::fs::read', childForFieldName: (_: string) => pathNode };
    const callNode = { type: 'call_expression', text: 'std::fs::read()', childForFieldName: (_: string) => funcNode };
    expect(plugin.getReceiverType(callNode as unknown as SyntaxNode, makeCtx([]))).toBe('std::fs');
  });
});
