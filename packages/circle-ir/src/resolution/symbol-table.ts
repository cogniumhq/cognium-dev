/**
 * Symbol Table for Cross-File Resolution
 *
 * Tracks what each file exports (classes, methods, fields) and imports,
 * enabling resolution of cross-file references.
 */

import type {
  CircleIR,
  TypeInfo,
  MethodInfo,
  FieldInfo,
  ImportInfo,
  ExportInfo,
} from '../types/index.js';

/**
 * Exported symbol with full metadata
 */
export interface ExportedSymbol {
  name: string;                   // Simple name
  fqn: string;                    // Fully qualified name
  kind: 'class' | 'interface' | 'enum' | 'method' | 'field';
  file: string;                   // Source file path
  line: number;                   // Declaration line
  visibility: 'public' | 'protected' | 'package' | 'private';
  parentType?: string;            // For methods/fields: containing type FQN
  signature?: string;             // For methods: parameter types
}

/**
 * Import tracking per file
 */
interface FileImports {
  imports: ImportInfo[];
  // Resolved: simple name -> FQN
  resolved: Map<string, string>;
  // Wildcard packages (for java.util.*)
  wildcardPackages: string[];
}

/**
 * SymbolTable - Tracks exports and imports across project files
 */
export class SymbolTable {
  // All exported symbols by FQN
  private exports: Map<string, ExportedSymbol> = new Map();

  // Simple name -> FQNs (for ambiguous resolution)
  private nameToFqns: Map<string, Set<string>> = new Map();

  // File -> its imports
  private fileImports: Map<string, FileImports> = new Map();

  // Package -> exported types in that package
  private packageTypes: Map<string, Set<string>> = new Map();

  // FQN -> file path
  private fqnToFile: Map<string, string> = new Map();

  /**
   * Add exports and imports from a CircleIR analysis result
   */
  addFromIR(ir: CircleIR, filePath: string): void {
    const pkg = ir.meta.package || '';

    // Process types and their members
    for (const type of ir.types) {
      this.addTypeExports(type, filePath, pkg);
    }

    // Process imports
    this.addFileImports(ir.imports, filePath);

    // Process explicit exports if available
    for (const exp of ir.exports) {
      this.addExplicitExport(exp, filePath, pkg);
    }
  }

  /**
   * Add type and its members as exports
   */
  private addTypeExports(type: TypeInfo, filePath: string, pkg: string): void {
    const fqn = pkg ? `${pkg}.${type.name}` : type.name;
    const visibility = this.getVisibility(type.annotations);

    // Add type itself
    const typeExport: ExportedSymbol = {
      name: type.name,
      fqn,
      kind: type.kind,
      file: filePath,
      line: type.start_line,
      visibility,
    };

    this.registerExport(typeExport);

    // Track in package
    if (!this.packageTypes.has(pkg)) {
      this.packageTypes.set(pkg, new Set());
    }
    this.packageTypes.get(pkg)!.add(fqn);

    // Add methods
    for (const method of type.methods) {
      this.addMethodExport(method, fqn, filePath);
    }

    // Add fields
    for (const field of type.fields) {
      this.addFieldExport(field, fqn, filePath);
    }
  }

  /**
   * Add a method as an export
   */
  private addMethodExport(method: MethodInfo, parentFqn: string, filePath: string): void {
    const methodFqn = `${parentFqn}.${method.name}`;
    const signature = method.parameters.map(p => p.type || 'Object').join(',');
    const visibility = this.getVisibilityFromModifiers(method.modifiers);

    const methodExport: ExportedSymbol = {
      name: method.name,
      fqn: methodFqn,
      kind: 'method',
      file: filePath,
      line: method.start_line,
      visibility,
      parentType: parentFqn,
      signature,
    };

    this.registerExport(methodExport);
  }

  /**
   * Add a field as an export
   */
  private addFieldExport(field: FieldInfo, parentFqn: string, filePath: string): void {
    const fieldFqn = `${parentFqn}.${field.name}`;
    const visibility = this.getVisibilityFromModifiers(field.modifiers);

    const fieldExport: ExportedSymbol = {
      name: field.name,
      fqn: fieldFqn,
      kind: 'field',
      file: filePath,
      line: 0, // Fields don't have line numbers in current TypeInfo
      visibility,
      parentType: parentFqn,
    };

    this.registerExport(fieldExport);
  }

  /**
   * Register an export in all indexes
   */
  private registerExport(symbol: ExportedSymbol): void {
    this.exports.set(symbol.fqn, symbol);
    this.fqnToFile.set(symbol.fqn, symbol.file);

    if (!this.nameToFqns.has(symbol.name)) {
      this.nameToFqns.set(symbol.name, new Set());
    }
    this.nameToFqns.get(symbol.name)!.add(symbol.fqn);
  }

  /**
   * Add imports for a file
   */
  private addFileImports(imports: ImportInfo[], filePath: string): void {
    const fileImport: FileImports = {
      imports,
      resolved: new Map(),
      wildcardPackages: [],
    };

    for (const imp of imports) {
      if (imp.is_wildcard && imp.from_package) {
        // Wildcard import: import java.util.*
        fileImport.wildcardPackages.push(imp.from_package);
      } else if (imp.from_package && imp.imported_name !== '*') {
        // Specific import: import java.util.ArrayList
        const fqn = `${imp.from_package}.${imp.imported_name}`;
        fileImport.resolved.set(imp.imported_name, fqn);
      }
    }

    this.fileImports.set(filePath, fileImport);
  }

  /**
   * Add explicit export declaration
   */
  private addExplicitExport(exp: ExportInfo, filePath: string, pkg: string): void {
    const fqn = pkg ? `${pkg}.${exp.symbol}` : exp.symbol;

    // Only add if not already registered (types take precedence)
    if (!this.exports.has(fqn)) {
      const symbol: ExportedSymbol = {
        name: exp.symbol,
        fqn,
        kind: exp.kind,
        file: filePath,
        line: 0,
        visibility: exp.visibility,
      };
      this.registerExport(symbol);
    }
  }

  /**
   * Resolve a simple name to its FQN from a given file's context
   */
  resolveSymbol(name: string, fromFile: string): ExportedSymbol | undefined {
    // Check if already FQN
    if (this.exports.has(name)) {
      return this.exports.get(name);
    }

    // Check file's specific imports
    const fileImport = this.fileImports.get(fromFile);
    if (fileImport) {
      const resolved = fileImport.resolved.get(name);
      if (resolved && this.exports.has(resolved)) {
        return this.exports.get(resolved);
      }

      // Check wildcard imports
      for (const pkg of fileImport.wildcardPackages) {
        const fqn = `${pkg}.${name}`;
        if (this.exports.has(fqn)) {
          return this.exports.get(fqn);
        }
      }
    }

    // Check by simple name (may be ambiguous)
    const fqns = this.nameToFqns.get(name);
    if (fqns && fqns.size === 1) {
      return this.exports.get(Array.from(fqns)[0]);
    }

    return undefined;
  }

  /**
   * Resolve a type name to FQN, considering imports
   */
  resolveTypeName(name: string, fromFile: string): string | undefined {
    const symbol = this.resolveSymbol(name, fromFile);
    if (symbol && (symbol.kind === 'class' || symbol.kind === 'interface' || symbol.kind === 'enum')) {
      return symbol.fqn;
    }
    return undefined;
  }

  /**
   * Get all methods of a type by FQN
   */
  getMethodsOfType(typeFqn: string): ExportedSymbol[] {
    const results: ExportedSymbol[] = [];
    for (const symbol of this.exports.values()) {
      if (symbol.kind === 'method' && symbol.parentType === typeFqn) {
        results.push(symbol);
      }
    }
    return results;
  }

  /**
   * Find a method by name in a type
   */
  findMethod(typeFqn: string, methodName: string): ExportedSymbol | undefined {
    const methodFqn = `${typeFqn}.${methodName}`;
    return this.exports.get(methodFqn);
  }

  /**
   * Get the file where a symbol is defined
   */
  getFile(fqn: string): string | undefined {
    return this.fqnToFile.get(fqn);
  }

  /**
   * Get all exported symbols from a file
   */
  getFileExports(filePath: string): ExportedSymbol[] {
    const results: ExportedSymbol[] = [];
    for (const symbol of this.exports.values()) {
      if (symbol.file === filePath) {
        results.push(symbol);
      }
    }
    return results;
  }

  /**
   * Get all types in a package
   */
  getPackageTypes(packageName: string): string[] {
    return Array.from(this.packageTypes.get(packageName) || []);
  }

  /**
   * Get all known packages
   */
  getPackages(): string[] {
    return Array.from(this.packageTypes.keys());
  }

  /**
   * Check if a symbol exists
   */
  hasSymbol(fqn: string): boolean {
    return this.exports.has(fqn);
  }

  /**
   * Get symbol by FQN
   */
  getSymbol(fqn: string): ExportedSymbol | undefined {
    return this.exports.get(fqn);
  }

  /**
   * Get all possible FQNs for a simple name
   */
  getPossibleFqns(simpleName: string): string[] {
    return Array.from(this.nameToFqns.get(simpleName) || []);
  }

  /**
   * Get imports for a file
   */
  getFileImports(filePath: string): ImportInfo[] {
    return this.fileImports.get(filePath)?.imports || [];
  }

  /**
   * Get statistics
   */
  getStats(): {
    totalSymbols: number;
    types: number;
    methods: number;
    fields: number;
    files: number;
    packages: number;
  } {
    let types = 0, methods = 0, fields = 0;
    const files = new Set<string>();

    for (const symbol of this.exports.values()) {
      files.add(symbol.file);
      if (symbol.kind === 'class' || symbol.kind === 'interface' || symbol.kind === 'enum') {
        types++;
      } else if (symbol.kind === 'method') {
        methods++;
      } else if (symbol.kind === 'field') {
        fields++;
      }
    }

    return {
      totalSymbols: this.exports.size,
      types,
      methods,
      fields,
      files: files.size,
      packages: this.packageTypes.size,
    };
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.exports.clear();
    this.nameToFqns.clear();
    this.fileImports.clear();
    this.packageTypes.clear();
    this.fqnToFile.clear();
  }

  // --- Private helpers ---

  /**
   * Extract visibility from annotations (for types)
   */
  private getVisibility(_annotations: string[]): 'public' | 'protected' | 'package' | 'private' {
    // Types in Java are public by default if in their own file
    // For simplicity, assume public unless we find evidence otherwise
    return 'public';
  }

  /**
   * Extract visibility from modifiers
   */
  private getVisibilityFromModifiers(modifiers: string[]): 'public' | 'protected' | 'package' | 'private' {
    if (modifiers.includes('public')) return 'public';
    if (modifiers.includes('protected')) return 'protected';
    if (modifiers.includes('private')) return 'private';
    return 'package';
  }
}

/**
 * Build a symbol table from multiple IR results
 */
export function buildSymbolTable(files: Array<{ ir: CircleIR; path: string }>): SymbolTable {
  const table = new SymbolTable();
  for (const { ir, path } of files) {
    table.addFromIR(ir, path);
  }
  return table;
}
