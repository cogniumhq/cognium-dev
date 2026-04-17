/**
 * Type Hierarchy Resolution
 *
 * Tracks class inheritance and interface implementations across files
 * to enable polymorphic sink detection.
 *
 * Example: When sink is Statement.executeQuery(), we can match calls
 * on PreparedStatement, CallableStatement, or any other subtype.
 */

import type {
  TypeInfo,
  TypeHierarchy as TypeHierarchyData,
  ClassHierarchyInfo,
  InterfaceHierarchyInfo,
  CircleIR,
} from '../types/index.js';

/**
 * Node representation for hierarchy tracking
 */
export interface TypeNode {
  name: string;
  fqn: string;                    // Fully qualified name: com.example.MyClass
  kind: 'class' | 'interface' | 'enum';
  extends: string | null;         // Parent class (for classes)
  implements: string[];           // Interfaces (for classes)
  extendsInterfaces: string[];    // Parent interfaces (for interfaces)
  file: string;                   // Source file path
  line: number;                   // Declaration line
}

/**
 * TypeHierarchyResolver - Builds and queries type inheritance relationships
 */
export class TypeHierarchyResolver {
  // All known types by FQN
  private types: Map<string, TypeNode> = new Map();

  // Simple name to FQN mapping (for resolution)
  private nameToFqn: Map<string, Set<string>> = new Map();

  // Subtype relationships: parent FQN -> child FQNs
  private subtypes: Map<string, Set<string>> = new Map();

  // Implementation relationships: interface FQN -> implementing class FQNs
  private implementations: Map<string, Set<string>> = new Map();

  // Memoization caches for transitive lookups (safe: hierarchy is immutable after loading)
  private _subtypeCache: Map<string, string[]> = new Map();
  private _implCache: Map<string, string[]> = new Map();

  /**
   * Add types from a CircleIR analysis result
   */
  addFromIR(ir: CircleIR, filePath: string): void {
    for (const type of ir.types) {
      this.addType(type, filePath, ir.meta.package || null);
    }
  }

  /**
   * Add a single type to the hierarchy
   */
  addType(type: TypeInfo, filePath: string, defaultPackage: string | null = null): void {
    const pkg = type.package || defaultPackage || '';
    const fqn = pkg ? `${pkg}.${type.name}` : type.name;

    const node: TypeNode = {
      name: type.name,
      fqn,
      kind: type.kind,
      extends: type.extends,
      implements: type.implements,
      extendsInterfaces: type.kind === 'interface' ? type.implements : [],
      file: filePath,
      line: type.start_line,
    };

    this.types.set(fqn, node);

    // Track simple name -> FQN mapping
    if (!this.nameToFqn.has(type.name)) {
      this.nameToFqn.set(type.name, new Set());
    }
    this.nameToFqn.get(type.name)!.add(fqn);

    // Build inheritance relationships
    if (type.kind === 'class' || type.kind === 'enum') {
      // Track class inheritance
      if (type.extends) {
        const parentFqn = this.resolveTypeName(type.extends, pkg);
        if (!this.subtypes.has(parentFqn)) {
          this.subtypes.set(parentFqn, new Set());
        }
        this.subtypes.get(parentFqn)!.add(fqn);
      }

      // Track interface implementations
      for (const iface of type.implements) {
        const ifaceFqn = this.resolveTypeName(iface, pkg);
        if (!this.implementations.has(ifaceFqn)) {
          this.implementations.set(ifaceFqn, new Set());
        }
        this.implementations.get(ifaceFqn)!.add(fqn);
      }
    } else if (type.kind === 'interface') {
      // Track interface inheritance (extends for interfaces)
      for (const parentIface of type.implements) {
        const parentFqn = this.resolveTypeName(parentIface, pkg);
        if (!this.subtypes.has(parentFqn)) {
          this.subtypes.set(parentFqn, new Set());
        }
        this.subtypes.get(parentFqn)!.add(fqn);
      }
    }
  }

  /**
   * Get all direct subtypes of a class
   */
  getDirectSubtypes(className: string): string[] {
    const fqn = this.resolveFqn(className);
    return Array.from(this.subtypes.get(fqn) || []);
  }

  /**
   * Get all subtypes (transitive) of a class
   */
  getAllSubtypes(className: string): string[] {
    const fqn = this.resolveFqn(className);
    const cached = this._subtypeCache.get(fqn);
    if (cached) return cached;

    const result = new Set<string>();
    const queue = [fqn];

    while (queue.length > 0) {
      const current = queue.shift()!;
      const children = this.subtypes.get(current);
      if (children) {
        for (const child of children) {
          if (!result.has(child)) {
            result.add(child);
            queue.push(child);
          }
        }
      }
    }

    const arr = Array.from(result);
    this._subtypeCache.set(fqn, arr);
    return arr;
  }

  /**
   * Get all direct implementations of an interface
   */
  getDirectImplementations(interfaceName: string): string[] {
    const fqn = this.resolveFqn(interfaceName);
    return Array.from(this.implementations.get(fqn) || []);
  }

  /**
   * Get all implementations (including through subinterfaces) of an interface
   */
  getAllImplementations(interfaceName: string): string[] {
    const fqn = this.resolveFqn(interfaceName);
    const cached = this._implCache.get(fqn);
    if (cached) return cached;

    const result = new Set<string>();
    const visited = new Set<string>();
    const queue = [fqn];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      // Add direct implementations
      const impls = this.implementations.get(current);
      if (impls) {
        for (const impl of impls) {
          result.add(impl);
          // Also add subtypes of implementing classes
          const subtypes = this.getAllSubtypes(impl);
          for (const subtype of subtypes) {
            result.add(subtype);
          }
        }
      }

      // Add subinterfaces to queue
      const subInterfaces = this.subtypes.get(current);
      if (subInterfaces) {
        for (const sub of subInterfaces) {
          queue.push(sub);
        }
      }
    }

    const arr = Array.from(result);
    this._implCache.set(fqn, arr);
    return arr;
  }

  /**
   * Check if a type is a subtype of another (including transitive)
   */
  isSubtypeOf(childName: string, parentName: string): boolean {
    const childFqn = this.resolveFqn(childName);
    const parentFqn = this.resolveFqn(parentName);

    if (childFqn === parentFqn) return true;

    // Check class hierarchy
    const allSubtypes = this.getAllSubtypes(parentFqn);
    if (allSubtypes.includes(childFqn)) return true;

    // Check interface implementations
    const allImpls = this.getAllImplementations(parentFqn);
    if (allImpls.includes(childFqn)) return true;

    return false;
  }

  /**
   * Check if a type implements an interface (directly or through inheritance)
   * Also handles interface-extends-interface relationships
   */
  implementsInterface(typeName: string, interfaceName: string): boolean {
    const typeFqn = this.resolveFqn(typeName);
    const ifaceFqn = this.resolveFqn(interfaceName);

    // Check class implementations
    const allImpls = this.getAllImplementations(ifaceFqn);
    if (allImpls.includes(typeFqn)) return true;

    // Check interface-extends-interface (stored in subtypes)
    const allSubtypes = this.getAllSubtypes(ifaceFqn);
    if (allSubtypes.includes(typeFqn)) return true;

    return false;
  }

  /**
   * Get type info by name
   */
  getType(name: string): TypeNode | undefined {
    const fqn = this.resolveFqn(name);
    return this.types.get(fqn);
  }

  /**
   * Get all types matching a simple name
   */
  getTypesByName(simpleName: string): TypeNode[] {
    const fqns = this.nameToFqn.get(simpleName);
    if (!fqns) return [];
    return Array.from(fqns)
      .map(fqn => this.types.get(fqn))
      .filter((t): t is TypeNode => t !== undefined);
  }

  /**
   * Get the file where a type is defined
   */
  getTypeFile(name: string): string | undefined {
    const type = this.getType(name);
    return type?.file;
  }

  /**
   * Check if a receiver type could match a target class
   * Handles: exact match, subtype, implementation, simple name match
   */
  couldBeType(receiverType: string, targetClass: string): boolean {
    // Direct match
    if (receiverType === targetClass) return true;

    // Simple name match
    const receiverSimple = this.getSimpleName(receiverType);
    const targetSimple = this.getSimpleName(targetClass);
    if (receiverSimple === targetSimple) return true;

    // Subtype or implementation match
    if (this.isSubtypeOf(receiverType, targetClass)) return true;

    // Check if receiver could be a subtype of target
    const allSubtypes = this.getAllSubtypes(targetClass);
    const allImpls = this.getAllImplementations(targetClass);

    for (const sub of [...allSubtypes, ...allImpls]) {
      const subSimple = this.getSimpleName(sub);
      if (subSimple === receiverSimple) return true;
    }

    return false;
  }

  /**
   * Export hierarchy data in the CircleIR format
   */
  toTypeHierarchyData(): TypeHierarchyData {
    const classes: Record<string, ClassHierarchyInfo> = {};
    const interfaces: Record<string, InterfaceHierarchyInfo> = {};

    for (const [fqn, node] of this.types) {
      if (node.kind === 'class' || node.kind === 'enum') {
        classes[fqn] = {
          file: node.file,
          extends: node.extends ? this.resolveTypeName(node.extends, this.getPackage(fqn)) : null,
          implements: node.implements.map(i => this.resolveTypeName(i, this.getPackage(fqn))),
          subclasses: this.getDirectSubtypes(fqn),
        };
      } else if (node.kind === 'interface') {
        interfaces[fqn] = {
          file: node.file,
          extends: node.extendsInterfaces.map(i => this.resolveTypeName(i, this.getPackage(fqn))),
          implementations: this.getDirectImplementations(fqn),
        };
      }
    }

    return { classes, interfaces };
  }

  /**
   * Get statistics about the hierarchy
   */
  getStats(): { totalTypes: number; classes: number; interfaces: number; enums: number } {
    let classes = 0, interfaces = 0, enums = 0;
    for (const node of this.types.values()) {
      if (node.kind === 'class') classes++;
      else if (node.kind === 'interface') interfaces++;
      else if (node.kind === 'enum') enums++;
    }
    return { totalTypes: this.types.size, classes, interfaces, enums };
  }

  /**
   * Get all types in the hierarchy
   */
  getAllTypes(): TypeNode[] {
    return Array.from(this.types.values());
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.types.clear();
    this.nameToFqn.clear();
    this.subtypes.clear();
    this.implementations.clear();
  }

  // --- Private helpers ---

  /**
   * Resolve a type name to its FQN
   */
  private resolveTypeName(name: string, currentPackage: string): string {
    // Already fully qualified
    if (name.includes('.')) return name;

    // Check if we know this type
    const fqns = this.nameToFqn.get(name);
    if (fqns && fqns.size === 1) {
      return Array.from(fqns)[0];
    }

    // Assume same package
    return currentPackage ? `${currentPackage}.${name}` : name;
  }

  /**
   * Resolve a name (simple or FQN) to its FQN
   */
  private resolveFqn(name: string): string {
    // Already in types map
    if (this.types.has(name)) return name;

    // Try to find by simple name
    const fqns = this.nameToFqn.get(name);
    if (fqns && fqns.size > 0) {
      return Array.from(fqns)[0];
    }

    return name;
  }

  /**
   * Get simple name from FQN
   */
  private getSimpleName(name: string): string {
    const lastDot = name.lastIndexOf('.');
    return lastDot === -1 ? name : name.substring(lastDot + 1);
  }

  /**
   * Get package from FQN
   */
  private getPackage(fqn: string): string {
    const lastDot = fqn.lastIndexOf('.');
    return lastDot === -1 ? '' : fqn.substring(0, lastDot);
  }
}

/**
 * Pre-populated common Java type hierarchy
 * These are standard JDK types that code often extends/implements
 */
export function createWithJdkTypes(): TypeHierarchyResolver {
  const resolver = new TypeHierarchyResolver();

  // Add common JDBC hierarchy
  const jdbcTypes: TypeInfo[] = [
    {
      name: 'Statement',
      kind: 'interface',
      package: 'java.sql',
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'PreparedStatement',
      kind: 'interface',
      package: 'java.sql',
      extends: null,
      implements: ['Statement'],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'CallableStatement',
      kind: 'interface',
      package: 'java.sql',
      extends: null,
      implements: ['PreparedStatement'],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
  ];

  // Add common IO hierarchy
  const ioTypes: TypeInfo[] = [
    {
      name: 'InputStream',
      kind: 'class',
      package: 'java.io',
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'FileInputStream',
      kind: 'class',
      package: 'java.io',
      extends: 'InputStream',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'OutputStream',
      kind: 'class',
      package: 'java.io',
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'FileOutputStream',
      kind: 'class',
      package: 'java.io',
      extends: 'OutputStream',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'Writer',
      kind: 'class',
      package: 'java.io',
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'PrintWriter',
      kind: 'class',
      package: 'java.io',
      extends: 'Writer',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
  ];

  // Add servlet hierarchy
  const servletTypes: TypeInfo[] = [
    {
      name: 'ServletRequest',
      kind: 'interface',
      package: 'javax.servlet',
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'HttpServletRequest',
      kind: 'interface',
      package: 'javax.servlet.http',
      extends: null,
      implements: ['javax.servlet.ServletRequest'],  // FQN for cross-package reference
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'ServletResponse',
      kind: 'interface',
      package: 'javax.servlet',
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'HttpServletResponse',
      kind: 'interface',
      package: 'javax.servlet.http',
      extends: null,
      implements: ['javax.servlet.ServletResponse'],  // FQN for cross-package reference
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
  ];

  // Add all JDK types
  for (const type of [...jdbcTypes, ...ioTypes, ...servletTypes]) {
    resolver.addType(type, 'jdk', type.package);
  }

  return resolver;
}
