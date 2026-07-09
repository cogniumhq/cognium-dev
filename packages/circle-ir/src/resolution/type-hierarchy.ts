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

  // Static-factory return-type registry.
  // Key: `<FactorySimpleName>.<method>` (e.g. `HttpClients.createDefault`,
  // `HttpClientBuilder.build`). Value: fully-qualified return-type name
  // (e.g. `org.apache.http.impl.client.CloseableHttpClient`).
  //
  // Purpose: recover receiver-type resolution when a sink call's receiver
  // is a chained static factory expression (e.g.
  // `HttpClients.createDefault().execute(req)`) and the language plugin
  // does not perform full return-type inference on the factory call. The
  // taint matcher consults this map when `call.receiver_type` is null. —
  // cognium-dev #241 Java
  private factoryReturnTypes: Map<string, string> = new Map();

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
   * Register the return type of a static factory method.
   *
   * @param factoryClass Simple class name of the factory (e.g. `HttpClients`).
   * @param method Factory method name (e.g. `createDefault`).
   * @param returnFqn Fully-qualified return type (e.g.
   *   `org.apache.http.impl.client.CloseableHttpClient`).
   *
   * — cognium-dev #241 Java
   */
  registerFactoryReturnType(factoryClass: string, method: string, returnFqn: string): void {
    this.factoryReturnTypes.set(`${factoryClass}.${method}`, returnFqn);
  }

  /**
   * Resolve a static-factory receiver expression to its return type FQN.
   *
   * Accepts a receiver expression of shape `<FactorySimple>.<method>()` (or
   * a longer dotted prefix ending in the same). Returns the registered
   * return-type FQN, or `null` when no matching factory is registered.
   *
   * Examples that resolve (given Apache HttpClient registration):
   *   `HttpClients.createDefault()` → `org.apache.http.impl.client.CloseableHttpClient`
   *   `org.apache.http.impl.client.HttpClients.createDefault()` → same
   *
   * — cognium-dev #241 Java
   */
  resolveFactoryReturnType(receiver: string): string | null {
    // Receiver must end with `()` (parameterless factory call).
    // Factories with arguments (`HttpClients.custom().build()`) are handled
    // by chaining: caller must strip inner call themselves.
    const m = receiver.match(/(?:^|\.)([A-Z]\w*)\.(\w+)\(\)$/);
    if (!m) return null;
    const key = `${m[1]}.${m[2]}`;
    return this.factoryReturnTypes.get(key) ?? null;
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.types.clear();
    this.nameToFqn.clear();
    this.subtypes.clear();
    this.implementations.clear();
    this.factoryReturnTypes.clear();
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

  // Add common third-party library hierarchies
  registerCommonLibraries(resolver);

  return resolver;
}

/**
 * Pre-registered type hierarchies for widely used third-party libraries.
 *
 * These are strictly additive facts — code that supplies its own IR types
 * for these classes overrides the pre-registered facts via the normal
 * `addFromIR()` path. Purpose: allow sink patterns keyed on a base class /
 * interface (e.g. `HttpClient.execute`) to match subtype receivers
 * (`CloseableHttpClient`, `InternalHttpClient`, etc.) via
 * `TypeHierarchyResolver.isSubtypeOf()`.
 *
 * Currently registered:
 * - Apache HttpClient 4.x (`org.apache.http.*`)
 * - Apache HttpClient 5.x (`org.apache.hc.client5.*`)
 */
export function registerCommonLibraries(resolver: TypeHierarchyResolver): void {
  // Apache HttpClient 4.x — org.apache.http.*
  const apacheHttpClient4x: TypeInfo[] = [
    {
      name: 'HttpClient',
      kind: 'interface',
      package: 'org.apache.http.client',
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'AbstractHttpClient',
      kind: 'class',
      package: 'org.apache.http.impl.client',
      extends: null,
      implements: ['org.apache.http.client.HttpClient'],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'CloseableHttpClient',
      kind: 'class',
      package: 'org.apache.http.impl.client',
      extends: null,
      implements: ['org.apache.http.client.HttpClient'],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'InternalHttpClient',
      kind: 'class',
      package: 'org.apache.http.impl.client',
      extends: 'org.apache.http.impl.client.CloseableHttpClient',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'MinimalHttpClient',
      kind: 'class',
      package: 'org.apache.http.impl.client',
      extends: 'org.apache.http.impl.client.CloseableHttpClient',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'DefaultHttpClient',
      kind: 'class',
      package: 'org.apache.http.impl.client',
      extends: 'org.apache.http.impl.client.AbstractHttpClient',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'SystemDefaultHttpClient',
      kind: 'class',
      package: 'org.apache.http.impl.client',
      extends: 'org.apache.http.impl.client.DefaultHttpClient',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
  ];

  // Apache HttpClient 5.x — org.apache.hc.client5.*
  const apacheHttpClient5x: TypeInfo[] = [
    {
      name: 'HttpClient',
      kind: 'interface',
      package: 'org.apache.hc.client5.http.classic',
      extends: null,
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'CloseableHttpClient',
      kind: 'class',
      package: 'org.apache.hc.client5.http.impl.classic',
      extends: null,
      implements: ['org.apache.hc.client5.http.classic.HttpClient'],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'InternalHttpClient',
      kind: 'class',
      package: 'org.apache.hc.client5.http.impl.classic',
      extends: 'org.apache.hc.client5.http.impl.classic.CloseableHttpClient',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
    {
      name: 'MinimalHttpClient',
      kind: 'class',
      package: 'org.apache.hc.client5.http.impl.classic',
      extends: 'org.apache.hc.client5.http.impl.classic.CloseableHttpClient',
      implements: [],
      annotations: [],
      methods: [],
      fields: [],
      start_line: 0,
      end_line: 0,
    },
  ];

  for (const type of [...apacheHttpClient4x, ...apacheHttpClient5x]) {
    resolver.addType(type, 'common-libraries', type.package);
  }

  // Static-factory return types.
  //
  // Apache HttpClient 4.x — HttpClients (org.apache.http.impl.client).
  // Both `createDefault()` and `createSystem()` return CloseableHttpClient.
  // Recovers receiver type for `HttpClients.createDefault().execute(req)`
  // patterns where the language plugin cannot infer the chained call's
  // return type.
  resolver.registerFactoryReturnType(
    'HttpClients',
    'createDefault',
    'org.apache.http.impl.client.CloseableHttpClient',
  );
  resolver.registerFactoryReturnType(
    'HttpClients',
    'createSystem',
    'org.apache.http.impl.client.CloseableHttpClient',
  );
  resolver.registerFactoryReturnType(
    'HttpClients',
    'createMinimal',
    'org.apache.http.impl.client.MinimalHttpClient',
  );

  // Apache HttpClient 5.x — HttpClients (org.apache.hc.client5.http.impl.classic).
  // Note: 4.x and 5.x share the simple class name `HttpClients`. Since our
  // registry is keyed on the simple name and the 5.x return type is also a
  // subtype of a `HttpClient` interface (in a different package), the
  // subtype check via `isSubtypeOf` will succeed on the 4.x FQN only. This
  // is acceptable for the SSRF sink (both are HttpClient subtypes and both
  // execute untrusted requests). — cognium-dev #241 Java
}
