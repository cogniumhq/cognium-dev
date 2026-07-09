/**
 * Tests for pre-registered common-library type hierarchies.
 *
 * Verifies that TypeHierarchyResolver.createWithJdkTypes() correctly loads
 * Apache HttpClient (4.x + 5.x) subtype relationships so sink patterns
 * keyed on the base HttpClient interface can match subtype receivers.
 *
 * See circle-ir 3.156.0 ADR-016 for context.
 */

import { describe, it, expect } from 'vitest';
import {
  TypeHierarchyResolver,
  createWithJdkTypes,
  registerCommonLibraries,
} from '../../src/resolution/type-hierarchy.js';

describe('TypeHierarchyResolver — Apache HttpClient 4.x', () => {
  it('CloseableHttpClient is subtype of HttpClient', () => {
    const h = createWithJdkTypes();
    expect(
      h.isSubtypeOf(
        'org.apache.http.impl.client.CloseableHttpClient',
        'org.apache.http.client.HttpClient',
      ),
    ).toBe(true);
  });

  it('InternalHttpClient is transitive subtype of HttpClient', () => {
    const h = createWithJdkTypes();
    expect(
      h.isSubtypeOf(
        'org.apache.http.impl.client.InternalHttpClient',
        'org.apache.http.client.HttpClient',
      ),
    ).toBe(true);
  });

  it('DefaultHttpClient is transitive subtype of HttpClient (through AbstractHttpClient)', () => {
    const h = createWithJdkTypes();
    expect(
      h.isSubtypeOf(
        'org.apache.http.impl.client.DefaultHttpClient',
        'org.apache.http.client.HttpClient',
      ),
    ).toBe(true);
  });
});

describe('TypeHierarchyResolver — Apache HttpClient 5.x', () => {
  it('5.x CloseableHttpClient is subtype of 5.x HttpClient', () => {
    const h = createWithJdkTypes();
    expect(
      h.isSubtypeOf(
        'org.apache.hc.client5.http.impl.classic.CloseableHttpClient',
        'org.apache.hc.client5.http.classic.HttpClient',
      ),
    ).toBe(true);
  });

  it('4.x HttpClient is NOT subtype of 5.x HttpClient (distinct FQNs)', () => {
    const h = createWithJdkTypes();
    expect(
      h.isSubtypeOf(
        'org.apache.http.client.HttpClient',
        'org.apache.hc.client5.http.classic.HttpClient',
      ),
    ).toBe(false);
  });
});

describe('TypeHierarchyResolver — negative cases', () => {
  it('unrelated class is not subtype of HttpClient', () => {
    const h = createWithJdkTypes();
    expect(
      h.isSubtypeOf('java.lang.String', 'org.apache.http.client.HttpClient'),
    ).toBe(false);
  });
});

describe('TypeHierarchyResolver — createWithJdkTypes preserves JDK facts', () => {
  it('still returns JDBC PreparedStatement→Statement hierarchy', () => {
    const h = createWithJdkTypes();
    expect(
      h.isSubtypeOf('java.sql.PreparedStatement', 'java.sql.Statement'),
    ).toBe(true);
  });
});

describe('TypeHierarchyResolver — registerCommonLibraries is additive', () => {
  it('user-supplied types coexist with pre-registered facts', () => {
    const h = new TypeHierarchyResolver();
    registerCommonLibraries(h);

    // User adds their own subclass of Apache HttpClient
    h.addType(
      {
        name: 'MyCustomHttpClient',
        kind: 'class',
        package: 'com.example',
        extends: 'org.apache.http.impl.client.CloseableHttpClient',
        implements: [],
        annotations: [],
        methods: [],
        fields: [],
        start_line: 10,
        end_line: 20,
      },
      'MyCustomHttpClient.java',
    );

    expect(
      h.isSubtypeOf(
        'com.example.MyCustomHttpClient',
        'org.apache.http.client.HttpClient',
      ),
    ).toBe(true);
  });
});

describe('TypeHierarchyResolver — static-factory return-type registry (#241)', () => {
  it('HttpClients.createDefault() → CloseableHttpClient', () => {
    const h = createWithJdkTypes();
    expect(h.resolveFactoryReturnType('HttpClients.createDefault()')).toBe(
      'org.apache.http.impl.client.CloseableHttpClient',
    );
  });

  it('HttpClients.createSystem() → CloseableHttpClient', () => {
    const h = createWithJdkTypes();
    expect(h.resolveFactoryReturnType('HttpClients.createSystem()')).toBe(
      'org.apache.http.impl.client.CloseableHttpClient',
    );
  });

  it('HttpClients.createMinimal() → MinimalHttpClient', () => {
    const h = createWithJdkTypes();
    expect(h.resolveFactoryReturnType('HttpClients.createMinimal()')).toBe(
      'org.apache.http.impl.client.MinimalHttpClient',
    );
  });

  it('FQN-prefixed receiver also resolves', () => {
    const h = createWithJdkTypes();
    expect(
      h.resolveFactoryReturnType('org.apache.http.impl.client.HttpClients.createDefault()'),
    ).toBe('org.apache.http.impl.client.CloseableHttpClient');
  });

  it('unregistered factory returns null', () => {
    const h = createWithJdkTypes();
    expect(h.resolveFactoryReturnType('Foo.bar()')).toBeNull();
  });

  it('receiver without ()  returns null', () => {
    const h = createWithJdkTypes();
    expect(h.resolveFactoryReturnType('HttpClients.createDefault')).toBeNull();
  });

  it('receiver with lowercase class returns null (guards ident collisions)', () => {
    const h = createWithJdkTypes();
    // `req.getParameter()` must NOT be interpreted as a factory.
    expect(h.resolveFactoryReturnType('req.getParameter()')).toBeNull();
  });

  it('registerFactoryReturnType is additive (user override)', () => {
    const h = createWithJdkTypes();
    h.registerFactoryReturnType('MyFactory', 'create', 'com.example.MyClient');
    expect(h.resolveFactoryReturnType('MyFactory.create()')).toBe(
      'com.example.MyClient',
    );
  });

  it('resolved factory return type is subtype of HttpClient interface', () => {
    const h = createWithJdkTypes();
    const returnFqn = h.resolveFactoryReturnType('HttpClients.createDefault()');
    expect(returnFqn).not.toBeNull();
    expect(h.isSubtypeOf(returnFqn!, 'org.apache.http.client.HttpClient')).toBe(true);
  });

  it('clear() empties the factory registry', () => {
    const h = createWithJdkTypes();
    expect(h.resolveFactoryReturnType('HttpClients.createDefault()')).not.toBeNull();
    h.clear();
    expect(h.resolveFactoryReturnType('HttpClients.createDefault()')).toBeNull();
  });
});
