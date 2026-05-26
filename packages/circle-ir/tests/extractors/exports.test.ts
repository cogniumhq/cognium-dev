/**
 * Tests for export extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { extractExports } from '../../src/core/extractors/exports.js';

describe('Export Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract public class as export', async () => {
    const code = `
public class UserService {
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const exports = extractExports(types);

    expect(exports.some(e => e.symbol === 'UserService' && e.kind === 'class')).toBe(true);
    expect(exports.find(e => e.symbol === 'UserService')?.visibility).toBe('public');
  });

  it('should extract public methods', async () => {
    const code = `
public class UserService {
    public void createUser(String name) {}
    private void validateUser(String name) {}
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const exports = extractExports(types);

    // Public method should be exported
    expect(exports.some(e => e.symbol === 'UserService.createUser')).toBe(true);

    // Private method should NOT be exported
    expect(exports.some(e => e.symbol === 'UserService.validateUser')).toBe(false);
  });

  it('should extract public and protected fields', async () => {
    const code = `
public class Config {
    public String apiKey;
    protected int timeout;
    private String secret;
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const exports = extractExports(types);

    // Public field should be exported
    expect(exports.some(e => e.symbol === 'Config.apiKey' && e.kind === 'field')).toBe(true);

    // Protected field should be exported
    expect(exports.some(e => e.symbol === 'Config.timeout' && e.kind === 'field')).toBe(true);

    // Private field should NOT be exported
    expect(exports.some(e => e.symbol === 'Config.secret')).toBe(false);
  });

  it('should extract interface as export', async () => {
    const code = `
public interface UserRepository {
    void save(User user);
    User findById(Long id);
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const exports = extractExports(types);

    expect(exports.some(e => e.symbol === 'UserRepository' && e.kind === 'interface')).toBe(true);
    expect(exports.some(e => e.symbol === 'UserRepository.save')).toBe(true);
    expect(exports.some(e => e.symbol === 'UserRepository.findById')).toBe(true);
  });

  it('should handle package-private visibility', async () => {
    const code = `
public class Service {
    void internalMethod() {}
    String internalField;
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const exports = extractExports(types);

    // Package-private method should be exported with 'package' visibility
    const methodExport = exports.find(e => e.symbol === 'Service.internalMethod');
    expect(methodExport).toBeDefined();
    expect(methodExport?.visibility).toBe('package');

    // Package-private field should be exported with 'package' visibility
    const fieldExport = exports.find(e => e.symbol === 'Service.internalField');
    expect(fieldExport).toBeDefined();
    expect(fieldExport?.visibility).toBe('package');
  });

  it('should extract enum as class export', async () => {
    const code = `
public enum Status {
    ACTIVE,
    INACTIVE
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const exports = extractExports(types);

    // Enum should be exported as 'class' kind
    expect(exports.some(e => e.symbol === 'Status' && e.kind === 'class')).toBe(true);
  });

  it('should handle multiple classes', async () => {
    const code = `
public class ServiceA {
    public void methodA() {}
}

public class ServiceB {
    public void methodB() {}
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);
    const exports = extractExports(types);

    expect(exports.some(e => e.symbol === 'ServiceA')).toBe(true);
    expect(exports.some(e => e.symbol === 'ServiceB')).toBe(true);
    expect(exports.some(e => e.symbol === 'ServiceA.methodA')).toBe(true);
    expect(exports.some(e => e.symbol === 'ServiceB.methodB')).toBe(true);
  });
});
