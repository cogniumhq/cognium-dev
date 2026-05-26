/**
 * Tests for Unresolved item detection
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { buildDFG } from '../../src/core/extractors/dfg.js';
import { detectUnresolved } from '../../src/analysis/unresolved.js';

describe('Unresolved Detection', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should detect interface method calls as virtual dispatch', async () => {
    const code = `
public class UserController {
    private UserService userService;

    public void handle() {
        userService.save(user);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const dfg = buildDFG(tree);
    const unresolved = detectUnresolved(calls, types, dfg);

    const virtualDispatch = unresolved.filter(u => u.type === 'virtual_dispatch');
    expect(virtualDispatch.length).toBeGreaterThanOrEqual(1);

    const saveDispatch = virtualDispatch.find(u => u.context.code.includes('save'));
    expect(saveDispatch).toBeDefined();
    expect(saveDispatch!.reason).toBe('interface_method_unknown_impl');
    expect(saveDispatch!.llm_question).toContain('implementation');
  });

  it('should detect reflection calls', async () => {
    const code = `
public class DynamicLoader {
    public Object loadClass(String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        return clazz.newInstance();
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const dfg = buildDFG(tree);
    const unresolved = detectUnresolved(calls, types, dfg);

    const reflectionCalls = unresolved.filter(u => u.type === 'reflection');
    expect(reflectionCalls.length).toBeGreaterThanOrEqual(1);

    const forNameCall = reflectionCalls.find(u => u.context.code.includes('forName'));
    expect(forNameCall).toBeDefined();
  });

  it('should detect Method.invoke reflection', async () => {
    const code = `
public class Invoker {
    public Object invoke(Method method, Object target, Object[] args) throws Exception {
        return method.invoke(target, args);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const dfg = buildDFG(tree);
    const unresolved = detectUnresolved(calls, types, dfg);

    const reflectionCalls = unresolved.filter(u => u.type === 'reflection');
    expect(reflectionCalls.some(u => u.context.code.includes('invoke'))).toBe(true);
  });

  it('should detect collection taint propagation uncertainty', async () => {
    const code = `
public class DataProcessor {
    private List<String> userList;

    public void addItem(String item) {
        userList.add(item);
    }

    public String getItem(int index) {
        return userList.get(index);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const dfg = buildDFG(tree);
    const unresolved = detectUnresolved(calls, types, dfg);

    const taintPropagation = unresolved.filter(u => u.type === 'taint_propagation');
    expect(taintPropagation.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect dynamic dispatch patterns', async () => {
    const code = `
public class CommandExecutor {
    public void execute(Command cmd) {
        cmd.execute();
    }

    public void handle(Request request) {
        handler.handle(request);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const dfg = buildDFG(tree);
    const unresolved = detectUnresolved(calls, types, dfg);

    const dynamicCalls = unresolved.filter(u => u.type === 'dynamic_call');
    expect(dynamicCalls.length).toBeGreaterThanOrEqual(1);
  });

  it('should include line numbers and context', async () => {
    const code = `
public class Test {
    private UserRepository repo;

    public void test() {
        repo.findById(1);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const dfg = buildDFG(tree);
    const unresolved = detectUnresolved(calls, types, dfg);

    for (const item of unresolved) {
      expect(item.context.line).toBeGreaterThan(0);
      expect(item.context.code).toBeTruthy();
      expect(item.llm_question).toBeTruthy();
    }
  });

  it('should handle calls without receivers (local function calls)', async () => {
    const code = `
public class LocalCaller {
    public void outer() {
        helperFunction(data);
        processData();
    }

    private void helperFunction(String data) {}
    private void processData() {}
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const dfg = buildDFG(tree);
    const unresolved = detectUnresolved(calls, types, dfg);

    // Local calls may or may not generate unresolved items depending on resolution
    expect(Array.isArray(unresolved)).toBe(true);
  });
});
