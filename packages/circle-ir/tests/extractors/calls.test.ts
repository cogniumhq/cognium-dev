/**
 * Tests for Call extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';

describe('Call Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract method calls with receiver', async () => {
    const code = `
public class Test {
    public void method() {
        String result = request.getParameter("id");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    expect(calls).toHaveLength(1);
    expect(calls[0].method_name).toBe('getParameter');
    expect(calls[0].receiver).toBe('request');
    expect(calls[0].in_method).toBe('method');
  });

  it('should extract method call arguments', async () => {
    const code = `
public class Test {
    public void method() {
        doSomething("literal", variable, obj.field);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    expect(calls).toHaveLength(1);
    expect(calls[0].arguments).toHaveLength(3);

    // First arg: string literal
    expect(calls[0].arguments[0].position).toBe(0);
    expect(calls[0].arguments[0].literal).toBe('literal');

    // Second arg: variable
    expect(calls[0].arguments[1].position).toBe(1);
    expect(calls[0].arguments[1].variable).toBe('variable');

    // Third arg: field access
    expect(calls[0].arguments[2].position).toBe(2);
    expect(calls[0].arguments[2].expression).toContain('obj.field');
  });

  it('should extract object creation (constructor calls)', async () => {
    const code = `
public class Test {
    public void method() {
        File file = new File("/path/to/file");
        List<String> list = new ArrayList<>();
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    // Should have 2 constructor calls
    const constructorCalls = calls.filter(c => c.receiver === null);
    expect(constructorCalls.length).toBeGreaterThanOrEqual(2);

    const fileCall = constructorCalls.find(c => c.method_name === 'File');
    expect(fileCall).toBeDefined();
    expect(fileCall!.arguments).toHaveLength(1);
    expect(fileCall!.arguments[0].literal).toBe('/path/to/file');
  });

  it('should extract chained method calls', async () => {
    const code = `
public class Test {
    public void method() {
        String result = builder.append("a").append("b").toString();
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    // Should have 3 calls: append, append, toString
    expect(calls.length).toBeGreaterThanOrEqual(3);

    const appendCalls = calls.filter(c => c.method_name === 'append');
    expect(appendCalls).toHaveLength(2);
  });

  it('should capture call location', async () => {
    const code = `public class Test {
    public void method() {
        doSomething();
    }
}`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    expect(calls).toHaveLength(1);
    expect(calls[0].location.line).toBe(3);
    expect(calls[0].location.column).toBeGreaterThan(0);
  });

  it('should handle static method calls', async () => {
    const code = `
public class Test {
    public void method() {
        int max = Math.max(1, 2);
        String env = System.getenv("PATH");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    const mathCall = calls.find(c => c.method_name === 'max');
    expect(mathCall).toBeDefined();
    expect(mathCall!.receiver).toBe('Math');

    const systemCall = calls.find(c => c.method_name === 'getenv');
    expect(systemCall).toBeDefined();
    expect(systemCall!.receiver).toBe('System');
  });

  it('should handle calls with no arguments', async () => {
    const code = `
public class Test {
    public void method() {
        list.clear();
        String s = obj.toString();
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    const clearCall = calls.find(c => c.method_name === 'clear');
    expect(clearCall).toBeDefined();
    expect(clearCall!.arguments).toHaveLength(0);
  });

  it('should resolve constructor calls', async () => {
    const code = `
public class Test {
    public void method() {
        File file = new File("/path");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    const constructorCall = calls.find(c => c.method_name === 'File');
    expect(constructorCall).toBeDefined();
    expect(constructorCall!.resolved).toBe(true);
    expect(constructorCall!.resolution?.status).toBe('resolved');
    expect(constructorCall!.resolution?.target).toBe('File.<init>');
  });

  it('should resolve this.method() calls', async () => {
    const code = `
public class UserService {
    public void process() {
        this.validate();
    }

    private void validate() {}
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    const thisCall = calls.find(c => c.method_name === 'validate');
    expect(thisCall).toBeDefined();
    expect(thisCall!.resolved).toBe(true);
    expect(thisCall!.resolution?.status).toBe('resolved');
    expect(thisCall!.resolution?.target).toBe('UserService.validate');
  });

  it('should resolve calls to same-class methods without receiver', async () => {
    const code = `
public class Calculator {
    public int compute(int x) {
        return doubleIt(x);
    }

    private int doubleIt(int n) {
        return n * 2;
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    const doubleCall = calls.find(c => c.method_name === 'doubleIt');
    expect(doubleCall).toBeDefined();
    expect(doubleCall!.resolved).toBe(true);
    expect(doubleCall!.resolution?.target).toBe('Calculator.doubleIt');
  });

  it('should resolve static method calls', async () => {
    const code = `
public class Test {
    public void method() {
        String result = String.valueOf(123);
        int hash = Objects.hashCode(obj);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    const valueOfCall = calls.find(c => c.method_name === 'valueOf');
    expect(valueOfCall).toBeDefined();
    expect(valueOfCall!.resolved).toBe(true);
    expect(valueOfCall!.resolution?.target).toBe('String.valueOf');
  });

  it('should detect interface method calls', async () => {
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

    const saveCall = calls.find(c => c.method_name === 'save');
    expect(saveCall).toBeDefined();
    expect(saveCall!.resolved).toBe(false);
    expect(saveCall!.resolution?.status).toBe('interface_method');
    expect(saveCall!.resolution?.candidates).toContain('UserService.save');
  });

  it('should resolve calls on known receiver patterns', async () => {
    const code = `
public class Servlet {
    public void doGet(HttpServletRequest request) {
        String id = request.getParameter("id");
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    const getParamCall = calls.find(c => c.method_name === 'getParameter');
    expect(getParamCall).toBeDefined();
    expect(getParamCall!.resolved).toBe(true);
    expect(getParamCall!.resolution?.target).toBe('HttpServletRequest.getParameter');
  });

  it('should extract calls within constructors', async () => {
    const code = `
public class Service {
    private Database db;

    public Service() {
        this.db = new Database();
        db.connect();
        initialize();
    }

    private void initialize() {}
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    // Should find calls in constructor (constructor name is class name or <init>)
    const connectCall = calls.find(c => c.method_name === 'connect');
    expect(connectCall).toBeDefined();
    // Constructor may report name as class name or <init>
    expect(['Service', '<init>']).toContain(connectCall!.in_method);

    const initCall = calls.find(c => c.method_name === 'initialize');
    expect(initCall).toBeDefined();
    expect(['Service', '<init>']).toContain(initCall!.in_method);
  });

  it('should extract calls with chained method receivers', async () => {
    const code = `
public class Test {
    public void method() {
        String result = builder.append("a").append("b").toString();
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);

    // Should find multiple append calls and toString
    const appendCalls = calls.filter(c => c.method_name === 'append');
    expect(appendCalls.length).toBeGreaterThanOrEqual(2);

    const toStringCall = calls.find(c => c.method_name === 'toString');
    expect(toStringCall).toBeDefined();
  });
});
