/**
 * Tests for JavaScript/TypeScript Call extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';

describe('JavaScript Call Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('Basic Function Calls', () => {
    it('should extract simple function calls', async () => {
      const code = `
const result = doSomething();
console.log("hello");
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      expect(calls.length).toBeGreaterThanOrEqual(2);

      const doSomethingCall = calls.find(c => c.method_name === 'doSomething');
      expect(doSomethingCall).toBeDefined();

      const logCall = calls.find(c => c.method_name === 'log');
      expect(logCall).toBeDefined();
      expect(logCall!.receiver).toBe('console');
    });

    it('should extract method calls with receiver', async () => {
      const code = `
const id = req.params.get("id");
const data = response.json();
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const getCall = calls.find(c => c.method_name === 'get');
      expect(getCall).toBeDefined();
      expect(getCall!.receiver).toBe('req.params');

      const jsonCall = calls.find(c => c.method_name === 'json');
      expect(jsonCall).toBeDefined();
      expect(jsonCall!.receiver).toBe('response');
    });

    it('should extract function call arguments', async () => {
      const code = `
doSomething("literal", variable, obj.field);
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      expect(calls).toHaveLength(1);
      expect(calls[0].arguments).toHaveLength(3);

      // First arg: string literal
      expect(calls[0].arguments[0].position).toBe(0);
      expect(calls[0].arguments[0].literal).toBe('literal');

      // Second arg: variable
      expect(calls[0].arguments[1].position).toBe(1);
      expect(calls[0].arguments[1].variable).toBe('variable');

      // Third arg: member expression
      expect(calls[0].arguments[2].position).toBe(2);
      expect(calls[0].arguments[2].variable).toBe('obj.field');
    });
  });

  describe('Constructor Calls (new expressions)', () => {
    it('should extract new expressions', async () => {
      const code = `
const date = new Date();
const arr = new Array(10);
const obj = new MyClass("arg1", arg2);
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const dateCall = calls.find(c => c.method_name === 'Date');
      expect(dateCall).toBeDefined();
      expect(dateCall!.receiver).toBeNull();

      const arrayCall = calls.find(c => c.method_name === 'Array');
      expect(arrayCall).toBeDefined();
      expect(arrayCall!.arguments).toHaveLength(1);

      const myClassCall = calls.find(c => c.method_name === 'MyClass');
      expect(myClassCall).toBeDefined();
      expect(myClassCall!.arguments).toHaveLength(2);
    });
  });

  describe('Express.js Patterns', () => {
    it('should extract Express route handler calls', async () => {
      const code = `
const express = require('express');
const app = express();

app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    res.json({ id });
});

app.post('/users', (req, res) => {
    const body = req.body;
    res.send('OK');
});
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      // Should find app.get, app.post, res.json, res.send
      const getCall = calls.find(c => c.method_name === 'get' && c.receiver === 'app');
      expect(getCall).toBeDefined();

      const postCall = calls.find(c => c.method_name === 'post' && c.receiver === 'app');
      expect(postCall).toBeDefined();

      const jsonCall = calls.find(c => c.method_name === 'json');
      expect(jsonCall).toBeDefined();

      const sendCall = calls.find(c => c.method_name === 'send');
      expect(sendCall).toBeDefined();
    });

    it('should extract database query calls', async () => {
      const code = `
app.get('/users/:id', (req, res) => {
    const query = "SELECT * FROM users WHERE id = " + req.params.id;
    db.query(query, (err, results) => {
        res.json(results);
    });
});
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const queryCall = calls.find(c => c.method_name === 'query');
      expect(queryCall).toBeDefined();
      expect(queryCall!.receiver).toBe('db');
      expect(queryCall!.arguments.length).toBeGreaterThanOrEqual(1);
    });

    it('should extract child_process exec calls', async () => {
      const code = `
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
    exec('ping -c 1 ' + req.query.host, (error, stdout) => {
        res.send(stdout);
    });
});
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const execCall = calls.find(c => c.method_name === 'exec');
      expect(execCall).toBeDefined();
      expect(execCall!.arguments.length).toBeGreaterThanOrEqual(1);
    });

    it('should extract fs file operations', async () => {
      const code = `
const fs = require('fs');

app.get('/files/:name', (req, res) => {
    fs.readFile('./uploads/' + req.params.name, (err, data) => {
        res.send(data);
    });
});
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const readFileCall = calls.find(c => c.method_name === 'readFile');
      expect(readFileCall).toBeDefined();
      expect(readFileCall!.receiver).toBe('fs');
    });
  });

  describe('Arrow Functions and Callbacks', () => {
    it('should identify enclosing function for calls in arrow functions', async () => {
      const code = `
const processData = (data) => {
    console.log(data);
    return transform(data);
};
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const logCall = calls.find(c => c.method_name === 'log');
      expect(logCall).toBeDefined();
      expect(logCall!.in_method).toBe('processData');

      const transformCall = calls.find(c => c.method_name === 'transform');
      expect(transformCall).toBeDefined();
      expect(transformCall!.in_method).toBe('processData');
    });

    it('should handle nested arrow functions', async () => {
      const code = `
const outer = () => {
    const inner = () => {
        doSomething();
    };
    inner();
};
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      expect(calls.length).toBeGreaterThanOrEqual(2);

      const doSomethingCall = calls.find(c => c.method_name === 'doSomething');
      expect(doSomethingCall).toBeDefined();
    });

    it('should handle callback patterns', async () => {
      const code = `
array.forEach((item) => {
    process(item);
});

array.map(item => transform(item));
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const forEachCall = calls.find(c => c.method_name === 'forEach');
      expect(forEachCall).toBeDefined();

      const mapCall = calls.find(c => c.method_name === 'map');
      expect(mapCall).toBeDefined();

      const processCall = calls.find(c => c.method_name === 'process');
      expect(processCall).toBeDefined();

      const transformCall = calls.find(c => c.method_name === 'transform');
      expect(transformCall).toBeDefined();
    });
  });

  describe('Chained Method Calls', () => {
    it('should extract chained method calls', async () => {
      const code = `
const result = fetch(url)
    .then(res => res.json())
    .then(data => process(data))
    .catch(err => console.error(err));
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const fetchCall = calls.find(c => c.method_name === 'fetch');
      expect(fetchCall).toBeDefined();

      const thenCalls = calls.filter(c => c.method_name === 'then');
      expect(thenCalls.length).toBeGreaterThanOrEqual(2);

      const catchCall = calls.find(c => c.method_name === 'catch');
      expect(catchCall).toBeDefined();
    });

    it('should extract builder pattern calls', async () => {
      const code = `
const query = db.select('*')
    .from('users')
    .where('id', userId)
    .orderBy('name');
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const selectCall = calls.find(c => c.method_name === 'select');
      expect(selectCall).toBeDefined();

      const fromCall = calls.find(c => c.method_name === 'from');
      expect(fromCall).toBeDefined();

      const whereCall = calls.find(c => c.method_name === 'where');
      expect(whereCall).toBeDefined();
    });
  });

  describe('Class Methods', () => {
    it('should extract calls from class methods', async () => {
      const code = `
class UserService {
    constructor(db) {
        this.db = db;
    }

    async getUser(id) {
        return this.db.query('SELECT * FROM users WHERE id = ?', [id]);
    }

    async saveUser(user) {
        return this.db.insert('users', user);
    }
}
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const queryCall = calls.find(c => c.method_name === 'query');
      expect(queryCall).toBeDefined();
      expect(queryCall!.in_method).toBe('getUser');

      const insertCall = calls.find(c => c.method_name === 'insert');
      expect(insertCall).toBeDefined();
      expect(insertCall!.in_method).toBe('saveUser');
    });
  });

  describe('Async/Await Patterns', () => {
    it('should extract calls in async functions', async () => {
      const code = `
async function fetchData(url) {
    const response = await fetch(url);
    const data = await response.json();
    return data;
}
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const fetchCall = calls.find(c => c.method_name === 'fetch');
      expect(fetchCall).toBeDefined();
      expect(fetchCall!.in_method).toBe('fetchData');

      const jsonCall = calls.find(c => c.method_name === 'json');
      expect(jsonCall).toBeDefined();
    });
  });

  describe('require() and import patterns', () => {
    it('should extract require calls', async () => {
      const code = `
const express = require('express');
const { readFile } = require('fs');
const path = require('path');
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const requireCalls = calls.filter(c => c.method_name === 'require');
      expect(requireCalls.length).toBe(3);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty function calls', async () => {
      const code = `
init();
setup();
teardown();
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      expect(calls.length).toBe(3);
      calls.forEach(call => {
        expect(call.arguments).toHaveLength(0);
      });
    });

    it('should handle IIFE (Immediately Invoked Function Expression)', async () => {
      const code = `
(function() {
    doSomething();
})();

(() => {
    doSomethingElse();
})();
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      const doSomethingCall = calls.find(c => c.method_name === 'doSomething');
      expect(doSomethingCall).toBeDefined();

      const doSomethingElseCall = calls.find(c => c.method_name === 'doSomethingElse');
      expect(doSomethingElseCall).toBeDefined();
    });

    it('should handle template literals in arguments', async () => {
      const code = `
console.log(\`Hello, \${name}!\`);
db.query(\`SELECT * FROM users WHERE id = \${id}\`);
`;
      const tree = await parse(code, 'javascript');
      const calls = extractCalls(tree, undefined, 'javascript');

      expect(calls.length).toBeGreaterThanOrEqual(2);
    });
  });
});
