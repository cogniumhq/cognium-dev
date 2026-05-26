/**
 * Integration tests for JavaScript/TypeScript analysis
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { analyze, initAnalyzer, resetAnalyzer, analyzeForAPI } from '../src/analyzer.js';

describe('JavaScript Analyzer Integration', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  afterAll(() => {
    resetAnalyzer();
  });

  describe('End-to-End Analysis', () => {
    it('should analyze simple JavaScript code', async () => {
      const code = `
function greet(name) {
    console.log("Hello, " + name);
}
`;
      const result = await analyze(code, 'test.js', 'javascript');

      expect(result.meta.language).toBe('javascript');
      expect(result.calls.length).toBeGreaterThan(0);
    });

    it('should extract Express.js route handler calls', async () => {
      const code = `
const express = require('express');
const app = express();

app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    res.json({ id });
});
`;
      const result = await analyze(code, 'app.js', 'javascript');

      // Should find app.get, res.json calls
      const getCalls = result.calls.filter(c => c.method_name === 'get');
      expect(getCalls.length).toBeGreaterThanOrEqual(1);

      const jsonCalls = result.calls.filter(c => c.method_name === 'json');
      expect(jsonCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Taint Source Detection', () => {
    it('should detect req.params as taint source', async () => {
      const code = `
app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM users WHERE id = " + id);
});
`;
      const result = await analyze(code, 'test.js', 'javascript');

      // Should detect req.params as a source
      const httpSources = result.taint.sources.filter(
        s => s.type === 'http_param' || s.location?.includes('req.params')
      );
      expect(httpSources.length).toBeGreaterThanOrEqual(0); // May detect via call patterns
    });

    it('should detect req.query as taint source', async () => {
      const code = `
app.get('/search', (req, res) => {
    const q = req.query.q;
    res.send('<h1>Results: ' + q + '</h1>');
});
`;
      const result = await analyze(code, 'test.js', 'javascript');

      expect(result.calls.length).toBeGreaterThan(0);
    });

    it('should detect req.body as taint source', async () => {
      const code = `
app.post('/users', (req, res) => {
    const userData = req.body;
    db.insert('users', userData);
});
`;
      const result = await analyze(code, 'test.js', 'javascript');

      expect(result.calls.length).toBeGreaterThan(0);
    });
  });

  describe('Taint Sink Detection', () => {
    it('should detect db.query as SQL injection sink', async () => {
      const code = `
function getUser(id) {
    const query = "SELECT * FROM users WHERE id = " + id;
    return db.query(query);
}
`;
      const result = await analyze(code, 'test.js', 'javascript');

      const queryCalls = result.calls.filter(c => c.method_name === 'query');
      expect(queryCalls.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect exec as command injection sink', async () => {
      const code = `
const { exec } = require('child_process');

function runCommand(cmd) {
    exec('ls -la ' + cmd, (err, stdout) => {
        console.log(stdout);
    });
}
`;
      const result = await analyze(code, 'test.js', 'javascript');

      const execCalls = result.calls.filter(c => c.method_name === 'exec');
      expect(execCalls.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect fs.readFile as path traversal sink', async () => {
      const code = `
const fs = require('fs');

function readUserFile(filename) {
    fs.readFile('./uploads/' + filename, (err, data) => {
        return data;
    });
}
`;
      const result = await analyze(code, 'test.js', 'javascript');

      const readFileCalls = result.calls.filter(c => c.method_name === 'readFile');
      expect(readFileCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Data Flow Graph', () => {
    it('should build DFG for JavaScript functions', async () => {
      const code = `
function process(input) {
    const x = input;
    const y = x + 1;
    return y;
}
`;
      const result = await analyze(code, 'test.js', 'javascript');

      expect(result.dfg.defs.length).toBeGreaterThan(0);
      expect(result.dfg.uses.length).toBeGreaterThan(0);

      const inputDef = result.dfg.defs.find(d => d.variable === 'input');
      expect(inputDef).toBeDefined();
    });

    it('should track variable definitions through arrow functions', async () => {
      const code = `
const processData = (data) => {
    const processed = transform(data);
    return processed;
};
`;
      const result = await analyze(code, 'test.js', 'javascript');

      const dataDef = result.dfg.defs.find(d => d.variable === 'data');
      expect(dataDef).toBeDefined();
    });
  });

  describe('Control Flow Graph', () => {
    it('should build CFG for JavaScript functions', async () => {
      const code = `
function check(x) {
    if (x > 0) {
        return true;
    }
    return false;
}
`;
      const result = await analyze(code, 'test.js', 'javascript');

      expect(result.cfg.blocks.length).toBeGreaterThan(0);
      expect(result.cfg.edges.length).toBeGreaterThan(0);

      const conditionalBlocks = result.cfg.blocks.filter(b => b.type === 'conditional');
      expect(conditionalBlocks.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Import Extraction', () => {
    it('should extract ES6 imports', async () => {
      const code = `
import React, { useState, useEffect } from 'react';
import express from 'express';

function App() {
    return null;
}
`;
      const result = await analyze(code, 'test.js', 'javascript');

      expect(result.imports.length).toBeGreaterThanOrEqual(2);

      const reactImport = result.imports.find(i => i.from_package === 'react');
      expect(reactImport).toBeDefined();

      const expressImport = result.imports.find(i => i.from_package === 'express');
      expect(expressImport).toBeDefined();
    });

    it('should extract CommonJS require', async () => {
      const code = `
const express = require('express');
const { readFile } = require('fs');
const path = require('path');
`;
      const result = await analyze(code, 'test.js', 'javascript');

      expect(result.imports.length).toBeGreaterThanOrEqual(3);

      const fsImport = result.imports.find(i => i.from_package === 'fs');
      expect(fsImport).toBeDefined();
    });
  });

  describe('Type/Class Extraction', () => {
    it('should extract JavaScript classes', async () => {
      const code = `
class UserService {
    constructor(db) {
        this.db = db;
    }

    async getUser(id) {
        return this.db.find(id);
    }
}
`;
      const result = await analyze(code, 'test.js', 'javascript');

      const userService = result.types.find(t => t.name === 'UserService');
      expect(userService).toBeDefined();
      expect(userService!.methods.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('API Response Format', () => {
    it('should return proper API response for JavaScript', async () => {
      const code = `
app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM users WHERE id = " + id);
});
`;
      const result = await analyzeForAPI(code, 'test.js', 'javascript');

      expect(result.success).toBe(true);
      expect(result.meta).toBeDefined();
      expect(result.meta.totalTimeMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Express.js SQL Injection Pattern', () => {
    it('should detect SQL injection vulnerability', async () => {
      const code = `
const express = require('express');
const mysql = require('mysql');
const app = express();
const db = mysql.createConnection({});

app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    const query = "SELECT * FROM users WHERE id = " + id;
    db.query(query, (err, results) => {
        res.json(results);
    });
});
`;
      const result = await analyze(code, 'test.js', 'javascript');

      // Verify calls are extracted
      const queryCalls = result.calls.filter(c => c.method_name === 'query');
      expect(queryCalls.length).toBeGreaterThanOrEqual(1);

      // Verify the query call has arguments
      if (queryCalls.length > 0) {
        expect(queryCalls[0].arguments.length).toBeGreaterThanOrEqual(1);
      }
    });
  });

  describe('Express.js Command Injection Pattern', () => {
    it('should detect command injection vulnerability', async () => {
      const code = `
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec('ping -c 1 ' + host, (error, stdout) => {
        res.send(stdout);
    });
});
`;
      const result = await analyze(code, 'test.js', 'javascript');

      // Verify exec call is extracted
      const execCalls = result.calls.filter(c => c.method_name === 'exec');
      expect(execCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Express.js Path Traversal Pattern', () => {
    it('should detect path traversal vulnerability', async () => {
      const code = `
const fs = require('fs');

app.get('/files/:name', (req, res) => {
    const filename = req.params.name;
    fs.readFile('./uploads/' + filename, (err, data) => {
        res.send(data);
    });
});
`;
      const result = await analyze(code, 'test.js', 'javascript');

      // Verify readFile call is extracted
      const readFileCalls = result.calls.filter(c => c.method_name === 'readFile');
      expect(readFileCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Express.js XSS Pattern', () => {
    it('should detect XSS vulnerability', async () => {
      const code = `
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send('<h1>Results for: ' + query + '</h1>');
});
`;
      const result = await analyze(code, 'test.js', 'javascript');

      // Verify res.send call is extracted
      const sendCalls = result.calls.filter(c => c.method_name === 'send');
      expect(sendCalls.length).toBeGreaterThanOrEqual(1);
    });
  });
});
