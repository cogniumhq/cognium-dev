/**
 * Tests for JavaScript/TypeScript import extraction
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractImports } from '../../src/core/extractors/imports.js';

describe('JavaScript Import Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('ES6 Named Imports', () => {
    it('should extract named imports', async () => {
      const code = `
import { useState, useEffect } from 'react';
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(2);

      const useState = imports.find(i => i.imported_name === 'useState');
      expect(useState).toBeDefined();
      expect(useState!.from_package).toBe('react');
      expect(useState!.is_wildcard).toBe(false);

      const useEffect = imports.find(i => i.imported_name === 'useEffect');
      expect(useEffect).toBeDefined();
    });

    it('should extract named imports with aliases', async () => {
      const code = `
import { useState as state, useEffect as effect } from 'react';
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(2);

      const useState = imports.find(i => i.imported_name === 'useState');
      expect(useState).toBeDefined();
      expect(useState!.alias).toBe('state');

      const useEffect = imports.find(i => i.imported_name === 'useEffect');
      expect(useEffect).toBeDefined();
      expect(useEffect!.alias).toBe('effect');
    });
  });

  describe('ES6 Default Imports', () => {
    it('should extract default imports', async () => {
      const code = `
import React from 'react';
import express from 'express';
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(2);

      const react = imports.find(i => i.alias === 'React');
      expect(react).toBeDefined();
      expect(react!.imported_name).toBe('default');
      expect(react!.from_package).toBe('react');

      const exp = imports.find(i => i.alias === 'express');
      expect(exp).toBeDefined();
      expect(exp!.imported_name).toBe('default');
    });
  });

  describe('ES6 Namespace Imports', () => {
    it('should extract namespace imports', async () => {
      const code = `
import * as utils from './utils';
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(1);
      expect(imports[0].imported_name).toBe('*');
      expect(imports[0].alias).toBe('utils');
      expect(imports[0].is_wildcard).toBe(true);
      expect(imports[0].from_package).toBe('./utils');
    });
  });

  describe('ES6 Mixed Imports', () => {
    it('should extract default and named imports together', async () => {
      const code = `
import React, { useState, useEffect } from 'react';
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(3);

      const defaultImport = imports.find(i => i.imported_name === 'default');
      expect(defaultImport).toBeDefined();
      expect(defaultImport!.alias).toBe('React');

      const useState = imports.find(i => i.imported_name === 'useState');
      expect(useState).toBeDefined();

      const useEffect = imports.find(i => i.imported_name === 'useEffect');
      expect(useEffect).toBeDefined();
    });
  });

  describe('ES6 Side-Effect Imports', () => {
    it('should extract side-effect imports', async () => {
      const code = `
import './styles.css';
import 'polyfills';
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(2);

      const stylesImport = imports.find(i => i.from_package === './styles.css');
      expect(stylesImport).toBeDefined();
      expect(stylesImport!.is_wildcard).toBe(true);
      expect(stylesImport!.imported_name).toBe('*');
    });
  });

  describe('CommonJS require', () => {
    it('should extract simple require calls', async () => {
      const code = `
const express = require('express');
const path = require('path');
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(2);

      const expressImport = imports.find(i => i.from_package === 'express');
      expect(expressImport).toBeDefined();
      expect(expressImport!.alias).toBe('express');
      expect(expressImport!.is_wildcard).toBe(true);

      const pathImport = imports.find(i => i.from_package === 'path');
      expect(pathImport).toBeDefined();
    });

    it('should extract destructured require calls', async () => {
      const code = `
const { readFile, writeFile } = require('fs');
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(2);

      const readFileImport = imports.find(i => i.imported_name === 'readFile');
      expect(readFileImport).toBeDefined();
      expect(readFileImport!.from_package).toBe('fs');
      expect(readFileImport!.is_wildcard).toBe(false);

      const writeFileImport = imports.find(i => i.imported_name === 'writeFile');
      expect(writeFileImport).toBeDefined();
    });
  });

  describe('Express.js Patterns', () => {
    it('should extract Express.js imports', async () => {
      const code = `
const express = require('express');
const { Router } = require('express');
const bodyParser = require('body-parser');
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(3);

      const expressImport = imports.find(i => i.alias === 'express');
      expect(expressImport).toBeDefined();

      const routerImport = imports.find(i => i.imported_name === 'Router');
      expect(routerImport).toBeDefined();

      const bodyParserImport = imports.find(i => i.alias === 'bodyParser');
      expect(bodyParserImport).toBeDefined();
    });
  });

  describe('Node.js Built-in Modules', () => {
    it('should extract built-in module imports', async () => {
      const code = `
const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');
const http = require('http');
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      expect(imports.length).toBe(5);

      const fsImport = imports.find(i => i.from_package === 'fs');
      expect(fsImport).toBeDefined();

      const childProcessImports = imports.filter(i => i.from_package === 'child_process');
      expect(childProcessImports.length).toBe(2);
    });
  });

  describe('Line Numbers', () => {
    it('should track line numbers correctly', async () => {
      const code = `import React from 'react';
import { useState } from 'react';
const express = require('express');
`;
      const tree = await parse(code, 'javascript');
      const imports = extractImports(tree, 'javascript');

      const reactImport = imports.find(i => i.alias === 'React');
      expect(reactImport!.line_number).toBe(1);

      const useStateImport = imports.find(i => i.imported_name === 'useState');
      expect(useStateImport!.line_number).toBe(2);

      const expressImport = imports.find(i => i.from_package === 'express');
      expect(expressImport!.line_number).toBe(3);
    });
  });
});
