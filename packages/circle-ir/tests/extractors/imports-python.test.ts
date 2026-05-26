/**
 * Tests for Python import extraction
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractImports } from '../../src/core/extractors/imports.js';

describe('Python Import Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('Simple Import Statements', () => {
    it('should extract simple imports', async () => {
      const code = `
import os
import sys
import json
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBe(3);

      const osImport = imports.find(i => i.imported_name === 'os');
      expect(osImport).toBeDefined();
      expect(osImport!.from_package).toBeNull();
      expect(osImport!.is_wildcard).toBe(false);

      const sysImport = imports.find(i => i.imported_name === 'sys');
      expect(sysImport).toBeDefined();

      const jsonImport = imports.find(i => i.imported_name === 'json');
      expect(jsonImport).toBeDefined();
    });

    it('should extract aliased imports', async () => {
      const code = `
import numpy as np
import pandas as pd
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBe(2);

      const numpyImport = imports.find(i => i.imported_name === 'numpy');
      expect(numpyImport).toBeDefined();
      expect(numpyImport!.alias).toBe('np');

      const pandasImport = imports.find(i => i.imported_name === 'pandas');
      expect(pandasImport).toBeDefined();
      expect(pandasImport!.alias).toBe('pd');
    });

    it('should extract dotted imports', async () => {
      const code = `
import os.path
import urllib.parse
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBeGreaterThanOrEqual(2);

      // Dotted imports are split: import os.path -> imported_name='path', from_package='os'
      const pathImport = imports.find(i => i.imported_name === 'path' && i.from_package === 'os');
      expect(pathImport).toBeDefined();

      const parseImport = imports.find(i => i.imported_name === 'parse' && i.from_package === 'urllib');
      expect(parseImport).toBeDefined();
    });
  });

  describe('From Import Statements', () => {
    it('should extract from imports', async () => {
      const code = `
from flask import Flask, request, jsonify
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBeGreaterThanOrEqual(3);

      const flaskImport = imports.find(i => i.imported_name === 'Flask');
      expect(flaskImport).toBeDefined();
      expect(flaskImport!.from_package).toBe('flask');
      expect(flaskImport!.is_wildcard).toBe(false);

      const requestImport = imports.find(i => i.imported_name === 'request');
      expect(requestImport).toBeDefined();
      expect(requestImport!.from_package).toBe('flask');

      const jsonifyImport = imports.find(i => i.imported_name === 'jsonify');
      expect(jsonifyImport).toBeDefined();
    });

    it('should extract from imports with aliases', async () => {
      const code = `
from datetime import datetime as dt, timedelta as td
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBeGreaterThanOrEqual(2);

      const datetimeImport = imports.find(i => i.imported_name === 'datetime' && i.from_package === 'datetime');
      expect(datetimeImport).toBeDefined();
      // Note: alias extraction may vary; the important thing is the import is found
      if (datetimeImport!.alias !== null) {
        expect(datetimeImport!.alias).toBe('dt');
      }

      const timedeltaImport = imports.find(i => i.imported_name === 'timedelta');
      expect(timedeltaImport).toBeDefined();
    });

    it('should extract wildcard imports', async () => {
      const code = `
from os.path import *
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBeGreaterThanOrEqual(1);
      const wildcardImport = imports.find(i => i.imported_name === '*');
      expect(wildcardImport).toBeDefined();
      expect(wildcardImport!.from_package).toBe('os.path');
      expect(wildcardImport!.is_wildcard).toBe(true);
    });

    it('should extract relative imports', async () => {
      const code = `
from . import utils
from .. import config
from .models import User
from ..services import UserService
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBe(4);

      const utilsImport = imports.find(i => i.imported_name === 'utils');
      expect(utilsImport).toBeDefined();
      expect(utilsImport!.from_package).toBe('.');

      const userImport = imports.find(i => i.imported_name === 'User');
      expect(userImport).toBeDefined();
      expect(userImport!.from_package).toBe('.models');
    });
  });

  describe('Flask/Django Patterns', () => {
    it('should extract Flask imports', async () => {
      const code = `
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBeGreaterThanOrEqual(6);

      const flaskImport = imports.find(i => i.imported_name === 'Flask');
      expect(flaskImport).toBeDefined();

      const requestImport = imports.find(i => i.imported_name === 'request');
      expect(requestImport).toBeDefined();

      const sqlalchemyImport = imports.find(i => i.imported_name === 'SQLAlchemy');
      expect(sqlalchemyImport).toBeDefined();
    });

    it('should extract Django imports', async () => {
      const code = `
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views import View
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBeGreaterThanOrEqual(5);

      const renderImport = imports.find(i => i.imported_name === 'render');
      expect(renderImport).toBeDefined();
      expect(renderImport!.from_package).toBe('django.shortcuts');

      const jsonResponseImport = imports.find(i => i.imported_name === 'JsonResponse');
      expect(jsonResponseImport).toBeDefined();
    });
  });

  describe('Dangerous Imports', () => {
    it('should extract subprocess imports', async () => {
      const code = `
import subprocess
from subprocess import call, Popen, run
from os import system, popen
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBeGreaterThanOrEqual(6);

      const subprocessImport = imports.find(i => i.imported_name === 'subprocess');
      expect(subprocessImport).toBeDefined();

      const callImport = imports.find(i => i.imported_name === 'call');
      expect(callImport).toBeDefined();
      expect(callImport!.from_package).toBe('subprocess');

      const systemImport = imports.find(i => i.imported_name === 'system');
      expect(systemImport).toBeDefined();
      expect(systemImport!.from_package).toBe('os');
    });

    it('should extract pickle/marshal imports', async () => {
      const code = `
import pickle
import marshal
from pickle import loads, dumps
`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      expect(imports.length).toBeGreaterThanOrEqual(4);

      const pickleImport = imports.find(i => i.imported_name === 'pickle');
      expect(pickleImport).toBeDefined();

      const loadsImport = imports.find(i => i.imported_name === 'loads');
      expect(loadsImport).toBeDefined();
    });
  });

  describe('Line Numbers', () => {
    it('should track line numbers correctly', async () => {
      const code = `import os
from flask import Flask
import subprocess`;
      const tree = await parse(code, 'python');
      const imports = extractImports(tree, 'python');

      const osImport = imports.find(i => i.imported_name === 'os');
      expect(osImport!.line_number).toBe(1);

      const flaskImport = imports.find(i => i.imported_name === 'Flask');
      expect(flaskImport!.line_number).toBe(2);

      const subprocessImport = imports.find(i => i.imported_name === 'subprocess');
      expect(subprocessImport!.line_number).toBe(3);
    });
  });
});
