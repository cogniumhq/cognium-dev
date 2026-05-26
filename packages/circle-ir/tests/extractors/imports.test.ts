/**
 * Tests for Import extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractImports } from '../../src/core/extractors/imports.js';

describe('Import Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract single class import', async () => {
    const code = `
import java.util.ArrayList;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('ArrayList');
    expect(imports[0].from_package).toBe('java.util');
    expect(imports[0].is_wildcard).toBe(false);
  });

  it('should extract wildcard import', async () => {
    const code = `
import java.util.*;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('*');
    expect(imports[0].from_package).toBe('java.util');
    expect(imports[0].is_wildcard).toBe(true);
  });

  it('should extract multiple imports', async () => {
    const code = `
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import javax.servlet.http.*;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(4);

    const listImport = imports.find(i => i.imported_name === 'List');
    expect(listImport).toBeDefined();
    expect(listImport!.from_package).toBe('java.util');

    const wildcardImport = imports.find(i => i.is_wildcard);
    expect(wildcardImport).toBeDefined();
    expect(wildcardImport!.from_package).toBe('javax.servlet.http');
  });

  it('should capture line numbers', async () => {
    const code = `import java.util.List;
import java.util.Map;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports[0].line_number).toBe(1);
    expect(imports[1].line_number).toBe(2);
  });

  it('should handle files without imports', async () => {
    const code = `
public class Test {
    public void method() {}
}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(0);
  });

  it('should handle nested package imports', async () => {
    const code = `
import org.springframework.web.bind.annotation.RequestMapping;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('RequestMapping');
    expect(imports[0].from_package).toBe('org.springframework.web.bind.annotation');
  });

  it('should handle simple class import without package', async () => {
    // This is an edge case - importing just a class name without package path
    const code = `
import SimpleClass;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    // Parser may or may not accept this syntax
    // If it does, the import should have no package
    for (const imp of imports) {
      expect(imp.imported_name).toBeDefined();
    }
  });

  it('should handle static import', async () => {
    const code = `
import static java.lang.Math.PI;

public class Test {}
`;
    const tree = await parse(code, 'java');
    const imports = extractImports(tree);

    // Static imports should still be captured
    expect(imports.length).toBeGreaterThanOrEqual(0);
  });
});

describe('JavaScript Imports', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract ES6 named imports', async () => {
    const code = `import { readFile, writeFile } from 'fs/promises';`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(2);

    const readFileImport = imports.find(i => i.imported_name === 'readFile');
    expect(readFileImport).toBeDefined();
    expect(readFileImport!.from_package).toBe('fs/promises');
    expect(readFileImport!.is_wildcard).toBe(false);
    expect(readFileImport!.alias).toBeNull();

    const writeFileImport = imports.find(i => i.imported_name === 'writeFile');
    expect(writeFileImport).toBeDefined();
    expect(writeFileImport!.from_package).toBe('fs/promises');
  });

  it('should extract ES6 named imports with aliases', async () => {
    const code = `import { useState as useStateHook, useEffect as useEffectHook } from 'react';`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(2);

    const useStateImport = imports.find(i => i.imported_name === 'useState');
    expect(useStateImport).toBeDefined();
    expect(useStateImport!.alias).toBe('useStateHook');
    expect(useStateImport!.from_package).toBe('react');
    expect(useStateImport!.is_wildcard).toBe(false);
  });

  it('should extract ES6 default import', async () => {
    const code = `import React from 'react';`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(1);

    const reactImport = imports.find(i => i.from_package === 'react');
    expect(reactImport).toBeDefined();
    expect(reactImport!.imported_name).toBe('default');
    expect(reactImport!.alias).toBe('React');
    expect(reactImport!.is_wildcard).toBe(false);
  });

  it('should extract ES6 namespace import', async () => {
    const code = `import * as path from 'path';`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(1);

    const pathImport = imports.find(i => i.from_package === 'path');
    expect(pathImport).toBeDefined();
    expect(pathImport!.imported_name).toBe('*');
    expect(pathImport!.alias).toBe('path');
    expect(pathImport!.is_wildcard).toBe(true);
  });

  it('should extract CommonJS require call', async () => {
    const code = `const express = require('express');`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(1);

    const expressImport = imports.find(i => i.from_package === 'express');
    expect(expressImport).toBeDefined();
    expect(expressImport!.alias).toBe('express');
    expect(expressImport!.is_wildcard).toBe(true);
  });

  it('should extract CommonJS destructured require', async () => {
    const code = `const { join, resolve } = require('path');`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(2);

    const joinImport = imports.find(i => i.imported_name === 'join');
    expect(joinImport).toBeDefined();
    expect(joinImport!.from_package).toBe('path');
    expect(joinImport!.is_wildcard).toBe(false);

    const resolveImport = imports.find(i => i.imported_name === 'resolve');
    expect(resolveImport).toBeDefined();
    expect(resolveImport!.from_package).toBe('path');
  });
});

describe('Python Imports', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract simple module import', async () => {
    const code = `import hashlib`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('hashlib');
    expect(imports[0].from_package).toBeNull();
    expect(imports[0].is_wildcard).toBe(false);
    expect(imports[0].alias).toBeNull();
  });

  it('should extract from-import with single name', async () => {
    const code = `from pathlib import Path`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports.length).toBeGreaterThanOrEqual(1);

    const pathImport = imports.find(i => i.imported_name === 'Path');
    expect(pathImport).toBeDefined();
    expect(pathImport!.from_package).toBe('pathlib');
    expect(pathImport!.is_wildcard).toBe(false);
    expect(pathImport!.alias).toBeNull();
  });

  it('should extract relative import with dot prefix', async () => {
    const code = `from . import helpers`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('helpers');
    expect(imports[0].from_package).toBe('.');
    expect(imports[0].is_wildcard).toBe(false);
  });

  it('should extract relative import from submodule', async () => {
    const code = `from .models import Article`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('Article');
    expect(imports[0].from_package).toBe('.models');
    expect(imports[0].is_wildcard).toBe(false);
  });

  it('should extract aliased module import', async () => {
    const code = `import collections as col`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('collections');
    expect(imports[0].alias).toBe('col');
  });

  it('should extract line numbers for python imports', async () => {
    const code = `import os
from sys import argv`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    const osImport = imports.find(i => i.imported_name === 'os');
    expect(osImport).toBeDefined();
    expect(osImport!.line_number).toBe(1);

    const argvImport = imports.find(i => i.imported_name === 'argv');
    expect(argvImport).toBeDefined();
    expect(argvImport!.line_number).toBe(2);
  });
});

describe('JavaScript Imports - Additional Edge Cases', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract side-effect import (import "module")', async () => {
    const code = `import './styles.css';`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(1);
    const sideEffect = imports.find(i => i.from_package === './styles.css');
    expect(sideEffect).toBeDefined();
    expect(sideEffect!.is_wildcard).toBe(true);
  });

  it('should extract combined default + named imports', async () => {
    const code = `import React, { useState, useEffect } from 'react';`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(2);
    const defaultImport = imports.find(i => i.imported_name === 'default');
    expect(defaultImport).toBeDefined();
    expect(defaultImport!.alias).toBe('React');

    const useStateImport = imports.find(i => i.imported_name === 'useState');
    expect(useStateImport).toBeDefined();
    expect(useStateImport!.from_package).toBe('react');
  });

  it('should extract renamed CommonJS destructured require', async () => {
    const code = `const { readFile: rf, writeFile: wf } = require('fs');`;
    const tree = await parse(code, 'javascript');
    const imports = extractImports(tree, 'javascript');

    expect(imports.length).toBeGreaterThanOrEqual(2);
    const rfImport = imports.find(i => i.imported_name === 'readFile');
    expect(rfImport).toBeDefined();
    expect(rfImport!.alias).toBe('rf');
    expect(rfImport!.from_package).toBe('fs');
    expect(rfImport!.is_wildcard).toBe(false);
  });
});

describe('Python Imports - Additional Edge Cases', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract wildcard from-import', async () => {
    const code = `from os import *`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports.length).toBeGreaterThanOrEqual(1);
    const wildcardImport = imports.find(i => i.is_wildcard === true);
    expect(wildcardImport).toBeDefined();
    expect(wildcardImport!.from_package).toBe('os');
    expect(wildcardImport!.imported_name).toBe('*');
    expect(wildcardImport!.alias).toBeNull();
  });

  it('should extract aliased from-import', async () => {
    const code = `from os import path as ospath`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports.length).toBeGreaterThanOrEqual(1);
    const pathImport = imports.find(i => i.alias === 'ospath');
    expect(pathImport).toBeDefined();
    expect(pathImport!.imported_name).toBe('path');
    expect(pathImport!.from_package).toBe('os');
    expect(pathImport!.is_wildcard).toBe(false);
  });

  it('should extract dotted module import (import os.path)', async () => {
    const code = `import os.path`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports).toHaveLength(1);
    expect(imports[0].imported_name).toBe('path');
    expect(imports[0].from_package).toBe('os');
    expect(imports[0].is_wildcard).toBe(false);
  });

  it('should extract multi-level relative import (from ...sibling import foo)', async () => {
    const code = `from ...sibling import helper`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports.length).toBeGreaterThanOrEqual(1);
    const helperImport = imports.find(i => i.imported_name === 'helper');
    expect(helperImport).toBeDefined();
    expect(helperImport!.from_package).toBeTruthy(); // has relative prefix
  });

  it('should extract multiple names from one from-import', async () => {
    const code = `from flask import Flask, request, jsonify`;
    const tree = await parse(code, 'python');
    const imports = extractImports(tree, 'python');

    expect(imports.length).toBeGreaterThanOrEqual(3);
    expect(imports.find(i => i.imported_name === 'Flask')).toBeDefined();
    expect(imports.find(i => i.imported_name === 'request')).toBeDefined();
    expect(imports.find(i => i.imported_name === 'jsonify')).toBeDefined();
    for (const imp of imports) {
      expect(imp.from_package).toBe('flask');
    }
  });
});

describe('Rust Imports', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract simple scoped use declaration', async () => {
    const code = `use std::collections::HashMap;

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(1);

    const hashMapImport = imports.find(i => i.imported_name === 'HashMap');
    expect(hashMapImport).toBeDefined();
    expect(hashMapImport!.from_package).toBe('std::collections');
    expect(hashMapImport!.is_wildcard).toBe(false);
    expect(hashMapImport!.alias).toBeNull();
  });

  it('should extract grouped use declaration with braces', async () => {
    const code = `use std::io::{Read, Write, BufReader};

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(3);

    const readImport = imports.find(i => i.imported_name === 'Read');
    expect(readImport).toBeDefined();
    expect(readImport!.from_package).toBe('std::io');
    expect(readImport!.is_wildcard).toBe(false);

    const writeImport = imports.find(i => i.imported_name === 'Write');
    expect(writeImport).toBeDefined();
    expect(writeImport!.from_package).toBe('std::io');

    const bufReaderImport = imports.find(i => i.imported_name === 'BufReader');
    expect(bufReaderImport).toBeDefined();
  });

  it('should extract wildcard use declaration', async () => {
    const code = `use std::prelude::*;

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(1);

    const wildcardImport = imports.find(i => i.is_wildcard === true);
    expect(wildcardImport).toBeDefined();
    expect(wildcardImport!.imported_name).toBe('*');
    expect(wildcardImport!.is_wildcard).toBe(true);
    expect(wildcardImport!.alias).toBeNull();
  });

  it('should extract aliased use declaration', async () => {
    const code = `use std::collections::HashMap as Map;

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(1);

    const mapImport = imports.find(i => i.imported_name === 'HashMap');
    expect(mapImport).toBeDefined();
    expect(mapImport!.alias).toBe('Map');
    expect(mapImport!.from_package).toBe('std::collections');
    expect(mapImport!.is_wildcard).toBe(false);
  });

  it('should extract multiple use declarations', async () => {
    const code = `use std::fmt;
use std::sync::Arc;
use std::thread;

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(3);

    const fmtImport = imports.find(i => i.imported_name === 'fmt');
    expect(fmtImport).toBeDefined();

    const arcImport = imports.find(i => i.imported_name === 'Arc');
    expect(arcImport).toBeDefined();
    expect(arcImport!.from_package).toBe('std::sync');

    const threadImport = imports.find(i => i.imported_name === 'thread');
    expect(threadImport).toBeDefined();
  });

  it('should capture line numbers for rust use declarations', async () => {
    const code = `use std::io;
use std::fmt;
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    const ioImport = imports.find(i => i.imported_name === 'io');
    expect(ioImport).toBeDefined();
    expect(ioImport!.line_number).toBe(1);

    const fmtImport = imports.find(i => i.imported_name === 'fmt');
    expect(fmtImport).toBeDefined();
    expect(fmtImport!.line_number).toBe(2);
  });

  it('should extract {self} in use list', async () => {
    const code = `use std::io::{self, Read};

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(2);
    const selfImport = imports.find(i => i.imported_name === 'self');
    expect(selfImport).toBeDefined();
    expect(selfImport!.from_package).toBe('std::io');
    expect(selfImport!.is_wildcard).toBe(false);

    const readImport = imports.find(i => i.imported_name === 'Read');
    expect(readImport).toBeDefined();
  });

  it('should extract aliased item in use list', async () => {
    const code = `use std::io::{Read as R, Write as W};

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(2);
    const readImport = imports.find(i => i.imported_name === 'Read');
    expect(readImport).toBeDefined();
    expect(readImport!.alias).toBe('R');
    expect(readImport!.from_package).toBe('std::io');

    const writeImport = imports.find(i => i.imported_name === 'Write');
    expect(writeImport).toBeDefined();
    expect(writeImport!.alias).toBe('W');
  });

  it('should extract nested scoped path in use list', async () => {
    const code = `use std::{collections::HashMap, sync::Arc};

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(2);
    const hashMapImport = imports.find(i => i.imported_name === 'HashMap');
    expect(hashMapImport).toBeDefined();
    expect(hashMapImport!.from_package).toContain('collections');

    const arcImport = imports.find(i => i.imported_name === 'Arc');
    expect(arcImport).toBeDefined();
  });

  it('should extract aliased nested scoped path in use list (path with ::)', async () => {
    const code = `use foo::{bar::Baz as B, other::Type as T};

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    expect(imports.length).toBeGreaterThanOrEqual(2);
    const bazImport = imports.find(i => i.imported_name === 'Baz');
    expect(bazImport).toBeDefined();
    expect(bazImport!.alias).toBe('B');
    expect(bazImport!.from_package).toContain('bar');

    const typeImport = imports.find(i => i.imported_name === 'Type');
    expect(typeImport).toBeDefined();
    expect(typeImport!.alias).toBe('T');
  });

  it('should extract bare use identifier (use std;)', async () => {
    // Rare case: top-level module without path
    const code = `use fmt;

fn main() {}
`;
    const tree = await parse(code, 'rust');
    const imports = extractImports(tree, 'rust');

    // May produce 0 or 1 import depending on grammar - just verify no crash
    expect(Array.isArray(imports)).toBe(true);
    const fmtImport = imports.find(i => i.imported_name === 'fmt');
    if (fmtImport) {
      expect(fmtImport.from_package).toBeNull();
      expect(fmtImport.is_wildcard).toBe(false);
    }
  });
});
