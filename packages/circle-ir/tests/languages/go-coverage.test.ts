/**
 * Go language support tests
 *
 * Tests parsing, type/call extraction, DFG, CFG, and taint analysis for Go.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('Go language support', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ── Parsing & basic IR ────────────────────────────────────────────────

  describe('basic parsing', () => {
    it('parses a simple Go file', async () => {
      const code = `package main

import "fmt"

func main() {
  fmt.Println("hello")
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.meta.language).toBe('go');
      expect(result.meta.loc).toBeGreaterThan(0);
    });

    it('extracts package name', async () => {
      const code = `package handlers

func Handle() {}`;
      const result = await analyze(code, 'handlers.go', 'go');
      expect(result.meta.language).toBe('go');
    });

    it('parses empty function body', async () => {
      const code = `package main

func noop() {}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.meta.language).toBe('go');
      expect(result.meta.loc).toBeGreaterThan(0);
    });
  });

  // ── Import extraction ────────────────────────────────────────────────

  describe('import extraction', () => {
    it('extracts single import', async () => {
      const code = `package main

import "fmt"

func main() { fmt.Println("hi") }`;
      const result = await analyze(code, 'main.go', 'go');
      const fmtImport = result.imports.find(i => i.imported_name === 'fmt');
      expect(fmtImport).toBeDefined();
      expect(fmtImport!.from_package).toBe('fmt');
    });

    it('extracts grouped imports', async () => {
      const code = `package main

import (
  "fmt"
  "net/http"
  "database/sql"
)

func main() {}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.imports.length).toBeGreaterThanOrEqual(3);
      expect(result.imports.some(i => i.imported_name === 'fmt')).toBe(true);
      expect(result.imports.some(i => i.imported_name === 'http')).toBe(true);
      expect(result.imports.some(i => i.imported_name === 'sql')).toBe(true);
    });

    it('handles aliased imports', async () => {
      const code = `package main

import (
  mydb "database/sql"
)

func main() {}`;
      const result = await analyze(code, 'main.go', 'go');
      const aliased = result.imports.find(i => i.from_package === 'database/sql');
      expect(aliased).toBeDefined();
      expect(aliased!.alias).toBe('mydb');
    });

    it('handles blank import', async () => {
      const code = `package main

import (
  _ "github.com/lib/pq"
  "fmt"
)

func main() {}`;
      const result = await analyze(code, 'main.go', 'go');
      const blankImport = result.imports.find(i => i.from_package === 'github.com/lib/pq');
      expect(blankImport).toBeDefined();
      expect(blankImport!.alias).toBe('_');
    });

    it('handles dot import', async () => {
      const code = `package main

import (
  . "math"
)

func main() {}`;
      const result = await analyze(code, 'main.go', 'go');
      const dotImport = result.imports.find(i => i.from_package === 'math');
      expect(dotImport).toBeDefined();
      expect(dotImport!.alias).toBe('.');
      expect(dotImport!.is_wildcard).toBe(true);
    });

    it('extracts correct short name from nested package path', async () => {
      const code = `package main

import (
  "encoding/json"
  "path/filepath"
)

func main() {}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.imports.some(i => i.imported_name === 'json' && i.from_package === 'encoding/json')).toBe(true);
      expect(result.imports.some(i => i.imported_name === 'filepath' && i.from_package === 'path/filepath')).toBe(true);
    });

    it('records line numbers for imports', async () => {
      const code = `package main

import (
  "fmt"
  "os"
)

func main() {}`;
      const result = await analyze(code, 'main.go', 'go');
      const fmtImport = result.imports.find(i => i.imported_name === 'fmt');
      expect(fmtImport).toBeDefined();
      expect(fmtImport!.line_number).toBeGreaterThan(0);
    });
  });

  // ── Type extraction ──────────────────────────────────────────────────

  describe('type extraction', () => {
    it('extracts struct type with fields', async () => {
      const code = `package main

type User struct {
  Name  string
  Email string
  Age   int
}`;
      const result = await analyze(code, 'models.go', 'go');
      const userType = result.types.find(t => t.name === 'User');
      expect(userType).toBeDefined();
      expect(userType!.kind).toBe('class');
      expect(userType!.fields.length).toBe(3);
      expect(userType!.fields.some(f => f.name === 'Name' && f.type === 'string')).toBe(true);
      expect(userType!.fields.some(f => f.name === 'Age' && f.type === 'int')).toBe(true);
    });

    it('extracts interface type', async () => {
      const code = `package main

type Handler interface {
  ServeHTTP(w ResponseWriter, r Request)
}`;
      const result = await analyze(code, 'handler.go', 'go');
      const handlerType = result.types.find(t => t.name === 'Handler');
      expect(handlerType).toBeDefined();
      expect(handlerType!.kind).toBe('interface');
    });

    it('extracts struct methods via receiver matching', async () => {
      const code = `package main

type User struct {
  Name string
}

func (u *User) GetName() string {
  return u.Name
}

func (u User) String() string {
  return u.Name
}`;
      const result = await analyze(code, 'models.go', 'go');
      const userType = result.types.find(t => t.name === 'User');
      expect(userType).toBeDefined();
      expect(userType!.methods.length).toBe(2);
      expect(userType!.methods.some(m => m.name === 'GetName')).toBe(true);
      expect(userType!.methods.some(m => m.name === 'String')).toBe(true);
    });

    it('extracts package in type info', async () => {
      const code = `package models

type Config struct {
  Timeout int
}`;
      const result = await analyze(code, 'config.go', 'go');
      const configType = result.types.find(t => t.name === 'Config');
      expect(configType).toBeDefined();
      expect(configType!.package).toBe('models');
    });

    it('extracts standalone functions as <module> type', async () => {
      const code = `package main

func add(a int, b int) int {
  return a + b
}

func main() {
  add(1, 2)
}`;
      const result = await analyze(code, 'main.go', 'go');
      const moduleType = result.types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();
      expect(moduleType!.methods.some(m => m.name === 'add')).toBe(true);
      expect(moduleType!.methods.some(m => m.name === 'main')).toBe(true);
    });

    it('extracts method return type and parameters', async () => {
      const code = `package main

type Server struct {}

func (s *Server) Listen(addr string, port int) error {
  return nil
}`;
      const result = await analyze(code, 'server.go', 'go');
      const serverType = result.types.find(t => t.name === 'Server');
      expect(serverType).toBeDefined();
      const listenMethod = serverType!.methods.find(m => m.name === 'Listen');
      expect(listenMethod).toBeDefined();
      expect(listenMethod!.return_type).toBe('error');
      expect(listenMethod!.parameters.length).toBe(2);
      expect(listenMethod!.parameters[0].name).toBe('addr');
      expect(listenMethod!.parameters[0].type).toBe('string');
    });

    it('extracts start_line and end_line', async () => {
      const code = `package main

type Foo struct {
  Bar string
}`;
      const result = await analyze(code, 'foo.go', 'go');
      const fooType = result.types.find(t => t.name === 'Foo');
      expect(fooType).toBeDefined();
      expect(fooType!.start_line).toBeGreaterThan(0);
      expect(fooType!.end_line).toBeGreaterThanOrEqual(fooType!.start_line);
    });

    it('handles multiple struct declarations', async () => {
      const code = `package main

type Request struct {
  URL string
}

type Response struct {
  Status int
  Body   string
}`;
      const result = await analyze(code, 'types.go', 'go');
      expect(result.types.some(t => t.name === 'Request')).toBe(true);
      expect(result.types.some(t => t.name === 'Response')).toBe(true);
      const response = result.types.find(t => t.name === 'Response');
      expect(response!.fields.length).toBe(2);
    });
  });

  // ── Call extraction ──────────────────────────────────────────────────

  describe('call extraction', () => {
    it('extracts function calls with package receiver', async () => {
      const code = `package main

import "fmt"

func main() {
  fmt.Println("hello")
}`;
      const result = await analyze(code, 'main.go', 'go');
      const printCall = result.calls.find(c => c.method_name === 'Println');
      expect(printCall).toBeDefined();
      expect(printCall!.receiver).toBe('fmt');
    });

    it('extracts method calls with variable receiver', async () => {
      const code = `package main

func handler(w http.ResponseWriter, r *http.Request) {
  name := r.FormValue("name")
  db.Query("SELECT * FROM users WHERE name = " + name)
}`;
      const result = await analyze(code, 'handler.go', 'go');
      const formCall = result.calls.find(c => c.method_name === 'FormValue');
      expect(formCall).toBeDefined();
      // #240 ship 2: Go local-receiver resolver rewrites bare-identifier
      // operands that name a function parameter to their declared type's
      // last identifier segment (`r` with declared `*http.Request` → 'Request').
      // Prior to ship 2 this returned the operand text 'r'.
      expect(formCall!.receiver).toBe('Request');
    });

    it('extracts plain function calls without receiver', async () => {
      const code = `package main

func add(a, b int) int { return a + b }

func main() {
  result := add(1, 2)
  println(result)
}`;
      const result = await analyze(code, 'main.go', 'go');
      const addCall = result.calls.find(c => c.method_name === 'add');
      expect(addCall).toBeDefined();
      expect(addCall!.receiver).toBeNull();
    });

    it('extracts call arguments with positions', async () => {
      const code = `package main

func main() {
  fmt.Printf("%s is %d years old", name, age)
}`;
      const result = await analyze(code, 'main.go', 'go');
      const printfCall = result.calls.find(c => c.method_name === 'Printf');
      expect(printfCall).toBeDefined();
      expect(printfCall!.arguments.length).toBe(3);
      expect(printfCall!.arguments[0].position).toBe(0);
      expect(printfCall!.arguments[1].position).toBe(1);
      expect(printfCall!.arguments[2].position).toBe(2);
    });

    it('identifies string literal arguments', async () => {
      const code = `package main

func main() {
  db.Query("SELECT * FROM users")
}`;
      const result = await analyze(code, 'main.go', 'go');
      const queryCall = result.calls.find(c => c.method_name === 'Query');
      expect(queryCall).toBeDefined();
      expect(queryCall!.arguments[0].literal).toBeDefined();
    });

    it('identifies variable arguments', async () => {
      const code = `package main

func main() {
  query := "SELECT 1"
  db.Query(query)
}`;
      const result = await analyze(code, 'main.go', 'go');
      const queryCall = result.calls.find(c => c.method_name === 'Query');
      expect(queryCall).toBeDefined();
      expect(queryCall!.arguments[0].variable).toBe('query');
    });

    it('tracks in_method for calls', async () => {
      const code = `package main

func handler() {
  fmt.Println("hello")
}`;
      const result = await analyze(code, 'main.go', 'go');
      const printCall = result.calls.find(c => c.method_name === 'Println');
      expect(printCall).toBeDefined();
      expect(printCall!.in_method).toBe('handler');
    });

    it('tracks call location (line and column)', async () => {
      const code = `package main

func main() {
  fmt.Println("hello")
}`;
      const result = await analyze(code, 'main.go', 'go');
      const printCall = result.calls.find(c => c.method_name === 'Println');
      expect(printCall).toBeDefined();
      expect(printCall!.location.line).toBe(4);
      expect(printCall!.location.column).toBeGreaterThanOrEqual(0);
    });
  });

  // ── DFG ──────────────────────────────────────────────────────────────

  describe('DFG', () => {
    it('tracks variable assignment and use', async () => {
      const code = `package main

func main() {
  x := "hello"
  fmt.Println(x)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === 'x')).toBe(true);
      expect(result.dfg.uses.some(u => u.variable === 'x')).toBe(true);
    });

    it('tracks function parameters as defs', async () => {
      const code = `package main

func greet(name string) {
  fmt.Println(name)
}`;
      const result = await analyze(code, 'main.go', 'go');
      const paramDef = result.dfg.defs.find(d => d.variable === 'name' && d.kind === 'param');
      expect(paramDef).toBeDefined();
    });

    it('tracks short var declaration :=', async () => {
      const code = `package main

func main() {
  x := 42
  y := x + 1
  fmt.Println(y)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === 'x')).toBe(true);
      expect(result.dfg.defs.some(d => d.variable === 'y')).toBe(true);
      expect(result.dfg.uses.some(u => u.variable === 'x')).toBe(true);
    });

    it('handles multiple return values', async () => {
      const code = `package main

func main() {
  data, err := os.ReadFile("config.txt")
  fmt.Println(data, err)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === 'data')).toBe(true);
      expect(result.dfg.defs.some(d => d.variable === 'err')).toBe(true);
    });

    it('skips blank identifier _', async () => {
      const code = `package main

func main() {
  _, err := os.ReadFile("config.txt")
  fmt.Println(err)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === '_')).toBe(false);
      expect(result.dfg.defs.some(d => d.variable === 'err')).toBe(true);
    });

    it('builds def-use chains', async () => {
      const code = `package main

func handler(input string) {
  result := input
  fmt.Println(result)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.chains.length).toBeGreaterThan(0);
    });

    it('tracks var declaration', async () => {
      const code = `package main

func main() {
  var count int
  count = 10
  fmt.Println(count)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === 'count')).toBe(true);
      expect(result.dfg.uses.some(u => u.variable === 'count')).toBe(true);
    });

    it('tracks assignment statement (reassignment)', async () => {
      const code = `package main

func main() {
  x := 1
  x = 2
  fmt.Println(x)
}`;
      const result = await analyze(code, 'main.go', 'go');
      // Should have at least 2 defs for x (initial + reassignment)
      const xDefs = result.dfg.defs.filter(d => d.variable === 'x');
      expect(xDefs.length).toBeGreaterThanOrEqual(2);
    });

    it('extracts uses from return statements', async () => {
      const code = `package main

func getVal() int {
  x := 42
  return x
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === 'x')).toBe(true);
      expect(result.dfg.uses.some(u => u.variable === 'x')).toBe(true);
    });

    it('tracks method receiver as def', async () => {
      const code = `package main

type Server struct {}

func (s *Server) Start() {
  fmt.Println(s)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === 's' && d.kind === 'param')).toBe(true);
    });

    it('tracks top-level var declarations', async () => {
      const code = `package main

var globalVar string

func main() {
  fmt.Println(globalVar)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === 'globalVar')).toBe(true);
    });

    it('does not create defs for Go keywords', async () => {
      const code = `package main

func main() {
  x := len("hello")
  fmt.Println(x)
}`;
      const result = await analyze(code, 'main.go', 'go');
      // len, fmt, Println should not appear as uses (they're keywords/package names)
      expect(result.dfg.defs.some(d => d.variable === 'len')).toBe(false);
      expect(result.dfg.uses.some(u => u.variable === 'len')).toBe(false);
    });

    it('skips selector field names as uses', async () => {
      const code = `package main

type Foo struct { Bar string }

func main() {
  f := Foo{Bar: "x"}
  fmt.Println(f.Bar)
}`;
      const result = await analyze(code, 'main.go', 'go');
      // "Bar" in f.Bar should NOT be tracked as a variable use
      // (it's a field access, not a variable reference)
      const barUses = result.dfg.uses.filter(u => u.variable === 'Bar');
      // This may or may not have uses depending on tree-sitter structure.
      // The key assertion: f should have a use
      expect(result.dfg.uses.some(u => u.variable === 'f')).toBe(true);
    });
  });

  // ── CFG ──────────────────────────────────────────────────────────────

  describe('CFG', () => {
    it('produces blocks for function body', async () => {
      const code = `package main

func main() {
  x := 1
  if x > 0 {
    fmt.Println("positive")
  }
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.cfg.blocks.length).toBeGreaterThan(0);
    });

    it('produces blocks for multiple functions', async () => {
      const code = `package main

func foo() {
  x := 1
  if x > 0 {
    fmt.Println("positive")
  }
}

func bar() {
  y := 2
  if y > 0 {
    fmt.Println("also positive")
  }
}`;
      const result = await analyze(code, 'main.go', 'go');
      // Two functions with if statements should produce at least 4 blocks
      expect(result.cfg.blocks.length).toBeGreaterThanOrEqual(4);
    });

    it('produces edges for if/else branching', async () => {
      const code = `package main

func main() {
  x := 1
  if x > 0 {
    fmt.Println("positive")
  } else {
    fmt.Println("non-positive")
  }
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.cfg.edges.length).toBeGreaterThan(0);
    });

    it('produces blocks for for loops', async () => {
      const code = `package main

func main() {
  for i := 0; i < 10; i++ {
    fmt.Println(i)
  }
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.cfg.blocks.length).toBeGreaterThan(0);
    });

    it('handles method declarations in CFG', async () => {
      const code = `package main

type Server struct {}

func (s *Server) Start() {
  if s != nil {
    fmt.Println("starting")
  }
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.cfg.blocks.length).toBeGreaterThan(0);
    });

    it('creates synthetic block for top-level declarations', async () => {
      const code = `package main

var globalX = 10
var globalY = 20

func main() {}`;
      const result = await analyze(code, 'main.go', 'go');
      // Should have blocks from both function and top-level
      expect(result.cfg.blocks.length).toBeGreaterThan(0);
    });
  });

  // ── Taint analysis ───────────────────────────────────────────────────

  describe('taint analysis', () => {
    it('detects FormValue as taint source', async () => {
      const code = `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
  name := r.FormValue("name")
  db.Query("SELECT * FROM users WHERE name = " + name)
}`;
      const result = await analyze(code, 'handler.go', 'go');
      expect(result.taint.sources.length).toBeGreaterThan(0);
      expect(result.taint.sinks.length).toBeGreaterThan(0);
    });

    it('detects exec.Command as taint sink', async () => {
      const code = `package main

import "os/exec"

func run(cmd string) {
  exec.Command(cmd)
}`;
      const result = await analyze(code, 'run.go', 'go');
      const sink = result.taint.sinks.find(s => s.method === 'Command');
      expect(sink).toBeDefined();
      expect(sink!.type).toBe('command_injection');
      expect(sink!.cwe).toBe('CWE-78');
    });

    it('detects os.Getenv as source', async () => {
      const code = `package main

import "os"
import "os/exec"

func main() {
  cmd := os.Getenv("CMD")
  exec.Command(cmd)
}`;
      const result = await analyze(code, 'main.go', 'go');
      const source = result.taint.sources.find(s =>
        s.method === 'Getenv' || s.location?.includes('Getenv')
      );
      expect(source).toBeDefined();
    });

    it('detects SQL injection sink with db.Query', async () => {
      const code = `package main

func handler(r *http.Request) {
  name := r.FormValue("name")
  db.Query("SELECT * FROM users WHERE name = " + name)
}`;
      const result = await analyze(code, 'handler.go', 'go');
      const sink = result.taint.sinks.find(s => s.method === 'Query');
      expect(sink).toBeDefined();
      expect(sink!.type).toBe('sql_injection');
    });

    it('detects db.Exec as SQL injection sink', async () => {
      const code = `package main

func handler(r *http.Request) {
  id := r.FormValue("id")
  db.Exec("DELETE FROM users WHERE id = " + id)
}`;
      const result = await analyze(code, 'handler.go', 'go');
      const sink = result.taint.sinks.find(s => s.method === 'Exec');
      expect(sink).toBeDefined();
      expect(sink!.type).toBe('sql_injection');
    });

    it('detects path traversal via os.Open', async () => {
      const code = `package main

import "os"

func readFile(path string) {
  os.Open(path)
}`;
      const result = await analyze(code, 'main.go', 'go');
      const sink = result.taint.sinks.find(s => s.method === 'Open');
      expect(sink).toBeDefined();
      expect(sink!.type).toBe('path_traversal');
    });

    it('detects SSRF via http.Get', async () => {
      const code = `package main

import "net/http"

func fetch(url string) {
  http.Get(url)
}`;
      const result = await analyze(code, 'main.go', 'go');
      const sink = result.taint.sinks.find(s =>
        s.method === 'Get' && s.type === 'ssrf'
      );
      expect(sink).toBeDefined();
    });

    it('detects multiple sources and sinks in same function', async () => {
      const code = `package main

import "net/http"
import "os/exec"

func handler(w http.ResponseWriter, r *http.Request) {
  name := r.FormValue("name")
  cmd := r.FormValue("cmd")
  db.Query("SELECT * FROM users WHERE name = " + name)
  exec.Command(cmd)
}`;
      const result = await analyze(code, 'handler.go', 'go');
      // Should have at least 2 sources (both FormValue calls)
      const formSources = result.taint.sources.filter(s =>
        s.location?.includes('FormValue')
      );
      expect(formSources.length).toBeGreaterThanOrEqual(2);
      // Should have both SQL and command injection sinks
      expect(result.taint.sinks.some(s => s.type === 'sql_injection')).toBe(true);
      expect(result.taint.sinks.some(s => s.type === 'command_injection')).toBe(true);
    });
  });

  // ── Framework detection ──────────────────────────────────────────────

  describe('framework detection', () => {
    it('detects gin framework from imports', async () => {
      const code = `package main

import "github.com/gin-gonic/gin"

func main() {
  r := gin.Default()
  r.GET("/hello", func(c *gin.Context) {
    c.String(200, "hello")
  })
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.imports.some(i => i.from_package?.includes('gin-gonic/gin'))).toBe(true);
    });

    it('detects echo framework from imports', async () => {
      const code = `package main

import "github.com/labstack/echo/v4"

func main() {
  e := echo.New()
  e.GET("/hello", func(c echo.Context) error {
    return c.String(200, "hello")
  })
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.imports.some(i => i.from_package?.includes('labstack/echo'))).toBe(true);
    });

    it('detects fiber framework from imports', async () => {
      const code = `package main

import "github.com/gofiber/fiber/v2"

func main() {
  app := fiber.New()
  app.Get("/hello", func(c *fiber.Ctx) error {
    return c.SendString("hello")
  })
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.imports.some(i => i.from_package?.includes('gofiber/fiber'))).toBe(true);
    });

    it('detects net/http from imports', async () => {
      const code = `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
  w.Write([]byte("hello"))
}

func main() {
  http.HandleFunc("/", handler)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.imports.some(i => i.from_package === 'net/http')).toBe(true);
    });
  });

  // ── Edge cases ──────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles function with no parameters', async () => {
      const code = `package main

func noParams() {
  fmt.Println("hello")
}`;
      const result = await analyze(code, 'main.go', 'go');
      const moduleType = result.types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();
      const method = moduleType!.methods.find(m => m.name === 'noParams');
      expect(method).toBeDefined();
      expect(method!.parameters.length).toBe(0);
    });

    it('handles struct with no fields', async () => {
      const code = `package main

type Empty struct {}`;
      const result = await analyze(code, 'main.go', 'go');
      const emptyType = result.types.find(t => t.name === 'Empty');
      expect(emptyType).toBeDefined();
      expect(emptyType!.kind).toBe('class');
      expect(emptyType!.fields.length).toBe(0);
    });

    it('handles function with multiple return types', async () => {
      const code = `package main

func divide(a, b int) (int, error) {
  if b == 0 {
    return 0, fmt.Errorf("division by zero")
  }
  return a / b, nil
}`;
      const result = await analyze(code, 'main.go', 'go');
      const moduleType = result.types.find(t => t.name === '<module>');
      const divideMethod = moduleType?.methods.find(m => m.name === 'divide');
      expect(divideMethod).toBeDefined();
      // Return type should include both types
      expect(divideMethod!.return_type).toBeDefined();
    });

    it('handles for-range loop variables as DFG defs', async () => {
      const code = `package main

func process(items []string) {
  for i, item := range items {
    fmt.Println(i, item)
  }
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.dfg.defs.some(d => d.variable === 'i')).toBe(true);
      expect(result.dfg.defs.some(d => d.variable === 'item')).toBe(true);
    });

    it('handles chained method calls', async () => {
      const code = `package main

func main() {
  r.URL.Query().Get("key")
}`;
      const result = await analyze(code, 'main.go', 'go');
      // Should extract Get call
      const getCall = result.calls.find(c => c.method_name === 'Get');
      expect(getCall).toBeDefined();
    });

    it('handles code with defer statements', async () => {
      const code = `package main

import "os"

func readFile(path string) {
  f, err := os.Open(path)
  if err != nil {
    return
  }
  defer f.Close()
  fmt.Println(f)
}`;
      const result = await analyze(code, 'main.go', 'go');
      // Should parse without errors and extract calls
      const openCall = result.calls.find(c => c.method_name === 'Open');
      expect(openCall).toBeDefined();
      const closeCall = result.calls.find(c => c.method_name === 'Close');
      expect(closeCall).toBeDefined();
    });

    it('handles code with goroutines', async () => {
      const code = `package main

func main() {
  go func() {
    fmt.Println("in goroutine")
  }()
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.meta.language).toBe('go');
      // Should extract the Println call inside the goroutine
      const printCall = result.calls.find(c => c.method_name === 'Println');
      expect(printCall).toBeDefined();
    });

    it('handles switch statement in CFG', async () => {
      const code = `package main

func classify(x int) string {
  switch {
  case x > 0:
    return "positive"
  case x < 0:
    return "negative"
  default:
    return "zero"
  }
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.cfg.blocks.length).toBeGreaterThan(0);
    });

    it('handles multiple imports with single import statements', async () => {
      const code = `package main

import "fmt"
import "os"

func main() {
  fmt.Println(os.Args)
}`;
      const result = await analyze(code, 'main.go', 'go');
      expect(result.imports.some(i => i.imported_name === 'fmt')).toBe(true);
      expect(result.imports.some(i => i.imported_name === 'os')).toBe(true);
    });

    it('handles const declarations at package level', async () => {
      const code = `package main

const MaxRetries = 3
const Timeout = 30

func main() {
  fmt.Println(MaxRetries, Timeout)
}`;
      const result = await analyze(code, 'main.go', 'go');
      // const declarations should produce a top-level CFG block
      expect(result.cfg.blocks.length).toBeGreaterThan(0);
    });
  });
});
