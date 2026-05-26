# Circle-IR 3.0 Specification

**Status**: Living Document
**Last Updated**: 2026-03-28
**Implementation**: Python (reference) → TypeScript (target)

---

## Implementation Status

| Section | Python | TypeScript | Status |
|---------|--------|------------|--------|
| Meta | ✅ | ✅ | Done |
| Types | ✅ | ✅ | Done |
| Methods | ✅ | ✅ | Done |
| CFG | ✅ | ✅ | Done |
| DFG | ✅ | ✅ | Done |
| Calls | ✅ | ✅ | Done |
| Taint Sources | ✅ | ✅ | Done |
| Taint Sinks | ✅ | ✅ | Done |
| Imports | ✅ | ✅ | Done |
| Exports | ⬜ | ✅ | Done |
| Sanitizers | ✅ (separate) | ✅ | Done |
| Constant Propagation | ✅ | ✅ | Done |
| Call Resolution | ⬜ | ✅ | Done |
| Unresolved | ⬜ | ⬜ | Pending |
| Enriched | ⬜ | ⬜ | Pending |
| DFG Chains | ⬜ | ⬜ | Pending |
| Project-Level (`analyzeProject`) | ⬜ | ✅ | Done |
| SAST Findings (`SastFinding[]`) | ⬜ | ✅ | Done (v3.9.1) |
| Software Metrics (`FileMetrics`, 24 metrics) | ⬜ | ✅ | Done (v3.9.5) |
| Reliability passes (null-deref, resource-leak, unchecked-return, dead-code, variable-shadowing, leaked-global, unused-variable, missing-await, sync-io-async, string-concat-loop, infinite-loop, double-close, use-after-close, unhandled-exception, broad-catch, swallowed-exception) | ⬜ | ✅ | Done (v3.9.0–3.9.9) |
| Performance passes (n-plus-one, redundant-loop-computation, unbounded-collection, serial-await, react-inline-jsx) | ⬜ | ✅ | Done (v3.9.0–3.9.8) |
| Maintainability passes (missing-public-doc, todo-in-prod, stale-doc-ref) | ⬜ | ✅ | Done (v3.9.0–3.9.8) |
| Architecture passes (circular-dependency, orphan-module, dependency-fan-out, deep-inheritance, missing-override, unused-interface-method) | ⬜ | ✅ | Done (v3.9.0–3.11.0) |
| TypeHierarchy resolver (polymorphic sink matching) | ⬜ | ✅ | Done (v3.11.0) |
| Dominator-tree passes (missing-guard-dom, cleanup-verify) | ⬜ | ✅ | Done (v3.11.0) |

---

## Output Format

Circle-IR produces JSON with this top-level structure:

```json
{
  "meta": { },
  "types": [ ],
  "calls": [ ],
  "cfg": { },
  "dfg": { },
  "taint": { },
  "imports": [ ],
  "exports": [ ],
  "findings": [ ],
  "metrics": { },
  "unresolved": [ ],
  "enriched": { }
}
```

`findings` is a `SastFinding[]` populated by the 36-pass `AnalysisPipeline` (19 security taint passes + 17 quality passes). Each finding is SARIF 2.1.0-aligned with `rule_id`, `category` (`PassCategory`), `severity`, `level` (`SarifLevel`), `file`, `line`, `cwe?`, `fix?`, and `evidence?`. See [docs/PASSES.md](PASSES.md) for the full pass registry.

`metrics` is a `FileMetrics` object always populated with 24 software quality metrics (cyclomatic complexity, Halstead suite, CK metrics, composite scores). See the Metrics section below.

---

## 1. Meta

File metadata and version information.

```typescript
interface Meta {
  circle_ir: "3.0";
  file: string;
  language: "java" | "javascript" | "typescript" | "python" | "go" | "rust" | "bash" | "html";
  loc: number;
  hash: string;           // SHA256 prefix (16 chars)
  package?: string;       // PENDING: Add to implementation
}
```

**Example:**
```json
{
  "meta": {
    "circle_ir": "3.0",
    "file": "/path/to/UserController.java",
    "language": "java",
    "loc": 150,
    "hash": "a1b2c3d4e5f67890"
  }
}
```

**Implementation**: `cpg_extractor.py:160-167`

---

## 2. Types

Class, interface, and enum definitions with nested methods.

```typescript
interface TypeInfo {
  name: string;
  kind: "class" | "interface" | "enum";
  package: string | null;
  extends: string | null;
  implements: string[];
  annotations: string[];
  methods: MethodInfo[];
  fields: FieldInfo[];
  start_line: number;
  end_line: number;
}

interface MethodInfo {
  name: string;
  return_type: string | null;
  parameters: ParameterInfo[];
  annotations: string[];
  modifiers: string[];       // ["public", "static", etc.]
  start_line: number;
  end_line: number;
}

interface ParameterInfo {
  name: string;
  type: string | null;
  annotations: string[];     // ["RequestParam", "PathVariable", etc.]
}

interface FieldInfo {
  name: string;
  type: string | null;
  modifiers: string[];
  annotations: string[];
}
```

**Example:**
```json
{
  "types": [
    {
      "name": "UserController",
      "kind": "class",
      "package": "com.example.controllers",
      "extends": "BaseController",
      "implements": ["Auditable"],
      "annotations": ["RestController", "RequestMapping(\"/api/users\")"],
      "methods": [
        {
          "name": "getUser",
          "return_type": "User",
          "parameters": [
            {
              "name": "id",
              "type": "Long",
              "annotations": ["PathVariable"]
            }
          ],
          "annotations": ["GetMapping(\"/{id}\")"],
          "modifiers": ["public"],
          "start_line": 15,
          "end_line": 20
        }
      ],
      "fields": [
        {
          "name": "userService",
          "type": "UserService",
          "modifiers": ["private"],
          "annotations": ["Autowired"]
        }
      ],
      "start_line": 10,
      "end_line": 50
    }
  ]
}
```

**Implementation**: `type_extractor.py`

---

## 3. Calls

Method invocations with arguments and context.

```typescript
interface CallInfo {
  method_name: string;
  receiver: string | null;
  arguments: ArgumentInfo[];
  location: {
    line: number;
    column: number;
  };
  in_method: string | null;
}

interface ArgumentInfo {
  position: number;          // 0-indexed
  expression: string;        // Full expression text
  variable: string | null;   // Variable name if simple reference
  literal: string | null;    // Literal value if constant
}
```

**Example:**
```json
{
  "calls": [
    {
      "method_name": "getParameter",
      "receiver": "request",
      "arguments": [
        {
          "position": 0,
          "expression": "\"id\"",
          "variable": null,
          "literal": "id"
        }
      ],
      "location": {"line": 25, "column": 20},
      "in_method": "handleRequest"
    },
    {
      "method_name": "executeQuery",
      "receiver": "stmt",
      "arguments": [
        {
          "position": 0,
          "expression": "\"SELECT * FROM users WHERE id = \" + id",
          "variable": null,
          "literal": null
        }
      ],
      "location": {"line": 30, "column": 8},
      "in_method": "handleRequest"
    }
  ]
}
```

**Implementation**: `call_extractor.py`

### PENDING: Call Resolution

```typescript
// PENDING: Add to CallInfo
interface CallInfo {
  // ... existing fields ...

  resolved?: boolean;
  resolution?: {
    status: "resolved" | "external_method" | "interface_method" | "reflection";
    target?: string;           // Fully qualified method name
    candidates?: string[];     // For interface/virtual dispatch
  };
}
```

**Example (PENDING):**
```json
{
  "method_name": "matches",
  "receiver": "encoder",
  "resolved": false,
  "resolution": {
    "status": "interface_method",
    "candidates": ["BCryptPasswordEncoder.matches", "Argon2PasswordEncoder.matches"]
  }
}
```

---

## 4. CFG (Control Flow Graph)

Basic blocks and control flow edges.

```typescript
interface CFG {
  blocks: CFGBlock[];
  edges: CFGEdge[];
}

interface CFGBlock {
  id: number;
  type: "entry" | "exit" | "normal" | "conditional" | "loop";
  start_line: number;
  end_line: number;
}

interface CFGEdge {
  from: number;
  to: number;
  type: "sequential" | "true" | "false" | "exception" | "back" | "break" | "continue";
}
```

**Example:**
```json
{
  "cfg": {
    "blocks": [
      {"id": 1, "type": "entry", "start_line": 15, "end_line": 15},
      {"id": 2, "type": "conditional", "start_line": 16, "end_line": 16},
      {"id": 3, "type": "normal", "start_line": 17, "end_line": 18},
      {"id": 4, "type": "normal", "start_line": 20, "end_line": 21},
      {"id": 5, "type": "exit", "start_line": 23, "end_line": 23}
    ],
    "edges": [
      {"from": 1, "to": 2, "type": "sequential"},
      {"from": 2, "to": 3, "type": "true"},
      {"from": 2, "to": 4, "type": "false"},
      {"from": 3, "to": 5, "type": "sequential"},
      {"from": 4, "to": 5, "type": "sequential"}
    ]
  }
}
```

**Implementation**: `cpg_extractor.py:181-395`

---

## 5. DFG (Data Flow Graph)

Variable definitions and uses.

```typescript
interface DFG {
  defs: DFGDef[];
  uses: DFGUse[];
  chains?: DFGChain[];       // PENDING
}

interface DFGDef {
  id: number;
  variable: string;
  line: number;
  kind: "param" | "local" | "field" | "return";
}

interface DFGUse {
  id: number;
  variable: string;
  line: number;
  def_id: number | null;     // Reaching definition
}
```

**Example:**
```json
{
  "dfg": {
    "defs": [
      {"id": 1, "variable": "id", "line": 15, "kind": "param"},
      {"id": 2, "variable": "name", "line": 16, "kind": "local"},
      {"id": 3, "variable": "sql", "line": 17, "kind": "local"}
    ],
    "uses": [
      {"id": 1, "variable": "request", "line": 16, "def_id": null},
      {"id": 2, "variable": "name", "line": 17, "def_id": 2},
      {"id": 3, "variable": "sql", "line": 18, "def_id": 3}
    ]
  }
}
```

**Implementation**: `cpg_extractor.py:398-463`

### PENDING: DFG Chains

```typescript
// PENDING: Add explicit def-use chains
interface DFGChain {
  from_def: number;          // Definition ID
  to_def: number;            // Downstream definition ID
  via: string;               // Variable name
}
```

**Example (PENDING):**
```json
{
  "dfg": {
    "chains": [
      {"from_def": 1, "to_def": 3, "via": "username"},
      {"from_def": 2, "to_def": 4, "via": "password"}
    ]
  }
}
```

---

## 6. Taint

Identified taint sources and sinks.

```typescript
interface Taint {
  sources: TaintSource[];
  sinks: TaintSink[];
  sanitizers?: TaintSanitizer[];  // PENDING: move to this section
}

interface TaintSource {
  type: string;              // See source types below
  location: string;          // Human-readable description
  severity: "high" | "medium" | "low";
  line: number;
  confidence: number;        // 0.0 - 1.0
}

interface TaintSink {
  type: string;              // See sink types below
  cwe: string;               // "CWE-89", etc.
  location: string;
  line: number;
  confidence: number;
}
```

### Source Types

| Type | Description | Example |
|------|-------------|---------|
| `http_param` | HTTP request parameter | `request.getParameter()` |
| `http_body` | HTTP request body | `@RequestBody` |
| `http_header` | HTTP header value | `request.getHeader()` |
| `http_cookie` | HTTP cookie | `request.getCookies()` |
| `http_path` | URL path variable | `@PathVariable` |
| `io_input` | File/console input | `BufferedReader.readLine()` |
| `env_input` | Environment variable | `System.getenv()` |
| `db_input` | Database result | `ResultSet.getString()` |

### Sink Types

| Type | CWE | Description |
|------|-----|-------------|
| `sql_injection` | CWE-89 | SQL query execution |
| `command_injection` | CWE-78 | OS command execution |
| `path_traversal` | CWE-22 | File path manipulation |
| `xss` | CWE-79 | Cross-site scripting |
| `xxe` | CWE-611 | XML external entity |
| `deserialization` | CWE-502 | Unsafe deserialization |
| `ldap_injection` | CWE-90 | LDAP injection |
| `xpath_injection` | CWE-643 | XPath injection |
| `ssrf` | CWE-918 | Server-side request forgery |

**Example:**
```json
{
  "taint": {
    "sources": [
      {
        "type": "http_param",
        "location": "@RequestParam id in getUser",
        "severity": "high",
        "line": 13,
        "confidence": 1.0
      }
    ],
    "sinks": [
      {
        "type": "sql_injection",
        "cwe": "CWE-89",
        "location": "executeQuery(sql) in getUser",
        "line": 17,
        "confidence": 1.0
      }
    ]
  }
}
```

**Implementation**: `taint_patterns.py`

### PENDING: Sanitizers in Taint Section

```typescript
// PENDING: Add to taint section
interface TaintSanitizer {
  type: string;
  method: string;
  line: number;
  sanitizes: string[];       // Which sink types it sanitizes
}
```

**Note**: Sanitizers currently implemented in separate module `taint/sanitizers.py`

---

## 6.1. Constant Propagation

Static analysis engine that tracks constant values, detects dead code, and refines taint analysis by eliminating false positives when variables hold known constant values.

```typescript
interface ConstantValue {
  value: string | number | boolean | null;
  type: 'string' | 'int' | 'float' | 'char' | 'bool' | 'null' | 'unknown';
  sourceLine: number;
}

interface ConstantPropagationResult {
  symbols: Map<string, ConstantValue>;       // Variable → constant value
  tainted: Set<string>;                       // Tainted variable names
  unreachableLines: Set<number>;              // Dead code lines
  taintedCollections: Map<string, Set<string>>; // Collection → tainted keys
}
```

### Features

| Feature | Description |
|---------|-------------|
| **Variable Tracking** | Tracks assignments: `bar = "constant"` vs `bar = taintedParam` |
| **Expression Evaluation** | Evaluates arithmetic, comparisons, and string methods |
| **Dead Code Detection** | Evaluates if/switch/ternary conditions, marks unreachable branches |
| **Collection Taint Tracking** | Per-key tracking for map.put/map.get operations |
| **Iterative Refinement** | Second pass with fixpoint to re-evaluate taint with updated symbols |
| **Conditional Branch Handling** | Conservative taint preservation in unknown-condition branches |

### Taint Source Detection

Recognizes HTTP input methods as taint sources:
- `request.getParameter()`, `request.getHeader()`, `request.getCookies()`
- `request.getParameterMap()`, `request.getPathInfo()`, `request.getRequestURI()`
- Scanner/BufferedReader input methods

### Dead Code Detection

Evaluates conditions to determine unreachable code:

```java
if (false) {
    // Marked as unreachable - sinks here are false positives
}

int x = 10;
if (x > 5) {
    // Always executed
} else {
    // Marked as unreachable
}
```

### False Positive Elimination

The `isFalsePositive()` helper identifies:
- `sink_in_dead_code` - Sink is in unreachable code block
- `variable_is_constant` - Variable has known constant value

**Implementation**: `src/analysis/constant-propagation.ts`

---

## 7. Imports

Import declarations for cross-file resolution.

```typescript
interface ImportInfo {
  imported_name: string;
  from_package: string | null;
  alias: string | null;
  is_wildcard: boolean;
  line_number: number | null;
}
```

**Example:**
```json
{
  "imports": [
    {
      "imported_name": "ArrayList",
      "from_package": "java.util",
      "alias": null,
      "is_wildcard": false,
      "line_number": 3
    },
    {
      "imported_name": "*",
      "from_package": "javax.servlet.http",
      "alias": null,
      "is_wildcard": true,
      "line_number": 4
    }
  ]
}
```

**Implementation**: `cpg_extractor.py:465-517`

---

## 8. Exports (PENDING)

Symbols exported by this file.

```typescript
// PENDING: Not implemented
interface ExportInfo {
  symbol: string;
  kind: "class" | "interface" | "method" | "field";
  visibility: "public" | "protected" | "package";
}
```

**Example (PENDING):**
```json
{
  "exports": [
    {"symbol": "UserController", "kind": "class", "visibility": "public"},
    {"symbol": "getUser", "kind": "method", "visibility": "public"}
  ]
}
```

---

## 9. Unresolved (PENDING)

Items that require LLM resolution.

```typescript
// PENDING: Not implemented
interface UnresolvedItem {
  type: "virtual_dispatch" | "taint_propagation" | "reflection" | "dynamic_call";
  call_id?: number;
  reason: string;
  context: {
    code: string;
    line: number;
    candidates?: string[];
  };
  llm_question: string;
}
```

**Example (PENDING):**
```json
{
  "unresolved": [
    {
      "type": "virtual_dispatch",
      "call_id": 5,
      "reason": "interface_multiple_impls",
      "context": {
        "code": "encoder.matches(password, hash)",
        "line": 25,
        "candidates": ["BCryptPasswordEncoder.matches", "Argon2PasswordEncoder.matches"]
      },
      "llm_question": "Which PasswordEncoder implementation is used?"
    },
    {
      "type": "taint_propagation",
      "reason": "collection_uncertainty",
      "context": {
        "code": "users.add(user); ... users.get(0)",
        "line": 30
      },
      "llm_question": "Does taint propagate through this collection?"
    }
  ]
}
```

---

## 10. Enriched (PENDING)

LLM-enhanced metadata after enrichment pass.

```typescript
// PENDING: Not implemented
interface Enriched {
  functions?: EnrichedFunction[];
  additional_sources?: TaintSource[];
  additional_sinks?: TaintSink[];
  resolved_calls?: ResolvedCall[];
}

interface EnrichedFunction {
  method_name: string;
  role: "controller" | "service" | "repository" | "utility";
  risk: "high" | "medium" | "low";
  trust_boundary: "entry_point" | "internal" | "external";
  summary: string;
}

interface ResolvedCall {
  call_id: number;
  resolved_to: string;
  confidence: number;
  reason: string;
}
```

**Example (PENDING):**
```json
{
  "enriched": {
    "functions": [
      {
        "method_name": "authenticate",
        "role": "service",
        "risk": "high",
        "trust_boundary": "entry_point",
        "summary": "Validates user credentials against database"
      }
    ],
    "additional_sources": [
      {
        "type": "deserialization",
        "location": "ObjectInputStream.readObject at line 88",
        "severity": "high",
        "line": 88,
        "confidence": 0.85
      }
    ],
    "resolved_calls": [
      {
        "call_id": 5,
        "resolved_to": "BCryptPasswordEncoder.matches",
        "confidence": 0.85,
        "reason": "BCrypt is Spring Security default"
      }
    ]
  }
}
```

---

## 11. Project-Level Schema (PENDING)

For multi-file analysis.

### Project Metadata (PENDING)

```typescript
interface ProjectMeta {
  name: string;
  root: string;
  language: string;
  framework: string;
  framework_version: string;
  build_tool: "maven" | "gradle" | "ant";
  total_files: number;
  total_loc: number;
}
```

### Cross-File Calls (PENDING)

```typescript
interface CrossFileCall {
  id: string;
  from: {
    file: string;
    method: string;
    line: number;
  };
  to: {
    file: string;
    method: string;
    line: number;
  };
  args_mapping: ArgMapping[];
}

interface ArgMapping {
  caller_arg: number;
  callee_param: number;
  taint_propagates: boolean;
}
```

### Type Hierarchy (PENDING)

```typescript
interface TypeHierarchy {
  classes: Record<string, {
    extends: string | null;
    implements: string[];
  }>;
  interfaces: Record<string, {
    implementations: string[];
  }>;
}
```

### Taint Paths (PENDING)

```typescript
interface TaintPath {
  id: string;
  source: {
    file: string;
    line: number;
    type: string;
  };
  sink: {
    file: string;
    line: number;
    type: string;
    cwe: string;
  };
  hops: TaintHop[];
  sanitizers_in_path: string[];
  path_exists: boolean;
  confidence: number;
}

interface TaintHop {
  file: string;
  method: string;
  line: number;
  code: string;
  variable: string;
}
```

---

## 12. Findings (PENDING)

Final vulnerability reports.

```typescript
// PENDING: Not implemented
interface Finding {
  id: string;
  type: string;              // sql_injection, xss, etc.
  cwe: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  source: {
    file: string;
    line: number;
    code: string;
  };
  sink: {
    file: string;
    line: number;
    code: string;
  };
  path?: TaintHop[];
  exploitable: boolean;
  explanation: string;
  remediation: string;
  verification: {
    graph_path_exists: boolean;
    llm_verified: boolean;
    llm_confidence: number;
  };
}
```

**Example (PENDING):**
```json
{
  "findings": [
    {
      "id": "vuln1",
      "type": "sql_injection",
      "cwe": "CWE-89",
      "severity": "critical",
      "confidence": 0.95,
      "source": {
        "file": "UserController.java",
        "line": 35,
        "code": "request.getParameter(\"id\")"
      },
      "sink": {
        "file": "UserRepository.java",
        "line": 45,
        "code": "em.createNativeQuery(sql)"
      },
      "exploitable": true,
      "explanation": "User input flows directly to SQL without sanitization",
      "remediation": "Use parameterized query with setParameter()",
      "verification": {
        "graph_path_exists": true,
        "llm_verified": true,
        "llm_confidence": 0.95
      }
    }
  ]
}
```

---

## API Response Format

For CF Workers deployment.

```typescript
interface AnalysisResponse {
  success: boolean;
  analysis: {
    sources: TaintSource[];
    sinks: TaintSink[];
    vulnerabilities: Vulnerability[];
  };
  meta: {
    parseTimeMs: number;
    analysisTimeMs: number;
    totalTimeMs: number;
  };
}

interface Vulnerability {
  type: string;
  cwe: string;
  severity: "critical" | "high" | "medium" | "low";
  source: { line: number; type: string };
  sink: { line: number; type: string };
  confidence: number;
  path?: string[];
}
```

**Example:**
```json
{
  "success": true,
  "analysis": {
    "sources": [
      {"line": 13, "type": "http_param", "location": "@RequestParam id"}
    ],
    "sinks": [
      {"line": 17, "type": "sql_injection", "cwe": "CWE-89"}
    ],
    "vulnerabilities": [
      {
        "type": "sql_injection",
        "cwe": "CWE-89",
        "severity": "critical",
        "source": {"line": 13, "type": "http_param"},
        "sink": {"line": 17, "type": "sql_injection"},
        "confidence": 0.95,
        "path": ["id", "sql"]
      }
    ]
  },
  "meta": {
    "parseTimeMs": 12,
    "analysisTimeMs": 45,
    "totalTimeMs": 57
  }
}
```

---

## Implementation Status

### Phase 1: Core
- [x] Meta extraction
- [x] Type extraction (classes, interfaces, methods, fields)
- [x] Call extraction (method invocations, arguments)
- [x] CFG construction (blocks, edges)
- [x] DFG construction (defs, uses)
- [x] Taint source matching
- [x] Taint sink matching
- [x] Import extraction
- [x] JSON serialization matching spec

### Phase 2: Enhanced
- [x] Export extraction
- [x] Call resolution tracking
- [x] Sanitizer detection
- [x] DFG chains computation

### Phase 3: Extension Points
- [x] Unresolved section population (static analysis identifies unresolvable patterns)
- [x] Enriched section schema (optional, populated by analysis consumers)
- [x] Finding generation

### Phase 4: Project-Level
- [x] Cross-file call graph
- [x] Type hierarchy
- [x] Taint path enumeration
- [x] Multi-file analysis

---

## File Locations

### Python Reference
| Component | File |
|-----------|------|
| CPG Extractor | `src/circle_ir/core/cpg_extractor.py` |
| Type Extractor | `src/circle_ir/core/type_extractor.py` |
| Call Extractor | `src/circle_ir/core/call_extractor.py` |
| Taint Patterns | `src/circle_ir/core/taint_patterns.py` |
| Constant Propagation | `src/circle_ir/core/constant_propagation.py` |
| Source Extractor | `src/circle_ir/core/source_extractor.py` |
| Sanitizers | `src/circle_ir/taint/sanitizers.py` |
| Path Finder | `src/circle_ir/taint/path_finder.py` |
| DFG Verifier | `src/circle_ir/taint/dfg_verifier.py` |

### TypeScript Implementation
| Component | File |
|-----------|------|
| Parser | `src/core/parser.ts` |
| Analyzer | `src/analyzer.ts` |
| Constant Propagation | `src/analysis/constant-propagation.ts` |
| Taint Propagation | `src/analysis/taint-propagation.ts` |
| Taint Matcher | `src/analysis/taint-matcher.ts` |
| Config Loader | `src/analysis/config-loader.ts` |
| Benchmark Runner | `src/benchmark/runner.ts` |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.0.2 | 2025-01-25 | Added Constant Propagation engine documentation |
| 3.0.1 | 2025-01-25 | Consolidated spec with implementation status |
| 3.0.0 | 2025-01 | Initial spec, JSON format, three-step pipeline |
