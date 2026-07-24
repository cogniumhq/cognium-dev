/**
 * Tests for cognium-dev #243 — Go taint-propagation shapes.
 *
 * The issue tracks four Go-specific propagation shapes surfaced by benchmark
 * regressions. This suite locks the shapes that are supported so future
 * refactors do not silently regress them, and documents the shapes still
 * awaiting engine work.
 *
 * Supported (locked here):
 *   - Shape 1: closure capture — a `func literal` that references an outer
 *     tainted variable propagates taint into the closure body.
 *   - Shape 2: range-clause loop-carried taint — `for _, v := range tainted`
 *     treats `v` as tainted for the loop body.
 *   - Shape 3: JSON marshal/unmarshal roundtrip — `json.Unmarshal(bytes, &d)`
 *     propagates taint from `bytes` into `d`; `json.Marshal(x)` propagates
 *     from `x` into its return value.
 *
 *   - Shape 4: package-global store/read across functions. A text-scan
 *     supplement detects `X = taintedRhs` on a package-level var and
 *     matches any sink whose arg text references `X`. Short-var-decl
 *     (`X := ...`) is preserved as local and does not fire this path.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const flowCount = (result: Awaited<ReturnType<typeof analyze>>): number =>
  result.taint.flows?.length ?? 0;

describe('cognium-dev #243 — Go taint-propagation shapes', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('Shape 2: range-clause loop-carried taint', () => {
    it('propagates taint from range source into loop variable', async () => {
      const code = `package main
import (
  "database/sql"
  "net/http"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  ids := r.URL.Query()["ids"]
  for _, v := range ids {
    db.Query("SELECT * FROM users WHERE id = " + v)
  }
}
`;
      const result = await analyze(code, 'range.go', 'go');
      expect(result.taint.sources.length).toBeGreaterThan(0);
      expect(result.taint.sinks.length).toBeGreaterThan(0);
      expect(flowCount(result)).toBeGreaterThan(0);
    });

    it('propagates taint through indexed range variable', async () => {
      const code = `package main
import (
  "database/sql"
  "net/http"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  vals := r.URL.Query()["k"]
  for i, v := range vals {
    _ = i
    db.Query("SELECT * FROM t WHERE x = " + v)
  }
}
`;
      const result = await analyze(code, 'range-i.go', 'go');
      expect(flowCount(result)).toBeGreaterThan(0);
    });
  });

  describe('Shape 3: opaque-codec roundtrip', () => {
    it('propagates taint through json.Unmarshal(body, &dest)', async () => {
      const code = `package main
import (
  "database/sql"
  "encoding/json"
  "net/http"
  "io"
)

type Query struct {
  Sql string
}

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  body, _ := io.ReadAll(r.Body)
  var q Query
  json.Unmarshal(body, &q)
  db.Query(q.Sql)
}
`;
      const result = await analyze(code, 'json.go', 'go');
      expect(flowCount(result)).toBeGreaterThan(0);
    });

    it('propagates taint through xml.Unmarshal(body, &dest)', async () => {
      const code = `package main
import (
  "database/sql"
  "encoding/xml"
  "net/http"
  "io"
)

type Query struct {
  Sql string
}

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  body, _ := io.ReadAll(r.Body)
  var q Query
  xml.Unmarshal(body, &q)
  db.Query(q.Sql)
}
`;
      const result = await analyze(code, 'xml.go', 'go');
      expect(flowCount(result)).toBeGreaterThan(0);
    });
  });

  describe('Shape 4: package-global store/read', () => {
    it('propagates taint from a store-func write to a read-func sink', async () => {
      const code = `package main
import (
  "database/sql"
  "net/http"
)

var lastQuery string

func store(r *http.Request) {
  lastQuery = r.URL.Query().Get("q")
}

func execute(db *sql.DB) {
  db.Query(lastQuery)
}

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  store(r)
  execute(db)
}
`;
      const result = await analyze(code, 'pkgvar.go', 'go');
      expect(flowCount(result)).toBeGreaterThan(0);
    });

    it('does not fire when the write shadows the package var with :=', async () => {
      const code = `package main
import (
  "database/sql"
  "net/http"
)

var lastQuery string

func store(r *http.Request) {
  lastQuery := r.URL.Query().Get("q")
  _ = lastQuery
}

func execute(db *sql.DB) {
  db.Query(lastQuery)
}
`;
      const result = await analyze(code, 'pkgvar-shadow.go', 'go');
      // sink db.Query(lastQuery) still exists but no write to the package var
      // → no flow from this shape.
      expect(flowCount(result)).toBe(0);
    });
  });

  describe('Shape 1: closure capture', () => {
    it('propagates tainted outer variable into a func literal body', async () => {
      const code = `package main
import (
  "database/sql"
  "net/http"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  userId := r.URL.Query().Get("id")
  fn := func() {
    db.Query("SELECT * FROM users WHERE id = " + userId)
  }
  fn()
}
`;
      const result = await analyze(code, 'closure.go', 'go');
      expect(result.taint.sources.length).toBeGreaterThan(0);
      expect(result.taint.sinks.length).toBeGreaterThan(0);
      expect(flowCount(result)).toBeGreaterThan(0);
    });

    it('propagates tainted outer variable into a goroutine func literal', async () => {
      const code = `package main
import (
  "database/sql"
  "net/http"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  userId := r.URL.Query().Get("id")
  go func() {
    db.Query("SELECT * FROM users WHERE id = " + userId)
  }()
}
`;
      const result = await analyze(code, 'goroutine.go', 'go');
      expect(result.taint.sources.length).toBeGreaterThan(0);
      expect(result.taint.sinks.length).toBeGreaterThan(0);
      expect(flowCount(result)).toBeGreaterThan(0);
    });
  });
});
