/**
 * Tests for cognium-dev #148 — Go `json.Unmarshal(data, &dst)` and
 * `json.NewDecoder(r).Decode(&dst)` CWE-502 (deserialization) sink emission
 * must be gated by the *destination* shape.
 *
 * Go's `encoding/json` populates the declared fields of the destination type
 * via reflection; it cannot instantiate attacker-chosen gadgets the way
 * Python pickle or Java native deserialization can. When the destination is
 * a concrete typed value (typed struct, typed slice, typed map, pointer to
 * named type) the call is *not* a CWE-502 sink. The dangerous shape is an
 * untyped destination (`interface{}`, `any`, `map[string]interface{}`).
 *
 * The fix is in `taint-matcher.ts`: `isSafeGoJsonUnmarshalCall()` +
 * `findGoLocalDeclaredType()` + `classifyGoDestinationType()` helpers and a
 * guard at the `findSinks()` emission point. This suite locks both
 * directions:
 *
 *  - FP-suppression: typed destinations (`var d dto`, `var d *dto`,
 *    `var d []User`, `var d map[string]string`, `d := dto{}`, Decoder shape)
 *    must NOT emit a `deserialization` sink.
 *  - Recall: untyped destinations (`interface{}`, `any`,
 *    `map[string]interface{}`, `make(map[string]interface{})`) and
 *    declarations the heuristic cannot find within its backward window
 *    must continue to emit a `deserialization` sink (conservative bias).
 *  - Downstream effect: the existing `sql_injection` gate behaviour is
 *    unchanged for safe parameterised queries that follow a now-suppressed
 *    Unmarshal — i.e. no spurious SQLi finding is introduced and the
 *    previously-masked SQLi sink is no longer obscured (FN-IL-19 side
 *    benefit noted in the issue body).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countDeserialization = (
  sinks: Array<{ type?: string; method?: string }> | undefined,
  method?: string,
) =>
  (sinks ?? []).filter(
    (s) => s.type === 'deserialization' && (method === undefined || s.method === method),
  ).length;

const countByType = (
  sinks: Array<{ type?: string }> | undefined,
  type: string,
) => (sinks ?? []).filter((s) => s.type === type).length;

describe('cognium-dev #148 — Go json.Unmarshal typed-struct FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP-suppression: typed destinations must NOT emit deserialization sink
  // -------------------------------------------------------------------------

  it('json.Unmarshal with `var d dto` typed struct destination: no sink', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
type dto struct { Name string }
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  var d dto
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'typed-struct.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBe(0);
  });

  it('json.Unmarshal with `var d *dto` pointer-to-typed destination: no sink', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
type dto struct { Name string }
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  var d *dto = &dto{}
  json.Unmarshal(body, d)
}
`;
    const r = await analyze(code, 'pointer-typed.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBe(0);
  });

  it('json.Unmarshal with `var d []User` typed slice destination: no sink', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
type User struct { ID int }
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  var d []User
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'typed-slice.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBe(0);
  });

  it('json.Unmarshal with `var d map[string]string` typed map destination: no sink', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  var d map[string]string
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'typed-map.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBe(0);
  });

  it('json.Unmarshal with `d := dto{}` composite-literal inferred type: no sink', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
type dto struct { Name string }
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  d := dto{}
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'composite-init.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBe(0);
  });

  it('json.NewDecoder(r).Decode(&d) with typed struct destination: no sink', async () => {
    const code = `package main
import (
  "encoding/json"
  "net/http"
)
type dto struct { Name string }
func h(w http.ResponseWriter, r *http.Request) {
  dec := json.NewDecoder(r.Body)
  var d dto
  dec.Decode(&d)
}
`;
    const r = await analyze(code, 'decoder-typed.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Decode')).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall: untyped / unresolvable destinations MUST still emit a sink
  // -------------------------------------------------------------------------

  it('json.Unmarshal with `var d interface{}` untyped destination: sink kept', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  var d interface{}
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'untyped-interface.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBeGreaterThanOrEqual(1);
  });

  it('json.Unmarshal with `var d any` (Go 1.18 any alias): sink kept', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  var d any
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'untyped-any.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBeGreaterThanOrEqual(1);
  });

  it('json.Unmarshal with `var d map[string]interface{}` untyped map: sink kept', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  var d map[string]interface{}
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'untyped-map.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBeGreaterThanOrEqual(1);
  });

  it('json.Unmarshal with `d := make(map[string]interface{})` untyped via make: sink kept', async () => {
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  d := make(map[string]interface{})
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'untyped-make.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBeGreaterThanOrEqual(1);
  });

  it('json.Unmarshal with no visible declaration in window: sink kept (conservative)', async () => {
    // `d` is a method-level field referenced via no nearby `var`/`:=`
    // declaration — the backward scan returns null, classifier returns
    // 'unknown', gate keeps the sink.
    const code = `package main
import (
  "encoding/json"
  "io"
  "net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
  body, _ := io.ReadAll(r.Body)
  json.Unmarshal(body, &d)
}
`;
    const r = await analyze(code, 'no-decl.go', 'go');
    expect(countDeserialization(r.taint.sinks, 'Unmarshal')).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Issue body repro + downstream FN-IL-19 lock
  // -------------------------------------------------------------------------

  it('issue #148 repro — safe_interop_json_deserialize_sink shape: no deserialization sink, parameterised SQL stays safe', async () => {
    // The exact shape from `safe_interop_json_deserialize_sink.go` in the
    // issue body: typed-struct Unmarshal followed by a parameterised
    // `db.Query("... = $1", d.Name)` SQL call. The deserialization sink
    // must drop (gate fires) AND the parameterised query must not be
    // emitted as a sql_injection sink (the existing $N placeholder gate
    // continues to recognise it as safe).
    const code = `package main
import (
  "database/sql"
  "encoding/json"
  "io"
  "net/http"
)
type dto struct { Name string }
func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  body, _ := io.ReadAll(r.Body)
  var d dto
  json.Unmarshal(body, &d)
  db.Query("SELECT * FROM users WHERE name = $1", d.Name)
}
`;
    const r = await analyze(code, 'safe_interop_json_deserialize_sink.go', 'go');
    expect(countByType(r.taint.sinks, 'deserialization')).toBe(0);
    // The parameterised query is safe — no sql_injection sink should fire.
    expect(countByType(r.taint.sinks, 'sql_injection')).toBe(0);
  });
});
