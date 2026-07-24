/**
 * Tests for cognium-dev #213 — ninth slice: Go web framework sources.
 *
 * Prior coverage was net/http standard library (`r.URL.Query()`) and
 * gRPC metadata. This slice adds the four major Go web frameworks:
 *
 *   - Gin       — `c.Query` / `Param` / `PostForm` / `GetHeader` /
 *                 `Cookie` / `FormFile` / `BindJSON` / `ShouldBindJSON`
 *                 / `Bind*` / `MultipartForm`
 *   - Echo      — `c.QueryParam` / `QueryParams` / `Param` /
 *                 `FormValue` / `FormParams` / `FormFile`
 *   - Fiber     — `c.Query` / `Params` / `FormValue` / `FormFile` /
 *                 `Cookies` / `Get` / `Body` / `BodyParser` /
 *                 `QueryParser` / `ParamsParser`
 *   - Chi       — `chi.URLParam(r, "id")` / `chi.URLParamFromCtx`
 *   - Beego     — `ctx.Input.Query / Param / Header / Cookie`
 *   - Gorilla   — `mux.Vars(r)`
 *
 * Class-scoping relies on the Go local-receiver resolver (#240 3.177.0)
 * which puts the resolved type into `call.receiver` for
 * `func h(c *gin.Context)` shapes.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 ninth slice — Go web framework sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows?.length ?? 0) > 0;

  it('Gin — `c.Query("id")` flows to SQL sink', async () => {
    const code = `package main
import (
  "github.com/gin-gonic/gin"
  "database/sql"
)
func h(c *gin.Context, db *sql.DB) {
  id := c.Query("id")
  db.Query("SELECT * FROM t WHERE id = " + id)
}`;
    const r = await analyze(code, 'gin.go', 'go');
    expect(hasFlow(r)).toBe(true);
  });

  it('Gin — `c.BindJSON(&d)` flows (body binder)', async () => {
    const code = `package main
import (
  "github.com/gin-gonic/gin"
  "database/sql"
)
type Q struct{ Sql string }
func h(c *gin.Context, db *sql.DB) {
  var q Q
  c.BindJSON(&q)
  db.Query(q.Sql)
}`;
    const r = await analyze(code, 'gin-bind.go', 'go');
    expect(hasFlow(r)).toBe(true);
  });

  it('Echo — `c.QueryParam("id")` flows', async () => {
    const code = `package main
import (
  "github.com/labstack/echo/v4"
  "database/sql"
)
func h(c echo.Context, db *sql.DB) error {
  id := c.QueryParam("id")
  db.Query("SELECT * FROM t WHERE id = " + id)
  return nil
}`;
    const r = await analyze(code, 'echo.go', 'go');
    expect(hasFlow(r)).toBe(true);
  });

  it('Echo — `c.FormValue("k")` flows', async () => {
    const code = `package main
import (
  "github.com/labstack/echo/v4"
  "database/sql"
)
func h(c echo.Context, db *sql.DB) error {
  v := c.FormValue("k")
  db.Query("SELECT * FROM t WHERE k = " + v)
  return nil
}`;
    const r = await analyze(code, 'echo-form.go', 'go');
    expect(hasFlow(r)).toBe(true);
  });

  it('Fiber — `c.Params("id")` flows', async () => {
    const code = `package main
import (
  "github.com/gofiber/fiber/v2"
  "database/sql"
)
func h(c *fiber.Ctx, db *sql.DB) error {
  id := c.Params("id")
  db.Query("SELECT * FROM t WHERE id = " + id)
  return nil
}`;
    const r = await analyze(code, 'fiber.go', 'go');
    expect(hasFlow(r)).toBe(true);
  });

  it('Fiber — `c.BodyParser(&d)` flows (body binder)', async () => {
    const code = `package main
import (
  "github.com/gofiber/fiber/v2"
  "database/sql"
)
type Q struct{ Sql string }
func h(c *fiber.Ctx, db *sql.DB) error {
  var q Q
  c.BodyParser(&q)
  db.Query(q.Sql)
  return nil
}`;
    const r = await analyze(code, 'fiber-bp.go', 'go');
    expect(hasFlow(r)).toBe(true);
  });
});
