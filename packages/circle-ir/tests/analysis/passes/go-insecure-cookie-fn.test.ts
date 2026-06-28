import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 56 — #182 Slice B: Go `http.SetCookie(w, &http.Cookie{Secure:false,
 * HttpOnly:false})` must fire insecure-cookie. The insecure-cookie pass
 * currently handles js/ts/python/java only; the Go branch is missing.
 *
 * Recall locks: explicit Secure+HttpOnly true → no finding;
 * unrelated http.* calls → no finding.
 */
describe('Sprint 56 — #182 Go insecure-cookie', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countInsecure = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.findings ?? []).filter(f => f.rule_id === 'insecure-cookie').length;

  it('FN — http.SetCookie with Secure:false must fire', async () => {
    const code = `package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x", Secure: false, HttpOnly: false})
}`;
    const r = await analyze(code, 'a.go', 'go');
    expect(countInsecure(r)).toBeGreaterThanOrEqual(1);
  });

  it('FN — http.SetCookie missing Secure entirely must fire', async () => {
    const code = `package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x"})
}`;
    const r = await analyze(code, 'b.go', 'go');
    expect(countInsecure(r)).toBeGreaterThanOrEqual(1);
  });

  it('TN — explicit Secure:true + HttpOnly:true must not fire', async () => {
    const code = `package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x", Secure: true, HttpOnly: true})
}`;
    const r = await analyze(code, 'c.go', 'go');
    expect(countInsecure(r)).toBe(0);
  });

  it('TN — unrelated http call must not fire', async () => {
    const code = `package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "/", 302)
}`;
    const r = await analyze(code, 'd.go', 'go');
    expect(countInsecure(r)).toBe(0);
  });
});
