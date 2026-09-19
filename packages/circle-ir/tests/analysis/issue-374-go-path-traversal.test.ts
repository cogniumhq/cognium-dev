/**
 * cognium-dev #374 — Go CWE-22 recall: 15 of 17 repos missed on the Cisco
 * vulnerability-localization corpus, the single largest taint-class gap in Go.
 *
 * Two independent causes, both found by reading what the missed files actually
 * contain rather than by guessing at the sink model.
 *
 * 1. MISSING SINKS. Only `os.Open`, `os.ReadFile` and `os.WriteFile` were
 *    registered for Go. Counting file-opening calls across the CWE-22
 *    ground-truth files:
 *
 *      filepath.Join 21 · os.Stat 14 · filepath.Clean 11 · os.Create 9
 *      os.OpenFile 8 · os.Open 6 · os.RemoveAll 4 · os.Remove 3
 *      ioutil.WriteFile 2 · ioutil.ReadFile 2
 *
 *    `os.Create` and `os.OpenFile` together outnumber `os.Open` nearly 3:1 and
 *    were not sinks at all — so a tainted path reaching a file CREATE was
 *    silent while the same path reaching a file OPEN was reported.
 *
 *    `os.Stat` is deliberately excluded despite appearing 14 times: it returns
 *    metadata only, so a traversal there discloses existence rather than
 *    content, and it fires on every path-validation helper that stats before
 *    opening — including the correct ones.
 *
 * 2. ZIP SLIP WAS MODELLED FOR JAVA ONLY. `ZipEntry.getName`,
 *    `TarArchiveEntry.getName` (issue #52) are METHOD calls and the source
 *    matcher is method-based. In Go the entry name is a struct FIELD:
 *
 *        for _, f := range r.File { p := filepath.Join(dest, f.Name); os.Create(p) }
 *        hdr, err := tr.Next();     p := filepath.Join(dest, hdr.Name)
 *
 *    so nothing matched and Go archive extraction was entirely invisible.
 *    That is the dominant shape in the corpus — its CWE-22 ground-truth files
 *    are extractors (`unzip.go`, `uzip.go`, the singularity squashfs unpacker).
 *
 * THE PRECISION HALF is why this is not just two registry additions. A CORRECT
 * Go extractor validates the joined path, and the first cut of the source fired
 * on exactly that code. Shipping it would have traded a false-negative class
 * for a worse false-positive one — the trade refused on #368. Hence the
 * containment-guard sanitizer, covering both canonical idioms, and relying on
 * `guardRejects` (#333) so a guard whose body does NOT reject earns nothing.
 *
 * The guard sanitizer is restricted to lines mentioning the guarded variable,
 * so a co-located flow through a DIFFERENT variable is not silently cleared —
 * the failure mode that withdrew #348.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const pt = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal' && !f.sanitized);

const go = (code: string) => analyze(code, 'x.go', 'go');

const httpSink = (stmt: string) => `package main
import ("net/http"; "os"; "io/ioutil")
func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	${stmt}
}`;

describe('#374 Go CWE-22: sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it.each([
    ['os.Open (pre-existing)', 'f, _ := os.Open("/d/" + name); _ = f'],
    ['os.Create', 'f, _ := os.Create("/d/" + name); _ = f'],
    ['os.OpenFile', 'f, _ := os.OpenFile("/d/" + name, os.O_RDWR, 0644); _ = f'],
    ['os.Remove', 'os.Remove("/d/" + name)'],
    ['os.RemoveAll', 'os.RemoveAll("/d/" + name)'],
    ['ioutil.ReadFile', 'b, _ := ioutil.ReadFile("/d/" + name); _ = b'],
    ['ioutil.WriteFile', 'ioutil.WriteFile("/d/" + name, []byte("x"), 0644)'],
  ])('reports a tainted path reaching %s', async (_label, stmt) => {
    expect((await go(httpSink(stmt))).taint.flows?.filter(f => f.sink_type === 'path_traversal').length ?? 0)
      .toBeGreaterThan(0);
  });

  it('does NOT treat os.Stat as a sink — metadata only, and it guards correct code', async () => {
    expect(pt(await go(httpSink('st, _ := os.Stat("/d/" + name); _ = st')))).toHaveLength(0);
  });
});

describe('#374 Go CWE-22: Zip/Tar Slip', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports an unsafe zip extractor', async () => {
    expect(pt(await go(`package main
import ("archive/zip"; "os"; "path/filepath")
func f(r *zip.Reader, dest string) {
	for _, f := range r.File {
		p := filepath.Join(dest, f.Name)
		out, _ := os.Create(p)
		_ = out
	}
}`)).length).toBeGreaterThan(0);
  });

  it('reports an unsafe tar extractor', async () => {
    expect(pt(await go(`package main
import ("archive/tar"; "os"; "path/filepath")
func f(tr *tar.Reader, dest string) {
	for {
		hdr, err := tr.Next()
		if err != nil { return }
		p := filepath.Join(dest, hdr.Name)
		out, _ := os.Create(p)
		_ = out
	}
}`)).length).toBeGreaterThan(0);
  });

  it('stays clean when a HasPrefix containment guard rejects', async () => {
    expect(pt(await go(`package main
import ("archive/zip"; "os"; "path/filepath"; "strings")
func f(r *zip.Reader, dest string) error {
	for _, f := range r.File {
		p := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(p, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		out, _ := os.Create(p)
		_ = out
	}
	return nil
}`))).toHaveLength(0);
  });

  it('stays clean for the filepath.Rel + ".." idiom', async () => {
    expect(pt(await go(`package main
import ("archive/zip"; "os"; "path/filepath"; "strings")
func f(r *zip.Reader, dest string) error {
	for _, f := range r.File {
		p := filepath.Join(dest, f.Name)
		rel, err := filepath.Rel(dest, p)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		out, _ := os.Create(p)
		_ = out
	}
	return nil
}`))).toHaveLength(0);
  });

  it('STILL reports when the guard only logs — guardRejects is load-bearing', async () => {
    expect(pt(await go(`package main
import ("archive/zip"; "os"; "path/filepath"; "strings"; "log")
func f(r *zip.Reader, dest string) {
	for _, f := range r.File {
		p := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(p, dest) {
			log.Printf("odd %s", p)
		}
		out, _ := os.Create(p)
		_ = out
	}
}`)).length).toBeGreaterThan(0);
  });

  it('STILL reports when the guard covers a DIFFERENT variable', async () => {
    expect(pt(await go(`package main
import ("archive/zip"; "os"; "path/filepath"; "strings")
func f(r *zip.Reader, dest string, other string) {
	for _, f := range r.File {
		p := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(other, dest) {
			continue
		}
		out, _ := os.Create(p)
		_ = out
	}
}`)).length).toBeGreaterThan(0);
  });

  it('does not fire without an archive import', async () => {
    expect(pt(await go(`package main
import ("os"; "path/filepath")
type E struct{ Name string }
func f(entries []E, dest string) {
	for _, f := range entries {
		p := filepath.Join(dest, f.Name)
		out, _ := os.Create(p)
		_ = out
	}
}`))).toHaveLength(0);
  });

  it('does not fire on an unrelated .Name read', async () => {
    expect(pt(await go(`package main
import ("archive/zip"; "os"; "path/filepath")
func f(fi os.FileInfo, dest string) {
	_ = zip.Reader{}
	p := filepath.Join(dest, fi.Name())
	out, _ := os.Create(p)
	_ = out
}`))).toHaveLength(0);
  });
});
