import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 59 — #201: Java Servlet 3.0 `Part.write(<dir> + part.getSubmittedFileName())`
 * was missed by `unrestricted-file-upload-pass`. The existing pass only
 * checked `MultipartFile.transferTo(...)` and `Files.copy(...)` in Java; the
 * Servlet API direct-write form (CVE-2021-26828 class) was overlooked.
 *
 * Fix: add a third Java call-shape — `write` receiver-agnostic (excluding
 * the pre-existing Files.write / FilePath.write sink wirings) when an arg
 * expression references an upload-name accessor (matched by `UPLOAD_NAME_RE`).
 *
 * Pre-existing positive paths (Spring `transferTo`, Python `f.save`,
 * JS multer) are recall-locked unchanged.
 */
describe('Sprint 59 — #201 unrestricted-file-upload Part.write', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const findingsFor = (
    r: Awaited<ReturnType<typeof analyze>>,
    rule: string,
  ) => (r.findings ?? []).filter(f => f.rule_id === rule);

  it('FN — Java Servlet `part.write(dir + part.getSubmittedFileName())` fires unrestricted-file-upload', async () => {
    const code = `
import javax.servlet.http.Part;

public class ServletUpload {
    public void doPost(Part part) throws Exception {
        part.write("/var/www/uploads/" + part.getSubmittedFileName());
    }
}
`;
    const r = await analyze(code, 'ServletUpload.java', 'java');
    const findings = findingsFor(r, 'unrestricted-file-upload');
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].cwe).toBe('CWE-434');
  });

  it('FN — Java Servlet `part.write(part.getName())` fires unrestricted-file-upload', async () => {
    const code = `
import javax.servlet.http.Part;

public class ServletUpload2 {
    public void doPost(Part part) throws Exception {
        part.write(part.getSubmittedFileName());
    }
}
`;
    const r = await analyze(code, 'ServletUpload2.java', 'java');
    const findings = findingsFor(r, 'unrestricted-file-upload');
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('recall — Java Spring `MultipartFile.transferTo` (pre-existing) still fires', async () => {
    const code = `
import org.springframework.web.multipart.MultipartFile;
import java.io.File;

public class UploadController {
    public void handle(MultipartFile file) throws Exception {
        file.transferTo(new File("/uploads/" + file.getOriginalFilename()));
    }
}
`;
    const r = await analyze(code, 'UploadController.java', 'java');
    expect(findingsFor(r, 'unrestricted-file-upload').length).toBeGreaterThanOrEqual(1);
  });

  it('recall — Python `f.save("/uploads/" + f.filename)` (pre-existing) still fires', async () => {
    const code = `
from flask import request

def upload():
    f = request.files['photo']
    f.save('/uploads/' + f.filename)
`;
    const r = await analyze(code, 'upload.py', 'python');
    expect(findingsFor(r, 'unrestricted-file-upload').length).toBeGreaterThanOrEqual(1);
  });

  it('TN — `Files.write(Path.of(...), bytes)` (pre-existing path_traversal sink) does NOT fire unrestricted-file-upload', async () => {
    // Files.write is path_traversal CWE-22, not upload. Our new Part.write
    // branch must not collide with it. Files receiver is excluded.
    const code = `
import java.nio.file.Files;
import java.nio.file.Path;

public class Writer {
    public void w() throws Exception {
        Files.write(Path.of("/tmp/x"), new byte[0]);
    }
}
`;
    const r = await analyze(code, 'Writer.java', 'java');
    expect(findingsFor(r, 'unrestricted-file-upload').length).toBe(0);
  });

  it('TN — `part.write("/var/www/static.html")` (literal, no upload-name) does NOT fire', async () => {
    const code = `
import javax.servlet.http.Part;

public class Static {
    public void w(Part part) throws Exception {
        part.write("/var/www/static.html");
    }
}
`;
    const r = await analyze(code, 'Static.java', 'java');
    expect(findingsFor(r, 'unrestricted-file-upload').length).toBe(0);
  });

  it('TN — `part.write(filename)` inside a function with secure_filename / FilenameUtils check does NOT fire', async () => {
    const code = `
import javax.servlet.http.Part;
import org.apache.commons.io.FilenameUtils;

public class SafeUpload {
    public void doPost(Part part) throws Exception {
        String ext = FilenameUtils.getExtension(part.getSubmittedFileName());
        part.write("/uploads/" + part.getSubmittedFileName());
    }
}
`;
    const r = await analyze(code, 'SafeUpload.java', 'java');
    expect(findingsFor(r, 'unrestricted-file-upload').length).toBe(0);
  });
});
