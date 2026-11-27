/**
 * A Java path-traversal flow whose source is the tool's own arguments.
 *
 * A command-line tool or a Maven plugin opens the files its own user names:
 * the `String[]` of `main`, an option read from a commons-cli `CommandLine`,
 * a Mojo `@Parameter`. The flow still reports, tagged
 * `tool-arguments:local-input` and at half its confidence, so a reader can
 * see the input is the tool's own arguments. Other sources, other sinks, and
 * a helper that a non-`main` caller also feeds keep the plain finding.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, analyzeProject, initAnalyzer } from '../../src/analyzer.js';
import { TOOL_ARGUMENTS_TAG } from '../../src/analysis/tool-arguments.js';
import type { TaintFlowInfo } from '../../src/types/index.js';

const pt = (flows: TaintFlowInfo[], sinkLine: number) =>
  flows.filter(f => f.sink_type === 'path_traversal' && f.sink_line === sinkLine);
const tagged = (f: TaintFlowInfo) => f.tags?.includes(TOOL_ARGUMENTS_TAG) === true;

const tool = [
  'import java.io.*;',
  'public class Tool {',
  '  public static void main(String[] args) throws IOException {',
  '    FileInputStream in = new FileInputStream(args[0]);',
  '    load(args);',
  '  }',
  '  static void load(String[] args) throws IOException {',
  '    new FileReader(new File(args[1]));',
  '  }',
  '  public void other(String name) throws IOException {',
  '    new FileInputStream(name);',
  '  }',
  '}',
].join('\n');

describe('path traversal from the tool\'s own arguments', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('tags a flow from main(String[] args) and halves its confidence', async () => {
    const r = await analyze(tool, 'Tool.java', 'java');
    const [fromMain] = pt(r.taint.flows, 4);
    const [plain] = pt(r.taint.flows, 11);
    expect(fromMain).toBeDefined();
    expect(tagged(fromMain)).toBe(true);
    expect(tagged(plain)).toBe(false);
    expect(fromMain.confidence).toBeCloseTo(plain.confidence / 2, 5);
  });

  it('tags a String[] helper that only main hands its args to', async () => {
    const r = await analyze(tool, 'Tool.java', 'java');
    const flows = pt(r.taint.flows, 8);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every(tagged)).toBe(true);
  });

  it('does not tag a String[] helper another caller also feeds', async () => {
    const code = [
      'import java.io.*;',
      'public class Tool {',
      '  public static void main(String[] args) throws IOException { load(args); }',
      '  static void again(String[] names) throws IOException { load(names); }',
      '  static void load(String[] args) throws IOException {',
      '    new FileInputStream(args[0]);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Tool.java', 'java');
    const fromLoad = pt(r.taint.flows, 6).filter(f => f.source_line === 5);
    expect(fromLoad.length).toBeGreaterThan(0);
    expect(fromLoad.some(tagged)).toBe(false);
  });

  it('does not tag a public String[] helper (a caller in another file may pass anything)', async () => {
    const code = [
      'import java.io.*;',
      'public class Tool {',
      '  public static void main(String[] args) throws IOException { load(args); }',
      '  public static void load(String[] args) throws IOException {',
      '    new FileInputStream(args[0]);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Tool.java', 'java');
    const fromLoad = pt(r.taint.flows, 5).filter(f => f.source_line === 4);
    expect(fromLoad.length).toBeGreaterThan(0);
    expect(fromLoad.some(tagged)).toBe(false);
  });

  it('tags a value read from a commons-cli CommandLine, and keeps the flow', async () => {
    const code = [
      'import java.io.*;',
      'import org.apache.commons.cli.*;',
      'public class Cli {',
      '  public static void main(String[] args) throws Exception {',
      '    Options options = new Options();',
      '    CommandLineParser parser = new DefaultParser();',
      '    CommandLine line = parser.parse(options, args);',
      '    String f = line.getOptionValue("f");',
      '    new FileInputStream(f);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Cli.java', 'java');
    const flows = pt(r.taint.flows, 9);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every(tagged)).toBe(true);
  });

  it('does not tag another stream read in a commons-cli tool', async () => {
    const code = [
      'import java.io.*;',
      'import org.apache.commons.cli.*;',
      'public class Cli {',
      '  void run(BufferedReader in) throws IOException {',
      '    String f = in.readLine();',
      '    new FileInputStream(f);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Cli.java', 'java');
    const flows = pt(r.taint.flows, 6).filter(f => f.source_type === 'io_input');
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(tagged)).toBe(false);
  });

  it('tags the setter of a Mojo @Parameter field, not another setter', async () => {
    const code = [
      'import java.io.*;',
      'import org.apache.maven.plugin.AbstractMojo;',
      'import org.apache.maven.plugins.annotations.*;',
      '@Mojo(name = "goal")',
      'public class GoalMojo extends AbstractMojo {',
      '  @Parameter(property = "reportFile")',
      '  String reportFile;',
      '  public void setReportFile(String reportFile) throws IOException {',
      '    new FileInputStream(reportFile);',
      '  }',
      '  public void setOther(String other) throws IOException {',
      '    new FileInputStream(other);',
      '  }',
      '  public void execute() {}',
      '}',
    ].join('\n');
    const r = await analyze(code, 'GoalMojo.java', 'java');
    expect(pt(r.taint.flows, 9).length).toBeGreaterThan(0);
    expect(pt(r.taint.flows, 9).every(tagged)).toBe(true);
    expect(pt(r.taint.flows, 12).length).toBeGreaterThan(0);
    expect(pt(r.taint.flows, 12).some(tagged)).toBe(false);
  });

  it('does not tag a same-named setter outside a Mojo', async () => {
    const code = [
      'import java.io.*;',
      'public class Plain {',
      '  @Parameter String reportFile;',
      '  public void setReportFile(String reportFile) throws IOException {',
      '    new FileInputStream(reportFile);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Plain.java', 'java');
    expect(pt(r.taint.flows, 5).length).toBeGreaterThan(0);
    expect(pt(r.taint.flows, 5).some(tagged)).toBe(false);
  });

  it('does not tag a request parameter', async () => {
    const code = [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class Web extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '    new FileInputStream(req.getParameter("f"));',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Web.java', 'java');
    expect(pt(r.taint.flows, 5).length).toBeGreaterThan(0);
    expect(pt(r.taint.flows, 5).some(tagged)).toBe(false);
  });

  it('tags only path traversal: main args into a command keep the plain finding', async () => {
    const code = [
      'public class Run {',
      '  public static void main(String[] args) throws Exception {',
      '    Runtime.getRuntime().exec(args[0]);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Run.java', 'java');
    const cmd = r.taint.flows.filter(f => f.sink_type === 'command_injection');
    expect(cmd.length).toBeGreaterThan(0);
    expect(cmd.some(tagged)).toBe(false);
  });

  it('tags a cross-file path from a CommandLine option, and its flow in the sink file', async () => {
    const files = [
      { filePath: '/p/src/Runner.java', language: 'java' as const, code: [
        'package p;',
        'import org.apache.commons.cli.*;',
        'public class Runner {',
        '  public static void main(String[] args) throws Exception {',
        '    Options options = new Options();',
        '    CommandLineParser parser = new DefaultParser();',
        '    CommandLine line = parser.parse(options, args);',
        '    Crawler c = new Crawler();',
        '    c.setTarget(line.getOptionValue("f"));',
        '  }',
        '}',
      ].join('\n') },
      { filePath: '/p/src/Crawler.java', language: 'java' as const, code: [
        'package p;',
        'import java.io.*;',
        'public class Crawler {',
        '  void setTarget(String target) {',
        '    File f = new File(target);',
        '  }',
        '}',
      ].join('\n') },
    ];
    const res = await analyzeProject(files, {});
    const paths = res.taint_paths.filter(p => p.sink.type === 'path_traversal' && p.source.file === '/p/src/Runner.java');
    expect(paths.length).toBeGreaterThan(0);
    expect(paths.every(p => p.tags?.includes(TOOL_ARGUMENTS_TAG))).toBe(true);
    expect(paths.every(p => p.confidence < 0.5)).toBe(true);
    const crawler = res.files.find(f => f.file === '/p/src/Crawler.java')!;
    const promoted = pt(crawler.analysis.taint.flows, 5).filter(f => f.source_type === 'io_input');
    expect(promoted.length).toBeGreaterThan(0);
    expect(promoted.every(tagged)).toBe(true);
    // the setter's own parameter is not known to be a tool argument: it stays plain
    expect(pt(crawler.analysis.taint.flows, 5).some(f => f.source_type === 'interprocedural_param' && !tagged(f))).toBe(true);
  });
});
