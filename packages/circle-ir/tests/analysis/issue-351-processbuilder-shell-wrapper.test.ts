/**
 * cognium-dev #351 — `ProcessBuilder` only reported `command_injection` when
 * the tainted value sat at argument 0, so the canonical shell-wrapper shape
 * was missed in both the constructor and the `.command(...)` setter:
 *
 *   new ProcessBuilder("bash", "-c", "cowsay '" + input + "'")   // payload at 2
 *   pb.command("bash", "-c", "cowsay '" + input + "'")
 *
 * `Runtime.exec(String[])` with the identical array already fired, so the taint
 * was available and only the sink model was wrong.
 *
 * TWO things were wrong, and the second is the interesting one.
 *
 * 1. `arg_positions: [0]` on the constructor and on `command`. Both take
 *    `String...` varargs (or one `List<String>`), so every element is a command
 *    token. Now enumerated `[0..7]` rather than `[]`, because the two layers
 *    reading that field disagree about an empty array: `isInDangerousPosition`
 *    does `arg_positions.includes(pos)` — `[]` matches NOTHING — while the
 *    sink-reachability loop in taint-propagation treats `length === 0` as "any
 *    argument". `ProcessBuilder.start` gets away with `[]` only because it
 *    takes no arguments.
 *
 * 2. The #179 argv-form suppression in sink-filter-pass then dropped the sink
 *    anyway — including the chained `.start()` on the same line. That
 *    suppression is CORRECT in general: `ProcessBuilder(List<String>)` and
 *    `(String...)` hand argv straight to fork(2), so a tainted element is one
 *    argv slot with no shell and no metacharacter expansion. It is wrong only
 *    when argv[0] is itself a shell, because then argv[1..] is a script and the
 *    tainted element IS a shell command string.
 *
 * So the fix is a shell-interpreter exception, not "every argument is
 * dangerous". Keeping #179 intact matters: `new ProcessBuilder(List.of("cowsay",
 * input))` is argument injection (CWE-88) at most — `input` cannot start a new
 * command — and reporting it as CWE-78 is the false positive #179 removed.
 *
 * NOTE — this is a deliberate deviation from the issue, which also expects a
 * tainted `List<String>` to fire. It should not, unless the list starts with a
 * shell; see the "argv, non-shell" cases below.
 *
 * Widening `command`'s positions also opened a new FP that the issue does not
 * mention: `pb.command("ls", input)` had no argv-form suppression of its own,
 * since #179 only ever matched `new ProcessBuilder(`. Hence the sibling
 * `PROCESS_BUILDER_COMMAND_ARGV_FORM_RE` — otherwise this fix would trade an
 * FN for an FP.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const TAINT = '"cowsay \'" + input + "\'"';

const run = (body: string[]) =>
  analyze(
    [
      'import java.util.*;',
      'import org.springframework.web.bind.annotation.*;',
      '@RestController public class V {',
      '  @GetMapping("/x") public String x(@RequestParam String input) throws Exception {',
      ...body.map(l => '    ' + l),
      '    return "";',
      '  }',
      '}',
    ].join('\n'),
    'V.java',
    'java'
  );

const cmdi = async (body: string[]) =>
  ((await run(body)).taint.flows ?? []).filter(
    f => f.sink_type === 'command_injection' && !f.sanitized
  );

describe('#351 ProcessBuilder shell-wrapper command injection', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('fires — argv[0] is a shell, so the tainted element is a script', () => {
    it('constructor varargs, bash -c', async () => {
      expect(await cmdi([`Process p = new ProcessBuilder("bash","-c",${TAINT}).start();`]))
        .not.toHaveLength(0);
    });

    it('constructor varargs, absolute /bin/sh', async () => {
      expect(await cmdi([`Process p = new ProcessBuilder("/bin/sh","-c",${TAINT}).start();`]))
        .not.toHaveLength(0);
    });

    it('constructor varargs, Windows cmd.exe /c', async () => {
      expect(await cmdi([`Process p = new ProcessBuilder("cmd.exe","/c",${TAINT}).start();`]))
        .not.toHaveLength(0);
    });

    it('constructor with List.of(shell, …)', async () => {
      expect(await cmdi([`Process p = new ProcessBuilder(List.of("sh","-c",${TAINT})).start();`]))
        .not.toHaveLength(0);
    });

    it('constructor with Arrays.asList(shell, …)', async () => {
      expect(
        await cmdi([`Process p = new ProcessBuilder(Arrays.asList("bash","-c",${TAINT})).start();`])
      ).not.toHaveLength(0);
    });

    it('constructor with new String[]{shell, …}', async () => {
      expect(
        await cmdi([`Process p = new ProcessBuilder(new String[]{"bash","-c",${TAINT}}).start();`])
      ).not.toHaveLength(0);
    });

    it('.command(…) varargs on a receiver', async () => {
      expect(
        await cmdi([
          'ProcessBuilder pb = new ProcessBuilder();',
          `pb.command("bash","-c",${TAINT});`,
          'Process p = pb.start();',
        ])
      ).not.toHaveLength(0);
    });

    it('.command(List.of(shell, …))', async () => {
      expect(
        await cmdi([
          'ProcessBuilder pb = new ProcessBuilder();',
          `pb.command(List.of("sh","-c",${TAINT}));`,
          'Process p = pb.start();',
        ])
      ).not.toHaveLength(0);
    });

    it('single tainted command string (the shape that already worked)', async () => {
      expect(await cmdi([`Process p = new ProcessBuilder(${TAINT}).start();`])).not.toHaveLength(0);
    });

    it('Runtime.exec(String[]) with the same array — the control that always fired', async () => {
      expect(
        await cmdi([
          `String[] c = {"bash","-c",${TAINT}}; Process p = Runtime.getRuntime().exec(c);`,
        ])
      ).not.toHaveLength(0);
    });
  });

  describe('stays clean — argv, non-shell: CWE-88 at most, and #179 must keep suppressing', () => {
    it('List.of with a non-shell program', async () => {
      expect(
        await cmdi(['Process p = new ProcessBuilder(List.of("cowsay", input)).start();'])
      ).toHaveLength(0);
    });

    it('varargs with a non-shell program', async () => {
      expect(
        await cmdi(['Process p = new ProcessBuilder("cowsay", input).start();'])
      ).toHaveLength(0);
    });

    it('.command with a non-shell program (the FP this fix must not open)', async () => {
      expect(
        await cmdi([
          'ProcessBuilder pb = new ProcessBuilder();',
          'pb.command("ls", input);',
          'Process p = pb.start();',
        ])
      ).toHaveLength(0);
    });

    it('constant argv, no user input at all', async () => {
      expect(
        await cmdi(['Process p = new ProcessBuilder(List.of("uptime")).start();'])
      ).toHaveLength(0);
    });
  });
});
