/**
 * Tests for cognium-dev #167 + #170 — Java `command_injection`
 * (CWE-78) Stage 10 FP suppression.
 *
 * Sprint 43 adds a new Stage 10 to `sink-filter-pass.ts`, scoped to
 * `language === 'java'` AND `sink.type === 'command_injection'`. Two
 * sub-stages:
 *
 *   10a (#167): picocli `new CommandLine(...)` — annotation-driven
 *               CLI parser. Collides with Apache Commons Exec
 *               `CommandLine` in the existing CWE_78_RECEIVER_ALLOWLIST
 *               at `taint-matcher.ts`. Suppressed when the file
 *               imports `picocli.*`.
 *
 *   10b (#170): protocol-client wire-command methods (Jedis / Lettuce
 *               / Kafka / Rabbit / Mongo / Paho / Spring-Data). The
 *               receiver is implicit `this` so `receiver_type` is
 *               unresolved and the existing classless `executeCommand`
 *               / `execute` / `dispatch` / `send` / `publish` / `run`
 *               sink rule overfires. Suppressed when the file imports
 *               a protocol-client package AND the sink line doesn't
 *               carry an explicit OS-exec receiver.
 *
 * Recall lock: real `Runtime.exec(userInput)` /
 * `new ProcessBuilder(userInput).start()` continues to fire.
 * Defense-in-depth: a protocol-client file that ALSO calls
 * `Runtime.exec(...)` keeps the Runtime sink.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countCmdSinks = (
  sinks: Array<{ type?: string }> | undefined,
) => (sinks ?? []).filter((s) => s.type === 'command_injection').length;

describe('cognium-dev #167 + #170 — Java command_injection Stage 10 FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // 10a — #167: picocli new CommandLine(...) collision
  // -------------------------------------------------------------------------

  it('FP #167 — picocli new CommandLine(MyApp.class): no command_injection sink', async () => {
    const code = `import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "myapp")
public class MyApp implements Runnable {
  public void run() { System.out.println("hello"); }
  public static void main(String[] args) {
    int code = new CommandLine(new MyApp()).execute(args);
    System.exit(code);
  }
}
`;
    const r = await analyze(code, 'MyApp.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 10b — #170: protocol-client wire-command FPs
  // -------------------------------------------------------------------------

  it('FP #170 — jedis UnifiedJedis this.executeCommand(...): no command_injection sink', async () => {
    const code = `import redis.clients.jedis.UnifiedJedis;
import redis.clients.jedis.CommandObjects;

public class JedisClient extends UnifiedJedis {
  private final CommandObjects commandObjects = new CommandObjects();
  public Object search(String q) {
    return this.executeCommand(commandObjects.ftSearch("idx", q));
  }
}
`;
    const r = await analyze(code, 'JedisClient.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #170 — lettuce RedisCommand.dispatch(cmd): no command_injection sink', async () => {
    const code = `import io.lettuce.core.RedisCommand;

public class LettuceClient {
  public Object run(RedisCommand cmd) {
    return cmd.dispatch(cmd);
  }
}
`;
    const r = await analyze(code, 'LettuceClient.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #170 — spring-data-redis RedisTemplate.execute(cb): no command_injection sink', async () => {
    const code = `import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.RedisCallback;

public class RedisService {
  private final RedisTemplate<String,Object> tpl;
  public RedisService(RedisTemplate<String,Object> tpl) { this.tpl = tpl; }
  public Object call(RedisCallback<Object> cb) {
    return tpl.execute(cb);
  }
}
`;
    const r = await analyze(code, 'RedisService.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #170 — kafka KafkaProducer.send(record): no command_injection sink', async () => {
    const code = `import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;

public class KafkaPublisher {
  private final KafkaProducer<String,String> kp;
  public KafkaPublisher(KafkaProducer<String,String> kp) { this.kp = kp; }
  public void publish(ProducerRecord<String,String> record) {
    kp.send(record);
  }
}
`;
    const r = await analyze(code, 'KafkaPublisher.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall locks — sinks that MUST continue to fire
  // -------------------------------------------------------------------------

  it('Recall — Runtime.getRuntime().exec(userInput): command_injection sink fires', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;

public class DangerousExec {
  public Process run(HttpServletRequest req) throws Exception {
    String cmd = req.getParameter("cmd");
    return Runtime.getRuntime().exec(cmd);
  }
}
`;
    const r = await analyze(code, 'DangerousExec.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — new ProcessBuilder(userInput).start(): command_injection sink fires', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;

public class DangerousPb {
  public Process run(HttpServletRequest req) throws Exception {
    String cmd = req.getParameter("cmd");
    return new ProcessBuilder(cmd).start();
  }
}
`;
    const r = await analyze(code, 'DangerousPb.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Defense-in-depth — jedis file with real Runtime.exec: Runtime sink still fires', async () => {
    const code = `import redis.clients.jedis.UnifiedJedis;
import javax.servlet.http.HttpServletRequest;

public class MixedJedis {
  public Process backdoor(HttpServletRequest req) throws Exception {
    String cmd = req.getParameter("cmd");
    return Runtime.getRuntime().exec(cmd);
  }
}
`;
    const r = await analyze(code, 'MixedJedis.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });
});
