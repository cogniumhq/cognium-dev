/**
 * Tests for cognium-dev #213 — WebSocket transport-channel sources.
 *
 * Second slice of the #213 transport-channel matrix. Extends the Lambda
 * event-shape coverage from the first slice with WebSocket handler
 * payload sources across the four languages that ship WS-handler idioms:
 *
 *   - Python — FastAPI / Starlette / Django Channels: `WebSocket.receive_*`
 *   - Go     — gorilla/websocket, nhooyr.io/websocket: `Conn.ReadMessage`
 *   - Java   — Jakarta WebSocket + Spring STOMP: `@OnMessage`,
 *              `@MessageMapping`, `@SubscribeMapping`
 *
 * JS/TS WebSocket handlers (`ws.on('message', (data) => ...)`) use a
 * callback-parameter shape that the current pattern format (property
 * source / return-tainted method / annotated param) doesn't express.
 * Deferred for a follow-up slice.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows?.length ?? 0) > 0;

describe('cognium-dev #213 — WebSocket transport-channel sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ── Python ────────────────────────────────────────────────────────────

  it('TP — FastAPI `WebSocket.receive_text()` flows to command exec', async () => {
    const code = `from fastapi import WebSocket
import subprocess

async def endpoint(websocket: WebSocket):
    await websocket.accept()
    data = await websocket.receive_text()
    subprocess.run(data, shell=True)
`;
    const r = await analyze(code, 'ws-text.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — FastAPI `WebSocket.receive_json()` field flows to command exec', async () => {
    const code = `from fastapi import WebSocket
import subprocess

async def endpoint(websocket: WebSocket):
    await websocket.accept()
    payload = await websocket.receive_json()
    subprocess.run("echo " + payload["cmd"], shell=True)
`;
    const r = await analyze(code, 'ws-json.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — inline `await websocket.receive_text()` at sink call site flows', async () => {
    const code = `from fastapi import WebSocket
import subprocess

async def endpoint(websocket: WebSocket):
    subprocess.run(await websocket.receive_text(), shell=True)
`;
    const r = await analyze(code, 'ws-inline.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('FP-guard — bare `queue.receive()` does not fire (not WebSocket-scoped)', async () => {
    // We deliberately did not add a bare `.receive\s*\(` regex; only
    // `receive_text` / `receive_bytes` / `receive_json` are broad, and
    // `receive` is class-scoped to `WebSocket`. Verify a synthetic queue
    // pattern with a bare `receive()` doesn't emit a WS-typed source.
    const code = `import subprocess

def handler(queue):
    data = queue.receive()
    subprocess.run(data, shell=True)
`;
    const r = await analyze(code, 'queue.py', 'python');
    const wsTyped = r.taint.sources.filter(
      s => s.type === 'network_input' || s.type === 'http_body',
    );
    expect(wsTyped.length).toBe(0);
  });

  // ── Go ────────────────────────────────────────────────────────────────

  it('TP — Go gorilla/websocket `Conn.ReadMessage()` flows to SQL sink', async () => {
    const code = `package main
import (
  "database/sql"
  "github.com/gorilla/websocket"
)

func handler(conn *websocket.Conn, db *sql.DB) {
  _, message, _ := conn.ReadMessage()
  db.Query("SELECT * FROM t WHERE x = " + string(message))
}
`;
    const r = await analyze(code, 'ws.go', 'go');
    expect(hasFlow(r)).toBe(true);
  });

  // ── Java ──────────────────────────────────────────────────────────────

  it('TP — Java `@OnMessage` param flows to SQL sink', async () => {
    const code = `import javax.websocket.OnMessage;
import java.sql.Statement;

public class Ws {
  Statement st;
  @OnMessage
  public void onMessage(String msg) throws Exception {
    st.execute("SELECT * FROM t WHERE x = '" + msg + "'");
  }
}
`;
    const r = await analyze(code, 'Ws.java', 'java');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — Spring STOMP `@MessageMapping` param flows to SQL sink', async () => {
    const code = `import org.springframework.messaging.handler.annotation.MessageMapping;
import java.sql.Statement;

public class StompCtrl {
  Statement st;
  @MessageMapping("/greet")
  public void greet(String body) throws Exception {
    st.execute("SELECT * FROM t WHERE x = '" + body + "'");
  }
}
`;
    const r = await analyze(code, 'StompCtrl.java', 'java');
    expect(hasFlow(r)).toBe(true);
  });
});
