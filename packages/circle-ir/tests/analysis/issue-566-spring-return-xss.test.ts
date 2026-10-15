/**
 * cognium-dev#566 — a Spring handler whose returned String is the response
 * body (`@RestController`, `@ResponseBody`, `ResponseEntity.ok(...)`) and
 * that concatenates request data into markup is reflected XSS. A plain
 * `@Controller` String return is a view name, and a non-HTML `produces` keeps
 * the body out of an HTML context.
 *
 * SAST regression fixture — the `Shoutbox` / `Fragments` handlers are
 * deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const restApi = `package com.acme.board;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class Shoutbox {
    @GetMapping("/shout")
    public String shout(@RequestParam String message) {
        return "<blockquote>" + message + "</blockquote>";
    }

    @GetMapping("/headline")
    public ResponseEntity<String> headline(@RequestParam("h") String caption) {
        String markup = "<h2>" + caption + "</h2>";
        return ResponseEntity.ok(markup);
    }

    @PostMapping("/memo/{slot}")
    public ResponseEntity<String> memo(@PathVariable String slot, @RequestBody String memo) {
        return new ResponseEntity<>("<pre>" + slot + memo + "</pre>", HttpStatus.CREATED);
    }

    @GetMapping(value = "/plain", produces = MediaType.TEXT_PLAIN_VALUE)
    public String plain(@RequestParam String message) {
        return "<blockquote>" + message + "</blockquote>";
    }

    @GetMapping(path = "/json", produces = "application/json")
    public String json(@RequestParam String message) {
        return "{\\"m\\":\\"" + message + "\\"}";
    }

    @GetMapping("/escaped")
    public String escaped(@RequestParam String message) {
        return "<blockquote>" + HtmlUtils.htmlEscape(message) + "</blockquote>";
    }

    @GetMapping("/echo")
    public String echo(@RequestParam String message) {
        return message;
    }

    @GetMapping("/size")
    public int size(@RequestParam String message) {
        return message.length();
    }
}
`;

const mvc = `package com.acme.board;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class Fragments {
    @GetMapping("/")
    public String landing() {
        return "landing";
    }

    @GetMapping("/theme")
    public String theme(@RequestParam String skin) {
        return "themes/" + skin;
    }

    @GetMapping("/chip")
    @ResponseBody
    public String chip(@RequestParam String tag) {
        return "<span class=chip>" + tag + "</span>";
    }
}
`;

function xssFlowLines(r: Awaited<ReturnType<typeof analyze>>): number[] {
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))].sort((a, b) => a - b);
}

describe('cognium-dev#566 — Spring return-as-body xss', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('@RestController String, ResponseEntity.ok and new ResponseEntity report xss; non-HTML returns stay clean', async () => {
    const r = await analyze(restApi, 'Shoutbox.java', 'java');
    expect(xssFlowLines(r)).toEqual([18, 24, 29]);
  });

  it('plain @Controller String returns are view names; method-level @ResponseBody is a body', async () => {
    const r = await analyze(mvc, 'Fragments.java', 'java');
    expect(xssFlowLines(r)).toEqual([24]);
  });

  it('number, boolean and UUID bound parameters cannot carry markup', async () => {
    const code = `package com.acme.board;

import java.util.UUID;
import org.springframework.web.bind.annotation.*;

@RestController
public class Items {
    @GetMapping("/item/{id}")
    public String item(@PathVariable long id) {
        return "<p>item " + id + "</p>";
    }

    @GetMapping("/page")
    public String page(@RequestParam Integer pageNo, @RequestParam Boolean on) {
        return "<span>" + pageNo + on + "</span>";
    }

    @GetMapping("/u/{uid}")
    public String user(@PathVariable java.util.UUID uid) {
        return "<a>" + uid + "</a>";
    }

    @GetMapping("/name")
    public String name(@RequestParam String who) {
        return "<b>" + who + "</b>";
    }
}
`;
    const r = await analyze(code, 'Items.java', 'java');
    expect(xssFlowLines(r)).toEqual([25]);
  });
});
