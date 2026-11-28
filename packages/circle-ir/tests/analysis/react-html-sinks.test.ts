/**
 * React HTML and URL sinks.
 *
 *  - `dangerouslySetInnerHTML={{ __html: x }}`: the `__html` value is the
 *    sink argument and the sink sits on its line, so an object literal that
 *    spans lines still reaches it; the same prop written as an object key
 *    (`React.createElement('div', { dangerouslySetInnerHTML: … })`) is a sink
 *    too.
 *  - `href={x}` on `<a>` and `src={x}` on `<iframe>` / `<script>` are XSS
 *    sinks (`javascript:` URLs) only for browser or URL input, and not where
 *    the URL is encoded or checked.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type Flow = { source_line: number; sink_line: number; sink_type: string };
const xssSinkLines = (r: { taint: { flows?: Flow[] } }): number[] =>
  [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))].sort((a, b) => a - b);

describe('React dangerouslySetInnerHTML', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('`__html` on a later line than the attribute name', async () => {
    const code = [
      "import React from 'react';",
      'export function Banner() {',
      '  const message = window.location.hash.substring(1);',
      '  return (',
      '    <div',
      '      className="banner"',
      '      dangerouslySetInnerHTML={{',
      '        __html: message,',
      '      }}',
      '    />',
      '  );',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Banner.jsx', 'javascript');
    expect((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => [f.source_line, f.sink_line]))
      .toEqual([[3, 8]]);
  });

  it('one-line attribute in a .tsx file', async () => {
    const code = [
      'export function Banner() {',
      "  const message = new URLSearchParams(window.location.search).get('msg');",
      '  return <div dangerouslySetInnerHTML={{ __html: message }} />;',
      '}',
    ].join('\n');
    expect(xssSinkLines(await analyze(code, 'Banner.tsx', 'typescript'))).toEqual([3]);
  });

  it('props object passed to React.createElement', async () => {
    const code = [
      "import React from 'react';",
      'export function Banner() {',
      "  const message = new URLSearchParams(window.location.search).get('msg');",
      "  return React.createElement('div', { dangerouslySetInnerHTML: { __html: message } });",
      '}',
    ].join('\n');
    const r = await analyze(code, 'banner.js', 'javascript');
    expect(xssSinkLines(r)).toEqual([4]);
    expect((r.taint.flows ?? []).some((f) => f.sink_type === 'external_taint_escape')).toBe(false);
  });

  it('no flow: sanitised value, literal markup, createElement with a literal', async () => {
    const code = [
      "import DOMPurify from 'dompurify';",
      'export function Safe() {',
      "  const message = new URLSearchParams(window.location.search).get('msg');",
      '  return <div dangerouslySetInnerHTML={{',
      '    __html: DOMPurify.sanitize(message),',
      '  }} />;',
      '}',
      'export function Static() {',
      "  return <div dangerouslySetInnerHTML={{ __html: '<b>hi</b>' }} />;",
      '}',
      'export function Element() {',
      "  return React.createElement('div', { dangerouslySetInnerHTML: { __html: '<hr>' } });",
      '}',
    ].join('\n');
    expect(xssSinkLines(await analyze(code, 'safe.jsx', 'javascript'))).toEqual([]);
  });
});

describe('React href / src URL attributes', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('browser and URL input reaching <a href>, <iframe src>, <script src>', async () => {
    const code = [
      "import { useSearchParams } from 'react-router-dom';",
      'export function Next() {',
      '  const [params] = useSearchParams();',
      "  const next = params.get('next');",
      '  return <a href={next}>continue</a>;',
      '}',
      'export function Frame() {',
      '  const src = window.location.hash.slice(1);',
      '  return <iframe src={src} />;',
      '}',
      'export function Widget() {',
      "  const src = new URLSearchParams(window.location.search).get('widget');",
      '  return <script src={src} />;',
      '}',
      'export function Back() {',
      '  const r = document.referrer;',
      '  return <a href={r}>back</a>;',
      '}',
    ].join('\n');
    expect(xssSinkLines(await analyze(code, 'links.jsx', 'javascript'))).toEqual([5, 9, 13, 17]);
  });

  it('no flow: props, state from a constant, quoted value, encoded or checked URL, other elements', async () => {
    const code = [
      "import { useState } from 'react';",
      'export function FromProps({ url }) {',
      '  return <a href={url}>x</a>;',
      '}',
      'export function FromState() {',
      "  const [url] = useState('https://example.com/docs');",
      '  return <a href={url}>docs</a>;',
      '}',
      'export function Quoted() {',
      '  return <a href="/home">home</a>;',
      '}',
      'export function Encoded() {',
      "  const next = new URLSearchParams(window.location.search).get('next');",
      '  return <a href={encodeURIComponent(next)}>continue</a>;',
      '}',
      'export function Checked() {',
      "  const next = new URLSearchParams(window.location.search).get('next');",
      '  if (!isSafeUrl(next)) return null;',
      '  return <a href={next}>continue</a>;',
      '}',
      'export function Protocol() {',
      '  const u = new URL(window.location.hash.slice(1), window.location.origin);',
      "  if (u.protocol !== 'https:') return null;",
      '  return <iframe src={u.href} />;',
      '}',
      'export function Image() {',
      "  const src = new URLSearchParams(window.location.search).get('img');",
      '  return <img src={src} />;',
      '}',
      'export function Api({ user }) {',
      '  return <a href={user.website}>site</a>;',
      '}',
    ].join('\n');
    expect(xssSinkLines(await analyze(code, 'safe-links.tsx', 'typescript'))).toEqual([]);
  });

  it('a real `src()` call is not a URL attribute sink', async () => {
    const code = [
      "const gulp = require('gulp');",
      'function build() {',
      "  const glob = new URLSearchParams(window.location.search).get('g');",
      '  return gulp.src(glob);',
      '}',
    ].join('\n');
    expect(xssSinkLines(await analyze(code, 'gulpfile.js', 'javascript'))).toEqual([]);
  });
});
