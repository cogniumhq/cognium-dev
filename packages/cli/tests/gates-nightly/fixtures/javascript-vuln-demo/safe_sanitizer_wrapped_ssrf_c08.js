'use strict';
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned flow-combo c08 corpus */
const express = require('express');
const http = require('http');
const app = express();
const ALLOWED = new Set(['api.internal.example.com']);

// cognium-dev#1244 flow-combo c08 — custom wrapper × SSRF (CWE-918). Expect clean.
function checkedUrl(u) {
  const host = new URL(u).hostname;
  if (!ALLOWED.has(host)) throw new Error('bad host');
  return u;
}

app.get('/wrapped', (req, res) => {
  http.get(checkedUrl(String(req.query.url || '')));
  res.end('ok');
});

module.exports = app;