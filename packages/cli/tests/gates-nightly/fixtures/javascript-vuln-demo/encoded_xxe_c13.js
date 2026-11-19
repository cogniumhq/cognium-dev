'use strict';
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned flow-combo c13 corpus */
// Combination #13 — ENCODED × XXE (CWE-611, JS).
// cognium-dev#1244 flow-combo c13 — base64/url decoding before libxml.parseXml.
const express = require('express');
const libxml = require('libxmljs2');
const app = express();
app.get('/b64', (req, res) => {
  const x = Buffer.from(req.query.d || '', 'base64').toString();
  libxml.parseXml(x);
  res.end();
});
app.get('/url', (req, res) => {
  const x = decodeURIComponent(req.query.d || '');
  libxml.parseXml(x);
  res.end();
});
module.exports = app;