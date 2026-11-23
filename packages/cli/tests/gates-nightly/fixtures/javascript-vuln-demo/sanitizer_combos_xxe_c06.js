'use strict';
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned flow-combo c06 corpus */
// Combinations #6/#7/#8 — SANITIZER × XXE (CWE-611, JS).
// cognium-dev#1244 flow-combo c06 — wrong/fake sanitizers still reach libxml.parseXml.
const express = require('express');
const libxml = require('libxmljs2');
const app = express();
function escapeHtml(s) {
  return String(s).replace(/[<>&]/g, '_');
}
function sanitizeXml(x) {
  return x;
}
app.get('/wrong', (req, res) => {
  libxml.parseXml(escapeHtml(req.query.xml || ''));
  res.end();
});
app.get('/fake', (req, res) => {
  libxml.parseXml(sanitizeXml(req.query.xml || ''));
  res.end();
});
app.get('/wrapped', (req, res) => {
  libxml.parseXml(req.query.xml || '', { noent: false });
  res.end();
});
module.exports = app;