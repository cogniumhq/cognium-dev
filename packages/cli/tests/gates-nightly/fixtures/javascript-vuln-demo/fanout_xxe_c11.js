'use strict';
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned flow-combo c11 corpus */
// Combination #11 — FAN-OUT × XXE (CWE-611, JS).
// cognium-dev#1244 flow-combo c11 — repeated libxml.parseXml on the same tainted local.
const express = require('express');
const libxml = require('libxmljs2');
const app = express();
app.get('/fanout', (req, res) => {
  const x = req.query.xml || '';
  libxml.parseXml(x);
  libxml.parseXml('<r>' + x + '</r>');
  libxml.parseXml(x);
  res.end();
});
module.exports = app;