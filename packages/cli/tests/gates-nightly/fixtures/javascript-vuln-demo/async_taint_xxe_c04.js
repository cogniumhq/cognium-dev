'use strict';
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned flow-combo c04 corpus */
const libxml = require('libxmljs');

// cognium-dev#1244 flow-combo c04 — async-carried taint to XXE sink (CWE-611)
const ident = async (x) => x;

module.exports.handler = async (req, res) => {
  const body = await ident(req.body);
  libxml.parseXml(body);
  res.end();
};