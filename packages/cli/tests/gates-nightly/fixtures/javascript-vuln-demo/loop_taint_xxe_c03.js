'use strict';
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned flow-combo c03 corpus */
const libxml = require('libxmljs');

// cognium-dev#1244 flow-combo c03 — loop-carried taint to XXE sink (CWE-611)
module.exports.handler = (req, res) => {
  let xml = req.body;
  while (xml.length > 0) {
    xml = String(xml);
  }
  libxml.parseXml(xml);
  res.end();
};