'use strict';
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned flow-combo c05 corpus */
// Combination #5 — OOP OBJECT FLOW × XXE (CWE-611, JS). Tainted field parsed with
// external entities enabled. NO finding = FALSE NEGATIVE.
const express = require('express');
const libxml = require('libxmljs');
const app = express();

class Importer {
  constructor(xml) {
    this.xml = xml;
  }
  get payload() {
    return this.xml;
  }
  parseDirect() {
    return libxml.parseXml(this.xml, { noent: true, dtdload: true });
  }
  parseViaGetter() {
    return libxml.parseXml(this.payload, { noent: true, dtdload: true });
  }
}

app.get('/import', (req, res) => {
  const i = new Importer(req.query.xml);
  i.parseDirect();
  i.parseViaGetter();
  res.end();
});
module.exports = app;