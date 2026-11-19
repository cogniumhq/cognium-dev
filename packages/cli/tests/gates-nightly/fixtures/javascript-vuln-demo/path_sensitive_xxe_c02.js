'use strict';
const libxml = require('libxmljs');

// cognium-dev#1244 flow-combo c02 — one-branch / path-sensitive XXE (CWE-611)
module.exports.neg = (req, res) => {
  const body = req.body;
  if (body === 'safe') {
    /* guard covers only literal */
  } else {
    libxml.parseXml(body);
  }
  res.end();
};