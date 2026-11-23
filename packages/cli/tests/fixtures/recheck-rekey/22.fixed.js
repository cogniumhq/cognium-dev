const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const BASE = '/srv/files';
app.get('/file', function readFile(req, res) {
  const name = path.basename(String(req.query.name));
  const full = path.resolve(BASE, name);
  if (!full.startsWith(BASE + path.sep)) { res.status(400).end(); return; }
  fs.readFile(full, (e, d) => res.send(d));
});
