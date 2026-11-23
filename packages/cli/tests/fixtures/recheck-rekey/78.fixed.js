const express = require('express');
const { execFile } = require('child_process');
const app = express();
app.get('/ping', function ping(req, res) {
  const host = String(req.query.host);
  if (!/^[a-z0-9.-]+$/i.test(host)) { res.status(400).end(); return; }
  execFile('ping', ['-c', '1', host], (err, out) => res.send(out));
});
