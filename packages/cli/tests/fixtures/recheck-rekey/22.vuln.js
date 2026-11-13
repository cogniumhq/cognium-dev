const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
app.get('/file', function readFile(req, res) {
  const name = req.query.name;
  fs.readFile(path.join('/srv/files', name), (e, d) => res.send(d));
});
