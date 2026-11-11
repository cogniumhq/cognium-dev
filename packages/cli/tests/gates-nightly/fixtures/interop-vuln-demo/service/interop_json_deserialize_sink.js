// IL-4 serialization boundary — Node JSON deserialize → sink (CWE-89).
// Untrusted JSON crosses the boundary, is parsed, and a field is used in a SQL
// sink. Tests taint survival through JSON.parse + property access.
const express = require('express');
const { Pool } = require('pg');

const app = express();
const pool = new Pool();

app.post('/ingest', express.text(), (req, res) => {
  const payload = JSON.parse(req.body); // SOURCE (untrusted JSON over the boundary)
  const name = payload.name;            // tainted field survives deserialization
  // SINK (CWE-89): deserialized field concatenated into SQL.
  pool.query("SELECT * FROM users WHERE name = '" + name + "'").then((r) => res.json(r.rows));
});

module.exports = app;
