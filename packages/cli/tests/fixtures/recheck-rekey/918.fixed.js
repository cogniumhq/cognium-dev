const express = require('express');
const axios = require('axios');
const app = express();
const ALLOWED = { docs: 'https://docs.example.com/index.json' };
app.get('/fetch', async function proxy(req, res) {
  const target = ALLOWED[String(req.query.name)];
  if (!target) { res.status(400).end(); return; }
  const r = await axios.get(target);
  res.send(r.data);
});
