const express = require('express');
const axios = require('axios');
const app = express();
app.get('/fetch', async function proxy(req, res) {
  const url = req.query.url;
  const r = await axios.get(url);
  res.send(r.data);
});
