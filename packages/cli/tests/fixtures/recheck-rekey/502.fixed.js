const express = require('express');
const app = express();
app.post('/profile', function load(req, res) {
  const profile = { name: String(req.body.name) };
  res.json({ name: profile.name });
});
