const express = require('express');
const serialize = require('node-serialize');
const app = express();
app.post('/profile', function load(req, res) {
  const data = req.body.data;
  const profile = serialize.unserialize(data);
  res.json({ name: profile.name });
});
