const express = require('express');
const escapeHtml = require('escape-html');
const app = express();
app.get('/hello', function hello(req, res) {
  const name = req.query.name;
  res.send('<h1>Hello ' + escapeHtml(name) + '</h1>');
});
