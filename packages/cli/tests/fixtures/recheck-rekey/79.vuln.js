const express = require('express');
const app = express();
app.get('/hello', function hello(req, res) {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});
